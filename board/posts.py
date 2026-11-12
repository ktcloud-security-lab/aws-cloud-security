from flask import Blueprint, abort, redirect, render_template, request, session, url_for

import db
from auth import login_required, check_auth_csrf

bp = Blueprint("posts", __name__)


@bp.route("/")
def index():
    keyword = request.args.get("q", "").strip()

    if len(keyword) > 100:
        return render_template(
            "index.html",
            posts=[],
            keyword=keyword,
            error="검색어는 100자 이하로 입력해 주세요.",
        ), 400

    sql = """
        SELECT p.id, p.title, p.created, u.username,
               (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count
        FROM posts p
        JOIN users u ON u.id = p.user_id
    """
    args = ()

    if keyword:
        escaped = (
            keyword.replace("=", "==")
            .replace("%", "=%")
            .replace("_", "=_")
        )
        pattern = f"%{escaped}%"

        sql += """
            WHERE (
                p.title LIKE %s ESCAPE '='
                OR p.body LIKE %s ESCAPE '='
            )
        """
        args = (pattern, pattern)

    sql += " ORDER BY p.id DESC"

    posts = db.query(sql, args)
    return render_template(
        "index.html",
        posts=posts,
        keyword=keyword,
    )


@bp.route("/write", methods=["GET", "POST"])
@login_required
def write():
    error = None
    if request.method == "POST":
        title, body = request.form["title"].strip(), request.form["body"].strip()
        if title and body and len(title) <= 100:
            db.execute("INSERT INTO posts (user_id, title, body) VALUES (%s, %s, %s)", (session["uid"], title, body))
            return redirect(url_for("posts.index"))
        error = "제목(100자 이하)과 내용을 입력하세요."
    return render_template("write.html", error=error)


@bp.route("/post/<int:pid>")
def post(pid):
    p = db.query(
        "SELECT p.*, u.username FROM posts p JOIN users u ON u.id=p.user_id WHERE p.id=%s", (pid,), one=True
    ) or abort(404)
    comments = db.query(
        "SELECT c.*, u.username FROM comments c JOIN users u ON u.id=c.user_id WHERE c.post_id=%s ORDER BY c.id", (pid,)
    )
    return render_template("post.html", p=p, comments=comments)


@bp.route("/post/<int:pid>/edit", methods=["GET", "POST"])
@login_required
def edit(pid):
    p = db.query("SELECT * FROM posts WHERE id=%s", (pid,), one=True)
    if p is None:
        abort(404)
    if p["user_id"] != session["uid"]:
        abort(403)
    error = None
    if request.method == "POST":
        check_auth_csrf()
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        if title and body and len(title) <= 100:
            db.execute(
                "UPDATE posts SET title=%s, body=%s WHERE id=%s AND user_id=%s",
                (title, body, pid, session["uid"]),
            )
            return redirect(url_for("posts.post", pid=pid))
        error = "제목(100자 이하)과 내용을 입력하세요."
    return render_template("edit.html", p=p, error=error)


@bp.route("/post/<int:pid>/delete", methods=["POST"])
@login_required
def delete(pid):
    check_auth_csrf()
    # Delete dependent comments and the post atomically.
    conn = db.connect()
    try:
        conn.begin()
        with conn.cursor() as cur:
            cur.execute("SELECT user_id FROM posts WHERE id=%s FOR UPDATE", (pid,))
            p = cur.fetchone()
            if p is None:
                abort(404)
            if p["user_id"] != session["uid"]:
                abort(403)
            cur.execute("DELETE FROM comments WHERE post_id=%s", (pid,))
            cur.execute("DELETE FROM posts WHERE id=%s AND user_id=%s", (pid, session["uid"]))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return redirect(url_for("posts.index"))


@bp.route("/post/<int:pid>/comment", methods=["POST"])
@login_required
def comment(pid):
    body = request.form["body"].strip()
    if body:
        db.execute("INSERT INTO comments (post_id, user_id, body) VALUES (%s, %s, %s)", (pid, session["uid"], body))
    return redirect(url_for("posts.post", pid=pid))


@bp.route("/comment/<int:cid>/delete", methods=["POST"])
@login_required
def comment_delete(cid):
    db.execute("DELETE FROM comments WHERE id=%s AND user_id=%s", (cid, session["uid"]))
    pid = request.form.get("pid")
    return redirect(url_for("posts.post", pid=pid))
