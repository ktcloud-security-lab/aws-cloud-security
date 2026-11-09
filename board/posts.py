from flask import Blueprint, abort, redirect, render_template, request, session, url_for

import db
from auth import login_required

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
        SELECT p.id, p.title, p.created, u.username
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


@bp.route("/post/<int:pid>/delete", methods=["POST"])
@login_required
def delete(pid):
    db.execute("DELETE FROM posts WHERE id=%s AND user_id=%s", (pid, session["uid"]))
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
