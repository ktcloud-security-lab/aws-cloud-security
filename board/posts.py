from flask import Blueprint, abort, redirect, render_template, request, session, url_for

import db
from auth import login_required

bp = Blueprint("posts", __name__)


@bp.route("/")
def index():
    posts = db.query(
        "SELECT p.id, p.title, p.created, u.username FROM posts p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC"
    )
    return render_template("index.html", posts=posts)


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
    return render_template("post.html", p=p)


@bp.route("/post/<int:pid>/delete", methods=["POST"])
@login_required
def delete(pid):
    # 작성자 본인 글만 삭제 (WHERE 조건에 user_id 포함)
    db.execute("DELETE FROM posts WHERE id=%s AND user_id=%s", (pid, session["uid"]))
    return redirect(url_for("posts.index"))
