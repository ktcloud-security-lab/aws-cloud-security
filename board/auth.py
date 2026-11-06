from functools import wraps

from flask import Blueprint, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import db

bp = Blueprint("auth", __name__)


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "uid" not in session:
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapper


@bp.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        name, pw = request.form["username"].strip(), request.form["password"]
        if not name or len(name) > 30 or len(pw) < 4:
            error = "아이디(1~30자)와 비밀번호(4자 이상)를 확인하세요."
        else:
            try:
                db.execute("INSERT INTO users (username, pw) VALUES (%s, %s)", (name, generate_password_hash(pw)))
                return redirect(url_for("auth.login"))
            except db.IntegrityError:
                error = "이미 있는 아이디입니다."
    return render_template("auth.html", title="회원가입", error=error)


@bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        # VULN: SQL Injection (username을 문자열 포맷으로 쿼리에 직접 삽입 → UNION 주입 가능, 해시 검증은 유지)
        user = db.query("SELECT * FROM users WHERE username='%s'" % request.form["username"], one=True)
        if user and check_password_hash(user["pw"], request.form["password"]):
            session.clear()
            session["uid"], session["name"] = user["id"], user["username"]
            return redirect(url_for("posts.index"))
        error = "아이디 또는 비밀번호가 틀렸습니다."
    return render_template("auth.html", title="로그인", error=error)


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("posts.index"))
