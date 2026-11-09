import re
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
        name = request.form.get("username", "").strip()
        pw = request.form.get("password", "")
        pw_confirm = request.form.get("password_confirm", "")

        if not name or len(name) > 30:
            error = "아이디는 1~30자로 입력해 주세요."

        elif len(pw) < 8:
            error = "비밀번호는 8자 이상이어야 합니다."

        elif not re.search(r"[A-Za-z]", pw):
            error = "비밀번호에 영문을 포함해 주세요."

        elif not re.search(r"[0-9]", pw):
            error = "비밀번호에 숫자를 포함해 주세요."

        elif not re.search(r"[^A-Za-z0-9]", pw):
            error = "비밀번호에 특수문자를 포함해 주세요."

        elif pw != pw_confirm:
            error = "비밀번호 확인이 일치하지 않습니다."

        else:
            try:
                db.execute(
                    "INSERT INTO users (username, pw) VALUES (%s, %s)",
                    (name, generate_password_hash(pw))
                )
                return redirect(url_for("auth.login"))

            except db.IntegrityError:
                error = "이미 있는 아이디입니다."

    return render_template("auth.html", title="회원가입", error=error)


@bp.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        # VULN: SQL Injection (교육용 실습 취약점 — 기존 코드 유지)
        user = db.query(
            "SELECT * FROM users WHERE username='%s'" % request.form["username"],
            one=True
        )

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
