import os

from flask import Flask

import auth
import db
import posts

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or os.urandom(32),  # 운영에선 환경변수로 고정 (재시작 시 로그인 유지)
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",  # 외부 사이트에서 오는 POST(CSRF) 차단
    SESSION_COOKIE_SECURE=os.environ.get("INSECURE_COOKIE") != "1",  # HTTPS에서만 쿠키 전송 (로컬 HTTP 테스트만 끔)
)
app.teardown_appcontext(db.close_db)
app.register_blueprint(auth.bp)
app.register_blueprint(posts.bp)
db.init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
