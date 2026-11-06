import os
from pathlib import Path

import pymysql
from flask import g

IntegrityError = pymysql.err.IntegrityError


def connect():
    return pymysql.connect(
        host=os.environ.get("DB_HOST", "127.0.0.1"),
        port=int(os.environ.get("DB_PORT", 3306)),
        user=os.environ.get("DB_USER", "board"),
        password=os.environ.get("DB_PASSWORD", ""),
        database=os.environ.get("DB_NAME", "board"),
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
    )


def get_db():
    if "db" not in g:
        g.db = connect()
    return g.db


def close_db(_=None):
    if (conn := g.pop("db", None)) is not None:
        conn.close()


def query(sql, args=(), one=False):
    with get_db().cursor() as cur:
        cur.execute(sql, args)
        return cur.fetchone() if one else cur.fetchall()


def execute(sql, args=()):
    with get_db().cursor() as cur:
        cur.execute(sql, args)


def init_db():
    sql = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
    conn = connect()
    with conn, conn.cursor() as cur:
        for stmt in sql.split(";"):
            if stmt.strip():
                cur.execute(stmt)
