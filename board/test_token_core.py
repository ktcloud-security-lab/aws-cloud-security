import importlib.util
import sqlite3
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

class Cursor:

    def __init__(self, conn):
        self.cur = conn.cursor()

    def __enter__(self):return self

    def __exit__(self, *args):self.cur.close()

    def execute(self, sql, args=()):
        args = tuple(x.isoformat(' ') if isinstance(x, datetime) else x for x in args)
        return self.cur.execute(sql.replace('%s', '?').replace(' FOR UPDATE', ''), args)

    def fetchone(self):
        row = self.cur.fetchone()
        return dict(row) if row is not None else None


class Connection:

    def __init__(self):
        self.raw = sqlite3.connect(':memory:', isolation_level=None)
        self.raw.row_factory = sqlite3.Row

        self.raw.executescript('''

            CREATE TABLE users (id INTEGER PRIMARY KEY, pw TEXT, email_verified INTEGER, auth_version INTEGER DEFAULT 0);
            CREATE TABLE auth_tokens (id INTEGER PRIMARY KEY, user_id INTEGER, token_hash TEXT UNIQUE, purpose TEXT, created_at TIMESTAMP, expires_at TIMESTAMP, used_at TIMESTAMP);
            INSERT INTO users(id,pw,email_verified) VALUES (1,'old-hash',0);

        ''')

    def cursor(self):return Cursor(self.raw)

    def begin(self):self.raw.execute('BEGIN')

    def commit(self):self.raw.commit()

    def rollback(self):self.raw.rollback()



class TokenTests(unittest.TestCase):

    def setUp(self):
        self.conn = Connection()
        self.original_db = sys.modules.get('db')
        fake = types.ModuleType('db')
        fake.get_db = lambda: self.conn

        def query(sql, args=(), one=False):

            with self.conn.cursor() as cur:
                cur.execute(sql, args)
                if one:return cur.fetchone()
                return [dict(r) for r in cur.cur.fetchall()]

        fake.query = query
        sys.modules['db'] = fake
        spec = importlib.util.spec_from_file_location('tested_auth_service', Path(__file__).with_name('auth_service.py'))
        self.service = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.service)



    def tearDown(self):
        self.conn.raw.close()
        if self.original_db is None:sys.modules.pop('db',None)
        else:sys.modules['db']=self.original_db


    def test_verification_single_use_and_hash_storage(self):
        token=self.service.issue_token(1,'verify')
        self.assertEqual(len(token),43)

        row=self.conn.raw.execute('SELECT * FROM auth_tokens').fetchone()

        self.assertNotEqual(row['token_hash'],token)
        self.assertEqual(row['token_hash'],self.service.token_digest(token))
        self.assertIsNone(self.service.find_token(token,'reset'))
        self.assertTrue(self.service.consume_token(token,'verify'))
        self.assertFalse(self.service.consume_token(token,'verify'))
        self.assertEqual(self.conn.raw.execute('SELECT email_verified FROM users').fetchone()[0],1)



    def test_expired_and_malformed_tokens_rejected(self):
        token=self.service.issue_token(1,'verify')
        past = datetime.now(timezone.utc).replace(tzinfo=None)-timedelta(seconds=1)
        self.conn.raw.execute('UPDATE auth_tokens SET expires_at=?',(past.isoformat(' '),))
        self.assertFalse(self.service.consume_token(token,'verify'))
        self.assertIsNone(self.service.find_token("' OR 1=1 --",'verify'))

    def test_reissue_invalidates_old_link_and_limits_rate(self):
        a=self.service.issue_token(1,'verify')
        b=self.service.issue_token(1,'verify')
        self.assertIsNone(self.service.find_token(a,'verify'))
        self.assertIsNotNone(self.service.find_token(b,'verify'))
        self.assertIsNotNone(self.service.issue_token(1,'verify'))
        self.assertIsNone(self.service.issue_token(1,'verify'))

    def test_reset_revokes_tokens_and_sessions(self):
        self.conn.raw.execute('UPDATE users SET email_verified=1')
        token=self.service.issue_token(1,'reset')
        self.service.issue_token(1,'verify')
        self.assertTrue(self.service.consume_token(token,'reset','new-hash'))
        self.assertFalse(self.service.consume_token(token,'reset','other-hash'))
        row=self.conn.raw.execute('SELECT pw,auth_version FROM users').fetchone()
        self.assertEqual(tuple(row),('new-hash',1))
        self.assertEqual(self.conn.raw.execute('SELECT COUNT(*) FROM auth_tokens WHERE used_at IS NULL').fetchone()[0],0)

    def test_unverified_reset_rejected(self):
        token=self.service.issue_token(1,'reset')
        self.assertFalse(self.service.consume_token(token,'reset','new-hash'))

    def test_email_and_password_validation(self):
        self.assertEqual(self.service.normalize_email(' Alice@Example.com '),'alice@example.com')
        for value in ['bad', 'a@example.com\r\nBcc:evil@example.com', 'a..b@example.com', 'a@b..com']:
            self.assertIsNone(self.service.normalize_email(value))

        self.assertIsNotNone(self.service.password_error('abc'))

        for password in ('Ab1!', '12345678!', 'abcdefgh!', 'Abcdef12'):
            self.assertIsNotNone(self.service.password_error(password))
        self.assertIsNone(self.service.password_error('Test-pass-12'))


if __name__=='__main__':unittest.main(verbosity=2)

