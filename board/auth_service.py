import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone
import db


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)

def normalize_email(value):
    value = value.strip().lower()

    if len(value) > 254 or not re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}", value):
        return None

    local, domain = value.rsplit('@', 1)

    if len(local) > 64 or '..' in local or '..' in domain or local.startswith('.') or local.endswith('.'):
        return None

    return value


def password_error(value):
    if len(value) < 8:
        return '비밀번호는 8자 이상이어야 합니다.'
    if not re.search(r'[A-Za-z]', value):
        return '비밀번호에 영문을 포함해 주세요.'
    if not re.search(r'[0-9]', value):
        return '비밀번호에 숫자를 포함해 주세요.'
    if not re.search(r'[^A-Za-z0-9]', value):
        return '비밀번호에 특수문자를 포함해 주세요.'
    return None


def token_digest(raw):
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()



def issue_token(user_id, purpose):
    if purpose not in ('verify', 'reset'):
        raise ValueError('Invalid purpose')

    now = utcnow()
    ttl = 30 if purpose == 'verify' else 15
    
    conn = db.get_db()
    conn.begin()

    try:
        with conn.cursor() as cur:

            cur.execute('SELECT id FROM users WHERE id=%s FOR UPDATE', (user_id,))

            if not cur.fetchone():
                conn.rollback()
                return None

            cur.execute('SELECT COUNT(*) AS n FROM auth_tokens WHERE user_id=%s AND purpose=%s AND created_at >= %s',
                        (user_id, purpose, now - timedelta(minutes=15)))

            if cur.fetchone()['n'] >= 3:
                conn.rollback()
                return None

            cur.execute('UPDATE auth_tokens SET used_at=%s WHERE user_id=%s AND purpose=%s AND used_at IS NULL',
                        (now, user_id, purpose))

            raw = secrets.token_urlsafe(32)

            cur.execute('INSERT INTO auth_tokens (user_id, token_hash, purpose, created_at, expires_at) VALUES (%s,%s,%s,%s,%s)',
                        (user_id, token_digest(raw), purpose, now, now + timedelta(minutes=ttl)))

        conn.commit()
        return raw

    except Exception:
        conn.rollback()
        raise


def find_token(raw, purpose):

    if not raw or not re.fullmatch(r'[A-Za-z0-9_-]{43}', raw):
        return None

    return db.query('SELECT user_id FROM auth_tokens WHERE token_hash=%s AND purpose=%s AND used_at IS NULL AND expires_at > %s',
                    (token_digest(raw), purpose, utcnow()), one=True)


def consume_token(raw, purpose, new_password_hash=None):

    token = find_token(raw, purpose)

    if not token:
        return False

    if purpose not in ('verify', 'reset') or (purpose == 'reset' and not new_password_hash):
        return False

    conn = db.get_db()
    conn.begin()

    try:

        with conn.cursor() as cur:
            cur.execute('SELECT id, email_verified FROM users WHERE id=%s FOR UPDATE', (token['user_id'],))
            user = cur.fetchone()
            if not user:
                conn.rollback()
                return False

            now = utcnow()
            cur.execute('SELECT id FROM auth_tokens WHERE token_hash=%s AND purpose=%s AND used_at IS NULL AND expires_at > %s FOR UPDATE',
                        (token_digest(raw), purpose, now))
            record = cur.fetchone()

            if not record or (purpose == 'reset' and not user['email_verified']):
                conn.rollback()
                return False

            if purpose == 'verify':
                cur.execute('UPDATE users SET email_verified=TRUE WHERE id=%s', (user['id'],))
                cur.execute('UPDATE auth_tokens SET used_at=%s WHERE user_id=%s AND purpose=%s AND used_at IS NULL',
                            (now, user['id'], 'verify'))

            else:

                cur.execute('UPDATE users SET pw=%s, auth_version=auth_version+1 WHERE id=%s',
                            (new_password_hash, user['id']))
                cur.execute('UPDATE auth_tokens SET used_at=%s WHERE user_id=%s AND used_at IS NULL', (now, user['id']))

        conn.commit()
        return True

    except Exception:
        conn.rollback()
        raise

