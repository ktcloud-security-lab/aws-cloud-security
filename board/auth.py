import hmac
import secrets
from functools import wraps

from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import auth_service as service
import db
import mailer
from mail_service import send_email

bp = Blueprint('auth', __name__)
# Same response for existing/nonexistent addresses.

def csrf_token():
    if 'auth_csrf' not in session:
        session['auth_csrf'] = secrets.token_urlsafe(32)
    return session['auth_csrf']


@bp.app_context_processor
def inject_csrf():
    return {'auth_csrf_token': csrf_token}


@bp.before_request
def check_auth_csrf():
    if request.method == 'POST':
        expected = session.get('auth_csrf', '')
        supplied = request.form.get('csrf_token', '')
        if not expected or not hmac.compare_digest(expected, supplied):
            abort(400, description='페이지를 새로고침한 뒤 다시 시도해 주세요.')


@bp.before_app_request
def validate_session():
    g.user = None
    if session.get('uid'):
        user = db.query('SELECT id, username, email_verified, auth_version FROM users WHERE id=%s',
                        (session['uid'],), one=True)
        if not user or not user['email_verified'] or session.get('auth_version') != user['auth_version']:
            session.clear()
        else:
            g.user = user


@bp.after_request
def auth_headers(response):
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not g.user:
            return redirect(url_for('auth.login'))
        return view(*args, **kwargs)
    return wrapper


def dispatch_link(user, purpose):
    raw = service.issue_token(user['id'], purpose)

    if not raw:
        return False, '메일 요청 횟수를 초과했습니다. 잠시 후 다시 시도해 주세요.'

    try:
        if purpose == 'verify':
            path = '/verify-email'
            subject = '[게시판] 이메일 인증'
            minutes = 30
        else:
            path = '/reset-password'
            subject = '[게시판] 비밀번호 재설정'
            minutes = 15

        link = mailer.public_link(path, raw)

        body = (
            f'{subject}\n\n'
            f'아래 링크를 눌러 진행해 주세요.\n'
            f'{link}\n\n'
            f'이 링크는 {minutes}분 동안 한 번 사용할 수 있습니다.\n'
            '직접 요청하지 않았다면 이 메일을 무시해 주세요.'
        )

        send_email(user['email'], subject, body)

        current_app.logger.info(
            'auth_mail accepted purpose=%s user_id=%s',
            purpose,
            user['id'],
        )

        return True, '메일을 발송했습니다. 수신함과 스팸함을 확인해 주세요.'

    except Exception as exc:
        current_app.logger.warning(
            'auth_mail failed purpose=%s user_id=%s error_type=%s',
            purpose,
            user['id'],
            type(exc).__name__,
        )

        # 발송하지 못한 토큰은 사용할 수 없도록 처리
        db.execute(
            '''
            UPDATE auth_tokens
            SET used_at = UTC_TIMESTAMP()
            WHERE token_hash = %s
              AND used_at IS NULL
            ''',
            (service.token_digest(raw),),
        )

        return False, '메일 발송에 실패했습니다. 잠시 후 다시 시도해 주세요.'


@bp.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        name = request.form.get('username', '').strip()
        email = service.normalize_email(request.form.get('email', ''))
        password = request.form.get('password', '')
        error = service.password_error(password)
        if not name or len(name) > 30 or not email:
            error = '아이디(1~30자)와 올바른 이메일 주소를 입력해 주세요.'
        elif password != request.form.get('password_confirm', ''):
            error = '비밀번호 확인이 일치하지 않습니다.'
        if not error:
            try:
                db.execute('INSERT INTO users (username,pw,email,email_verified,auth_version) VALUES (%s,%s,%s,FALSE,0)',
                           (name, generate_password_hash(password), email))
            except db.IntegrityError:
                error = '이미 사용 중인 아이디 또는 이메일입니다.'
            else:
                user = db.query('SELECT id,email FROM users WHERE username=%s', (name,), one=True)
                success, message = dispatch_link(user, 'verify')

                if success:
                    message = (
                        '회원가입이 완료되었습니다. '
                        '인증 메일을 발송했습니다. 이메일 인증 후 로그인해 주세요.'
                    )
                else:
                    message = (
                        '계정은 생성되었습니다. '
                        + message
                        + ' 인증 메일 재발송을 이용해 주세요.'
                    )

                return render_template(
                    'auth_message.html',
                    title='회원가입 완료',
                    message=message,
                    action=None,
                )
    return render_template('auth.html', title='회원가입', error=error)


@bp.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        # Parameterized lookup: authentication must not trust injected user rows.
        user = db.query('SELECT * FROM users WHERE username=%s',
                        (request.form.get('username', '').strip(),), one=True)
        if user and check_password_hash(user['pw'], request.form.get('password', '')):
            if not user['email_verified']:
                error = '이메일 인증 후 로그인해 주세요. 기존 계정은 관리자에게 이메일 등록을 요청하세요.'
            else:
                session.clear()
                session.update(uid=user['id'], name=user['username'], auth_version=user['auth_version'])
                return redirect(url_for('posts.index'))
        else:
            error = '아이디 또는 비밀번호가 틀렸습니다.'
    return render_template('auth.html', title='로그인', error=error)


@bp.route('/logout', methods=['GET', 'POST'])
def logout():
    if request.method == 'POST':
        session.clear()
        return redirect(url_for('posts.index'))
    return render_template('auth_message.html', title='로그아웃', message='로그아웃하시겠습니까?', action='logout')


@bp.route('/resend-verification', methods=['GET', 'POST'])
def resend_verification():
    error = None

    if request.method == 'POST':
        email = service.normalize_email(request.form.get('email', ''))

        if not email:
            error = '올바른 이메일 주소를 입력해 주세요.'
        else:
            user = db.query(
                'SELECT id, email, email_verified FROM users WHERE email=%s',
                (email,),
                one=True,
            )

            if not user:
                error = '등록되지 않은 이메일입니다.'
            elif user['email_verified']:
                error = '이미 이메일 인증이 완료된 계정입니다. 로그인해 주세요.'
            else:
                success, message = dispatch_link(user, 'verify')

                if success:
                    return render_template(
                        'auth_message.html',
                        title='인증 메일 발송 완료',
                        message=message,
                        action=None,
                    )

                error = message

    return render_template(
        'email_request.html',
        title='인증 메일 재발송',
        description='가입 시 등록한 이메일을 입력해 주세요.',
        error=error,
    )

@bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    error = None

    if request.method == 'POST':
        email = service.normalize_email(request.form.get('email', ''))

        if not email:
            error = '올바른 이메일 주소를 입력해 주세요.'
        else:
            user = db.query(
                'SELECT id, email, email_verified FROM users WHERE email=%s',
                (email,),
                one=True,
            )

            if not user:
                error = '등록되지 않은 이메일입니다.'
            elif not user['email_verified']:
                error = '이메일 인증을 먼저 완료해 주세요. 인증 메일 재발송을 이용해 주세요.'
            else:
                success, message = dispatch_link(user, 'reset')

                if success:
                    return render_template(
                        'auth_message.html',
                        title='비밀번호 재설정 메일 발송 완료',
                        message=message,
                        action=None,
                    )

                error = message

    return render_template(
        'email_request.html',
        title='비밀번호 찾기',
        description='인증된 이메일로 비밀번호 재설정 링크를 보내드립니다.',
        error=error,
    )

@bp.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    raw = request.form.get('token', '') if request.method == 'POST' else request.args.get('token', '')
    if request.method == 'POST':
        if service.consume_token(raw, 'verify'):
            flash('이메일 인증이 완료되었습니다. 로그인해 주세요.')
            return redirect(url_for('auth.login'))
    elif service.find_token(raw, 'verify'):
        # GET does not consume tokens (mail security scanners may visit links).
        return render_template('auth_message.html', title='이메일 인증', message='아래 버튼을 눌러 이메일 인증을 완료하세요.', action='verify', token=raw)
    return render_template('auth_message.html', title='링크를 확인해 주세요', message='만료되었거나 이미 사용한 인증 링크입니다.', action=None), 400


@bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    raw = request.form.get('token', '') if request.method == 'POST' else request.args.get('token', '')
    if not service.find_token(raw, 'reset'):
        return render_template('auth_message.html', title='링크를 확인해 주세요', message='만료되었거나 이미 사용한 재설정 링크입니다.', action=None), 400
    error = None
    if request.method == 'POST':
        password = request.form.get('password', '')
        error = service.password_error(password)
        if password != request.form.get('password_confirm', ''):
            error = '비밀번호 확인이 일치하지 않습니다.'
        if not error:
            if service.consume_token(raw, 'reset', generate_password_hash(password)):
                session.clear()
                flash('비밀번호가 변경되었습니다. 새 비밀번호로 로그인해 주세요.')
                return redirect(url_for('auth.login'))
            error = '만료되었거나 이미 사용한 링크입니다.'
    return render_template('reset_password.html', token=raw, error=error)
