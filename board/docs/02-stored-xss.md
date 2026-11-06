# 02 · Stored XSS (저장형 크로스 사이트 스크립팅)

## 1. 한 줄 요약
게시글 본문을 이스케이프 없이 화면에 출력해서, 글에 심어 둔 `<script>`가 **그 글을 보는 모든 사람의 브라우저에서 실행**된다.

> **XSS (Cross-Site Scripting)**: 공격자가 넣은 HTML/자바스크립트가 피해자의 브라우저에서 실행되는 취약점.
> **Stored(저장형) XSS**: 그 스크립트가 서버(DB)에 **저장**되어, 해당 글을 열람하는 모든 사용자에게 계속 실행되는 유형. 공격자가 한 번 심으면 반복 피해가 난다.

## 2. 원리: 왜 취약한가

게시글 상세 화면 템플릿 (`templates/post.html:6`):

```html
<!-- templates/post.html:6 -->
<pre>{{ p.body|safe }}</pre>
```

문제는 `|safe` 필터입니다. Flask가 쓰는 **Jinja2 템플릿은 기본적으로 자동 이스케이프**를 합니다. 즉 `<`, `>`, `&`, `"` 같은 글자를 `&lt;`, `&gt;` 처럼 바꿔서 **글자 그대로 보이게만** 하고 태그로 해석하지 않습니다. 그런데 `|safe`는 "이 값은 안전하니 이스케이프하지 말고 HTML 원본 그대로 출력하라"는 뜻입니다.

> **이스케이프(escape)**: `<script>`처럼 특별한 뜻을 가진 글자를 `&lt;script&gt;`로 바꿔, 브라우저가 **코드가 아니라 글자**로 보게 만드는 처리.

게시글 본문 `p.body`는 사용자가 아무거나 적을 수 있는 입력입니다(`posts.py:24`에서 저장). 거기에 `|safe`를 걸었으니, 본문에 들어 있는 `<script>...</script>`가 **진짜 스크립트 태그로 브라우저에 전달되어 실행**됩니다.

반면 글 목록의 제목은 안전합니다 (`templates/index.html:6`):

```html
<!-- templates/index.html:6 -->
<a href="{{ url_for('posts.post', pid=p.id) }}">{{ p.title }}</a>
```

제목 `{{ p.title }}`에는 `|safe`가 없어서 Jinja2 자동 이스케이프가 그대로 걸립니다. 그래서 제목에 `<script>`를 넣어도 글자로만 보이고 실행되지 않습니다. **본문의 `|safe` 하나가 차이를 만듭니다.**

## 3. 실습: 공격 재현

### 공격 요청

로그인한 뒤 글쓰기(`POST /write`)에서 본문에 스크립트를 넣어 저장합니다.

- **title**: `테스트` (아무거나)
- **body**:
  ```html
  <script>alert('xss')</script>
  ```

이 글은 `posts.py:24`를 통해 DB의 `posts.body`에 그대로 저장됩니다.

### 열람

저장한 글을 `GET /post/<id>`로 엽니다(글 목록에서 제목 클릭). `post.html:6`이 본문을 `|safe`로 출력하므로, 응답 HTML에 `<script>alert('xss')</script>`가 그대로 들어가고 브라우저가 이를 실행합니다.

### 기대 결과

글을 여는 순간 **`xss`라는 경고창(alert)이 뜹니다.** 저장형이므로 그 글을 여는 **모든 사용자**에게 뜹니다. `alert`는 데모일 뿐, 실제 공격이라면 쿠키 탈취(`document.cookie` 전송)나 피해자 권한으로 요청을 보내는 등으로 이어질 수 있습니다.

## 4. 탐지: WAF·Snort에서 보이는 요청 특징

이 취약점은 두 지점에서 보입니다.

1. **저장될 때** — `POST /write` 요청 **본문의 `body` 파라미터**에 스크립트 조각이 들어온다.
2. **열람될 때** — 저장형이라 `GET /post/<id>`의 **응답 HTML**에도 이스케이프되지 않은 `<script>`가 그대로 나간다.

특징적인 신호:
- `<script` 태그
- 이벤트 핸들러 `onerror=`, `onload=` 등 `on...=`
- `javascript:` 스킴
- `<img`, `<svg` 등과 결합된 `on...=` (예: `<img src=x onerror=alert(1)>`)

### 탐지 규칙 예시

**WAF (정규식 — URL 디코딩된 요청 본문/응답 본문에 적용):**

```
(?i)(<script|on\w+\s*=|javascript:)
```

**Snort — ① 저장 요청 탐지 (`POST /write` 본문):**

```
alert tcp any any -> $WEB_SERVER 443 ( \
  msg:"Stored XSS attempt in post body"; flow:to_server,established; \
  content:"POST"; http_method; content:"/write"; http_uri; \
  content:"<script"; nocase; http_client_body; \
  sid:1000011; rev:1; )
```

**Snort — ② 응답에 섞여 나가는 미이스케이프 스크립트 탐지:**

```
alert tcp $WEB_SERVER 443 -> any any ( \
  msg:"Stored XSS in HTTP response"; flow:to_client,established; \
  content:"<script>alert"; nocase; http_server_body; \
  sid:1000012; rev:1; )
```

> 참고: SQL Injection 문서와 마찬가지로, 사용자 ↔ Web 구간은 HTTPS(443)라서 암호문 그대로는 content 매치가 안 됩니다. Nginx가 복호화한 뒤의 평문 지점에서 검사해야 합니다. 저장형 XSS는 **요청(저장)과 응답(열람) 양쪽**을 봐야 완전히 잡힙니다.

## 5. 대응: 안전한 코드로 고치기

근본 원인은 "사용자 입력에 `|safe`를 걸어 자동 이스케이프를 꺼 버린 것"입니다. **`|safe`를 제거**하면 Jinja2가 본문을 자동 이스케이프해서 `<script>`가 코드가 아니라 글자로 출력됩니다.

**Before (`templates/post.html:6`):**
```html
<pre>{{ p.body|safe }}</pre>
```

**After:**
```html
<pre>{{ p.body }}</pre>
```

- `|safe`를 빼면 본문의 `<script>`는 응답에서 `&lt;script&gt;`로 바뀌어 화면에 **글자 그대로** 보이고 실행되지 않습니다.
- 줄바꿈이나 공백을 유지하려고 `<pre>` 태그는 그대로 둬도 됩니다. 문제는 `<pre>`가 아니라 `|safe`입니다.
- 원칙: **사용자 입력에는 절대 `|safe`를 쓰지 않는다.** 꼭 일부 HTML 서식을 허용해야 한다면 `|safe` 대신 허용 태그만 남기는 HTML 새니타이저(예: `bleach` 라이브러리)로 걸러서 넣습니다.

## 6. 확인 문제

<details>
<summary>Q1. 같은 입력 `<script>alert('xss')</script>`를 글 제목에 넣으면 왜 실행되지 않나?</summary>

제목은 `index.html:6`의 `{{ p.title }}`로 출력되는데 `|safe`가 없어 Jinja2 자동 이스케이프가 그대로 걸리기 때문. `<script>`가 `&lt;script&gt;`로 바뀌어 글자로만 보인다. 본문만 `post.html:6`에서 `|safe`로 이스케이프를 꺼서 실행된다.
</details>

<details>
<summary>Q2. 이 XSS가 "저장형(Stored)"이라고 불리는 이유는?</summary>

스크립트가 DB의 `posts.body`에 저장되어(`posts.py:24`), 그 글을 여는 모든 사용자에게 열람 시점마다 반복 실행되기 때문. 공격자가 한 번만 심으면 피해가 지속·확산된다.
</details>

<details>
<summary>Q3. `|safe`를 제거하면 왜 안전해지나? `<pre>`는 지워야 하나?</summary>

`|safe`를 빼면 Jinja2가 본문을 자동 이스케이프해 `<script>`를 코드가 아닌 글자(`&lt;script&gt;`)로 출력하기 때문에 실행되지 않는다. `<pre>`는 줄바꿈·공백 표시용일 뿐 취약점과 무관하므로 그대로 둬도 된다. 문제는 `|safe`다.
</details>
