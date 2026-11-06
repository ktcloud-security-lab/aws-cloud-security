# 게시판 보안 실습 교육 자료

이 폴더는 KT Cloud 보안 프로젝트의 실습용 게시판(Flask + MySQL)에 대한 교육 자료입니다.
이 게시판에는 **공부를 위해 일부러 넣어 둔 취약점**이 있습니다. WAF(웹 방화벽)와 Snort(침입 탐지 도구)로
공격을 어떻게 탐지하고 막는지 실습하는 것이 목표입니다.

> 주의: 취약점이 있는 앱이므로 인터넷 전체에 열지 마세요. 보안그룹의 80/443 인바운드는 **내 IP(/32)** 로만 엽니다.

## 읽는 순서

| 순서 | 문서 | 내용 |
|---|---|---|
| 1 | [00-구성.md](00-구성.md) | 전체 인프라가 어떻게 연결되는지 (NAT → Web → DB), 보안그룹 |
| 2 | [01-sql-injection.md](01-sql-injection.md) | SQL Injection: 로그인 우회 공격과 탐지·대응 |
| 3 | [02-stored-xss.md](02-stored-xss.md) | Stored XSS: 게시글에 심은 스크립트 실행과 탐지·대응 |

## 미리 알아 둘 용어

- **WAF (Web Application Firewall)**: 웹 요청을 들여다보고 공격 패턴을 막는 웹 전용 방화벽.
- **Snort**: 지나가는 네트워크 트래픽에서 공격 신호를 찾아 알려 주는(또는 막는) 탐지 도구.
- **취약점(vulnerability)**: 공격자가 악용할 수 있는 코드의 약한 부분.

## 실습 대상 코드 (파일별 역할)

| 파일 | 역할 |
|---|---|
| `auth.py` | 회원가입 · 로그인 · 로그아웃 (← SQL Injection 취약점) |
| `posts.py` | 글 목록 · 쓰기 · 보기 · 삭제 |
| `templates/post.html` | 게시글 상세 화면 (← Stored XSS 취약점) |
| `db.py` | MySQL 연결과 `query`/`execute` 헬퍼 |
| `schema.sql` | `users`, `posts` 테이블 정의 |
