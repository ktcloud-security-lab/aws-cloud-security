# 게시판 (Flask + MySQL) — WAF/Snort 실습용 취약 앱

> ⚠️ 교육 목적으로 **SQL Injection, Stored XSS 취약점이 일부러 들어 있다**. 자세한 내용은 `docs/` 참고.
> 인터넷 전체에 열지 말 것. NAT EC2·Web EC2 보안그룹의 80/443 인바운드는 **내 IP(/32)** 로만 허용한다.

```
사용자 ─HTTPS─▶ NAT EC2 (public-subnet-a, iptables DNAT 80·443)
                 ▶ Web EC2 (private) Nginx :443 자체서명 → gunicorn 127.0.0.1:8000 → Flask
                     ▶ DB EC2 (private) MySQL :3306
```

## 파일
| 파일 | 역할 |
|---|---|
| `app.py` | Flask 앱 생성, 설정, 블루프린트 등록 |
| `db.py` | MySQL 연결(pymysql), `query`/`execute` 헬퍼, 테이블 생성 |
| `schema.sql` | 테이블 정의 |
| `auth.py` | 회원가입·로그인·로그아웃, `login_required` |
| `posts.py` | 글 목록·쓰기·보기·삭제 |
| `templates/` | HTML 템플릿 |

환경변수: `DB_HOST` `DB_PORT` `DB_USER` `DB_PASSWORD` `DB_NAME` `SECRET_KEY`

## 로컬 테스트 (Docker)
```bash
docker run -d --name board-mysql -e MYSQL_ROOT_PASSWORD=test -p 3307:3306 mysql:8.4
pip install -r requirements.txt
python test_app.py   # OK 출력되면 통과
```

## 1) DB EC2 (Ubuntu)
```bash
sudo apt update && sudo apt install -y mysql-server
sudo sed -i 's/^bind-address.*/bind-address = 0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf
sudo systemctl restart mysql
sudo mysql <<'EOF'
CREATE DATABASE board DEFAULT CHARSET utf8mb4;
CREATE USER 'board'@'<WEB_EC2_사설IP>' IDENTIFIED BY '<DB_비밀번호>';
GRANT ALL ON board.* TO 'board'@'<WEB_EC2_사설IP>';
EOF
```

## 2) Web EC2 (Ubuntu)
```bash
# 앱 설치 (board 폴더를 ~/board 로 올린 뒤)
sudo apt update && sudo apt install -y python3-venv nginx
cd ~/board && python3 -m venv venv && venv/bin/pip install -r requirements.txt

# 비밀값은 root만 읽는 파일로
sudo tee /etc/board.env >/dev/null <<EOF
DB_HOST=<DB_EC2_사설IP>
DB_PASSWORD=<DB_비밀번호>
SECRET_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(32))')
EOF
sudo chmod 600 /etc/board.env

sudo tee /etc/systemd/system/board.service >/dev/null <<'EOF'
[Unit]
After=network.target
[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/board
EnvironmentFile=/etc/board.env
ExecStart=/home/ubuntu/board/venv/bin/gunicorn -w 2 -b 127.0.0.1:8000 app:app
Restart=always
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now board

# 자체 서명 인증서 + Nginx
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -subj "/CN=board" \
  -keyout /etc/ssl/private/board.key -out /etc/ssl/certs/board.crt
sudo tee /etc/nginx/sites-available/board >/dev/null <<'EOF'
server {
    listen 80;
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl;
    ssl_certificate     /etc/ssl/certs/board.crt;
    ssl_certificate_key /etc/ssl/private/board.key;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF
sudo ln -sf /etc/nginx/sites-available/board /etc/nginx/sites-enabled/board
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

## 3) NAT EC2 — 80/443 포트포워딩
NAT 설정(`../Project3_NAT인스턴스_구축가이드.md`)이 끝난 상태에서 추가한다.
```bash
WEB=<WEB_EC2_사설IP>
IF=$(ip route show default | awk '{print $5}')   # 보통 ens5
sudo iptables -t nat -A PREROUTING -i $IF -p tcp -m multiport --dports 80,443 -j DNAT --to-destination $WEB
sudo iptables -A FORWARD -d $WEB -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -j ACCEPT
sudo netfilter-persistent save
```
응답은 Web EC2의 `0.0.0.0/0 → NAT EC2` 경로(private-rt)로 돌아오므로 추가 SNAT는 필요 없다.

## 보안그룹
| 대상 | 인바운드 |
|---|---|
| NAT EC2 | TCP 80, 443 ← 내 IP/32 |
| Web EC2 | TCP 80, 443 ← 내 IP/32 (DNAT는 출발지 IP를 바꾸지 않아서 NAT EC2 보안그룹이 아니라 **사용자 IP**가 보인다) |
| DB EC2 | TCP 3306 ← Web EC2 보안그룹 |

## 확인
1. `https://<NAT_EC2_공인IP>` 접속 → 인증서 경고 → 계속 → 게시판
2. `http://` 로 접속하면 `https://` 로 이동
3. 회원가입 → 로그인 → 글쓰기 → 보기 → 삭제
4. DB EC2: `sudo mysql -e "SELECT id,title FROM board.posts"` 에 글이 보임
