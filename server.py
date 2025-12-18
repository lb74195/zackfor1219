import json
import os
import re
import secrets
import sqlite3
import time
import base64
from dataclasses import dataclass
from hashlib import pbkdf2_hmac
from hmac import compare_digest, new as hmac_new
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse


APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "app.sqlite3"

STATIC_DIR = APP_DIR / "static"

COOKIE_NAME = "admin_session"
SESSION_TTL_SECONDS = 60 * 60 * 8

# 生产环境建议设置环境变量：ADMIN_SECRET
SECRET_KEY = os.environ.get("ADMIN_SECRET", "dev-secret-change-me").encode("utf-8")


def now_ts() -> int:
    return int(time.time())


def json_response(handler: BaseHTTPRequestHandler, status: int, payload: Any) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def html_response(handler: BaseHTTPRequestHandler, status: int, html: str) -> None:
    body = html.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def redirect(handler: BaseHTTPRequestHandler, location: str) -> None:
    handler.send_response(HTTPStatus.FOUND)
    handler.send_header("Location", location)
    handler.end_headers()


def read_body(handler: BaseHTTPRequestHandler) -> bytes:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    if length <= 0:
        return b""
    return handler.rfile.read(length)


def parse_json_body(handler: BaseHTTPRequestHandler) -> Dict[str, Any]:
    body = read_body(handler)
    if not body:
        return {}
    try:
        return json.loads(body.decode("utf-8"))
    except Exception:
        return {}


def parse_form_body(handler: BaseHTTPRequestHandler) -> Dict[str, str]:
    body = read_body(handler).decode("utf-8", errors="ignore")
    data = parse_qs(body)
    out: Dict[str, str] = {}
    for k, v in data.items():
        if not v:
            continue
        out[k] = v[0]
    return out


def pbkdf2_hash_password(password: str, salt: Optional[bytes] = None) -> str:
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return f"pbkdf2_sha256$120000${salt.hex()}${dk.hex()}"


def pbkdf2_verify_password(password: str, stored: str) -> bool:
    try:
        alg, iter_s, salt_hex, dk_hex = stored.split("$", 3)
        if alg != "pbkdf2_sha256":
            return False
        iters = int(iter_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(dk_hex)
        dk = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
        return compare_digest(dk, expected)
    except Exception:
        return False


def sign_session(data: str) -> str:
    sig = hmac_new(SECRET_KEY, data.encode("utf-8"), "sha256").hexdigest()
    return f"{data}.{sig}"


def verify_session(token: str) -> Optional[str]:
    if "." not in token:
        return None
    data, sig = token.rsplit(".", 1)
    expected = hmac_new(SECRET_KEY, data.encode("utf-8"), "sha256").hexdigest()
    if not compare_digest(sig, expected):
        return None
    return data


@dataclass
class AdminSession:
    staff_id: int
    is_superadmin: bool
    exp: int


def encode_session(sess: AdminSession) -> str:
    raw = json.dumps(
        {"staff_id": sess.staff_id, "is_superadmin": bool(sess.is_superadmin), "exp": sess.exp},
        separators=(",", ":"),
        ensure_ascii=False,
    )
    # Cookie 值要尽量只包含安全字符，避免浏览器丢弃（之前直接放 JSON 会带引号/花括号）
    data = base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")
    return sign_session(data)


def decode_session(token: str) -> Optional[AdminSession]:
    data = verify_session(token)
    if not data:
        return None
    try:
        # base64url 解码（补齐 padding）
        pad = "=" * ((4 - (len(data) % 4)) % 4)
        raw = base64.urlsafe_b64decode((data + pad).encode("ascii")).decode("utf-8")
        obj = json.loads(raw)
        sess = AdminSession(
            staff_id=int(obj["staff_id"]),
            is_superadmin=bool(obj.get("is_superadmin", False)),
            exp=int(obj["exp"]),
        )
        if sess.exp < now_ts():
            return None
        return sess
    except Exception:
        return None


def open_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS staff (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  is_superadmin INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS lottery_group (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS prize (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  quantity INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(group_id) REFERENCES lottery_group(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS participant (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  phone TEXT,
  code TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(group_id) REFERENCES lottery_group(id) ON DELETE CASCADE
);

-- 预分配/指定中奖：participant_id 必须在 group_id 下，prize_id 必须在 group_id 下
CREATE TABLE IF NOT EXISTS assignment (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_id INTEGER NOT NULL,
  participant_id INTEGER NOT NULL,
  prize_id INTEGER NOT NULL,
  locked INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  UNIQUE(group_id, participant_id),
  FOREIGN KEY(group_id) REFERENCES lottery_group(id) ON DELETE CASCADE,
  FOREIGN KEY(participant_id) REFERENCES participant(id) ON DELETE CASCADE,
  FOREIGN KEY(prize_id) REFERENCES prize(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS draw_result (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_id INTEGER NOT NULL,
  participant_id INTEGER NOT NULL,
  prize_id INTEGER NOT NULL,
  source TEXT NOT NULL,
  drawn_at INTEGER NOT NULL,
  UNIQUE(group_id, participant_id),
  FOREIGN KEY(group_id) REFERENCES lottery_group(id) ON DELETE CASCADE,
  FOREIGN KEY(participant_id) REFERENCES participant(id) ON DELETE CASCADE,
  FOREIGN KEY(prize_id) REFERENCES prize(id) ON DELETE CASCADE
);

-- 现场活动：一场活动配置（单例 id=1）
CREATE TABLE IF NOT EXISTS live_config (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  attendees_count INTEGER NOT NULL,
  round_counts_json TEXT NOT NULL,
  current_round_index INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- 现场活动：抽取结果（同一号码不可重复）
CREATE TABLE IF NOT EXISTS live_pick (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  round_index INTEGER NOT NULL,
  pick_order INTEGER NOT NULL,
  value INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(value)
);
"""


def init_db() -> None:
    conn = open_db()
    try:
        conn.executescript(SCHEMA_SQL)
        conn.commit()
        # 首次启动：创建默认超级管理员
        row = conn.execute("SELECT COUNT(*) AS c FROM staff").fetchone()
        if row and int(row["c"]) == 0:
            conn.execute(
                "INSERT INTO staff(username, password_hash, is_superadmin, created_at) VALUES(?,?,?,?)",
                ("admin", pbkdf2_hash_password("admin123"), 1, now_ts()),
            )
            conn.commit()
            print("[bootstrap] 创建默认管理员：admin / admin123（请尽快登录后台修改密码）")
    finally:
        conn.close()


def render_page(title: str, body_html: str, extra_head: str = "") -> str:
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <link rel="stylesheet" href="/static/admin.css" />
  {extra_head}
</head>
<body>
  <div class="topbar">
    <div class="brand">抽奖后台</div>
    <div class="topbar-actions">
      <a class="link" href="/admin">抽奖组</a>
      <a class="link" href="/admin/live">现场活动</a>
      <a class="link" href="/admin/staff">管理人员</a>
      <form method="POST" action="/admin/logout" style="display:inline">
        <button class="btn btn-ghost" type="submit">退出</button>
      </form>
    </div>
  </div>
  <div class="container">
    {body_html}
  </div>
  <script src="/static/admin.js"></script>
</body>
</html>"""


def render_login(error: str = "") -> str:
    err_html = f'<div class="alert alert-error">{error}</div>' if error else ""
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>管理员登录</title>
  <link rel="stylesheet" href="/static/admin.css" />
</head>
<body class="center">
  <div class="card">
    <div class="card-title">管理员登录</div>
    {err_html}
    <form method="POST" action="/admin/login">
      <label class="label">用户名</label>
      <input class="input" name="username" autocomplete="username" />
      <label class="label">密码</label>
      <input class="input" name="password" type="password" autocomplete="current-password" />
      <button class="btn btn-primary" type="submit">登录</button>
    </form>
    <div class="muted" style="margin-top:10px">首次启动默认：admin / admin123</div>
  </div>
</body>
</html>"""


def read_cookie(handler: BaseHTTPRequestHandler, name: str) -> Optional[str]:
    raw = handler.headers.get("Cookie")
    if not raw:
        return None
    c = SimpleCookie()
    c.load(raw)
    if name not in c:
        return None
    return c[name].value


def set_cookie(handler: BaseHTTPRequestHandler, name: str, value: str, max_age: int) -> None:
    handler.send_header(
        "Set-Cookie",
        f"{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}",
    )


def clear_cookie(handler: BaseHTTPRequestHandler, name: str) -> None:
    handler.send_header("Set-Cookie", f"{name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")


def require_admin(handler: BaseHTTPRequestHandler) -> Optional[AdminSession]:
    token = read_cookie(handler, COOKIE_NAME)
    if not token:
        return None
    return decode_session(token)


def ensure_admin_or_redirect(handler: BaseHTTPRequestHandler) -> Optional[AdminSession]:
    sess = require_admin(handler)
    if not sess:
        redirect(handler, "/admin/login")
        return None
    return sess


def serve_static(handler: BaseHTTPRequestHandler, path: str) -> bool:
    # 只允许访问 /static 下的文件
    if not path.startswith("/static/"):
        return False
    rel = path[len("/static/") :]
    safe_rel = rel.replace("..", "")
    file_path = STATIC_DIR / safe_rel
    if not file_path.exists() or not file_path.is_file():
        handler.send_error(HTTPStatus.NOT_FOUND)
        return True
    data = file_path.read_bytes()
    if file_path.suffix == ".css":
        ctype = "text/css; charset=utf-8"
    elif file_path.suffix == ".js":
        ctype = "application/javascript; charset=utf-8"
    else:
        ctype = "application/octet-stream"
    handler.send_response(HTTPStatus.OK)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)
    return True


def db_get_group(conn: sqlite3.Connection, group_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM lottery_group WHERE id=?", (group_id,)).fetchone()


def gen_live_numbers(attendees_count: int) -> list[int]:
    """
    生成“到场人数”对应的号码池：从 1 开始递增，跳过任何包含数字 '4' 的号码，
    直到凑够 attendees_count 个号码。
    例：5 -> [1,2,3,5,6]
    """
    out: list[int] = []
    x = 1
    while len(out) < attendees_count:
        if "4" not in str(x):
            out.append(x)
        x += 1
    return out


def get_live_state(conn: sqlite3.Connection) -> Dict[str, Any]:
    cfg = conn.execute("SELECT * FROM live_config WHERE id=1").fetchone()
    if not cfg:
        return {"configured": False}
    attendees_count = int(cfg["attendees_count"])
    round_counts = json.loads(cfg["round_counts_json"] or "[]")
    current_round_index = int(cfg["current_round_index"])
    picks = conn.execute(
        "SELECT round_index, pick_order, value FROM live_pick ORDER BY round_index ASC, pick_order ASC"
    ).fetchall()
    picks_by_round: Dict[int, list[int]] = {}
    used = set()
    for r in picks:
        ri = int(r["round_index"])
        picks_by_round.setdefault(ri, []).append(int(r["value"]))
        used.add(int(r["value"]))
    pool = gen_live_numbers(attendees_count)
    pool_max = int(pool[-1]) if pool else 0
    remaining = [v for v in pool if v not in used]
    return {
        "configured": True,
        "attendees_count": attendees_count,
        "pool_max": pool_max,
        "round_counts": round_counts,
        "current_round_index": current_round_index,
        "picks_by_round": picks_by_round,
        "remaining_count": len(remaining),
        "created_at": int(cfg["created_at"]),
        "updated_at": int(cfg["updated_at"]),
    }


def api_error(handler: BaseHTTPRequestHandler, status: int, message: str) -> None:
    json_response(handler, status, {"ok": False, "error": message})


def api_ok(handler: BaseHTTPRequestHandler, payload: Any = None) -> None:
    if payload is None:
        payload = {}
    json_response(handler, HTTPStatus.OK, {"ok": True, "data": payload})


def draw_group(conn: sqlite3.Connection, group_id: int) -> Tuple[bool, str]:
    # 事务中执行：校验 -> 写入 draw_result
    group = db_get_group(conn, group_id)
    if not group:
        return False, "抽奖组不存在"

    # 奖项与数量
    prizes = conn.execute(
        "SELECT id, name, quantity FROM prize WHERE group_id=? ORDER BY id ASC", (group_id,)
    ).fetchall()
    if not prizes:
        return False, "该抽奖组还没有配置奖项"

    participants = conn.execute(
        "SELECT id, name FROM participant WHERE group_id=? ORDER BY id ASC", (group_id,)
    ).fetchall()
    if not participants:
        return False, "该抽奖组还没有导入/添加参与人员"

    # 已开奖：不允许重复写入（简单策略）
    existing = conn.execute(
        "SELECT COUNT(*) AS c FROM draw_result WHERE group_id=?", (group_id,)
    ).fetchone()
    if existing and int(existing["c"]) > 0:
        return False, "该抽奖组已开奖，如需重开请先清空结果（后续可加功能）"

    prize_remaining: Dict[int, int] = {int(p["id"]): int(p["quantity"]) for p in prizes}

    # 预分配（锁定）
    assignments = conn.execute(
        """
        SELECT a.id, a.participant_id, a.prize_id, a.locked,
               p.group_id AS participant_group_id,
               z.group_id AS prize_group_id
        FROM assignment a
        JOIN participant p ON p.id = a.participant_id
        JOIN prize z ON z.id = a.prize_id
        WHERE a.group_id=?
        ORDER BY a.id ASC
        """,
        (group_id,),
    ).fetchall()

    used_participants = set()
    results_to_insert = []

    for a in assignments:
        pid = int(a["participant_id"])
        prize_id = int(a["prize_id"])
        if int(a["participant_group_id"]) != group_id or int(a["prize_group_id"]) != group_id:
            return False, "存在跨组预分配数据（请检查预分配配置）"
        if pid in used_participants:
            return False, "存在同一参与者重复预分配（请检查预分配配置）"
        if prize_id not in prize_remaining:
            return False, "预分配的奖项不存在"
        if prize_remaining[prize_id] <= 0:
            return False, "预分配奖项数量不足"
        prize_remaining[prize_id] -= 1
        used_participants.add(pid)
        results_to_insert.append((group_id, pid, prize_id, "assignment", now_ts()))

    # 随机分配剩余名额
    participant_ids = [int(x["id"]) for x in participants if int(x["id"]) not in used_participants]
    rng = secrets.SystemRandom()
    rng.shuffle(participant_ids)

    # 构造 prize slots
    slots = []
    for prize_id, remaining in prize_remaining.items():
        slots.extend([prize_id] * remaining)
    if len(slots) > len(participant_ids):
        return False, "奖项总名额大于可用参与者数量（考虑减少数量或允许一人多奖）"
    rng.shuffle(slots)
    for prize_id, pid in zip(slots, participant_ids):
        used_participants.add(pid)
        results_to_insert.append((group_id, pid, prize_id, "random", now_ts()))

    # 写入结果
    conn.executemany(
        "INSERT INTO draw_result(group_id, participant_id, prize_id, source, drawn_at) VALUES(?,?,?,?,?)",
        results_to_insert,
    )
    conn.execute("UPDATE lottery_group SET status='finished' WHERE id=?", (group_id,))
    return True, "开奖成功"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:
        # 简化输出
        return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if serve_static(self, path):
            return

        if path == "/":
            redirect(self, "/live")
            return

        if path == "/live":
            html_response(
                self,
                HTTPStatus.OK,
                """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>现场抽号</title>
  <link rel="stylesheet" href="/static/live.css" />
</head>
<body>
  <div class="live-topbar">
    <div class="brand">现场抽号</div>
  </div>
  <div class="live-container">
    <div id="needConfigCard" class="card" style="display:none">
      <div class="card-title">尚未配置活动</div>
      <div class="muted">请联系工作人员先完成活动配置，然后这里就能开始抽号。</div>
      <div class="row" style="margin-top:12px">
        <button class="btn btn-ghost" onclick="Live.loadState()">刷新状态</button>
      </div>
    </div>

    <div id="drawCard" class="card" style="display:none">
      <div class="page-header">
        <div>
          <div class="h1" id="liveTitle">抽号进行中</div>
          <div class="muted" id="liveMeta"></div>
        </div>
        <div class="row">
          <button class="btn btn-danger" onclick="Live.resetAll()">清空重新开始</button>
        </div>
      </div>

      <div class="roll-box">
        <div class="roll-label" id="rollLabel">准备就绪</div>
        <div class="roll-number" id="rollNumber">—</div>
        <div class="row" style="justify-content:center;margin-top:14px">
          <button class="btn btn-primary btn-big" id="drawBtn" onclick="Live.drawNext()">开始本轮抽取</button>
        </div>
      </div>

      <div class="card" style="margin-top:14px;background:rgba(255,255,255,.03)">
        <div class="card-title">轮次占位</div>
        <div id="roundBoard" class="round-board"></div>
      </div>
    </div>
  </div>

  <script src="/static/live.js"></script>
</body>
</html>""",
            )
            return

        if path == "/admin/login":
            html_response(self, HTTPStatus.OK, render_login())
            return

        # /admin 下的页面都要登录
        if path.startswith("/admin"):
            sess = ensure_admin_or_redirect(self)
            if not sess:
                return

            if path == "/admin" or path == "/admin/":
                html = render_page(
                    "抽奖组",
                    """
                    <div class="page-header">
                      <div>
                        <div class="h1">抽奖组</div>
                        <div class="muted">支持多组抽奖，每组独立配置奖项/人员/预分配与开奖结果</div>
                      </div>
                      <div>
                        <a class="btn btn-primary" href="/admin/groups/new">新建抽奖组</a>
                      </div>
                    </div>
                    <div id="groupsTable" class="card"></div>
                    <script>window.__PAGE__ = {name:'groups'};</script>
                    """,
                )
                html_response(self, HTTPStatus.OK, html)
                return

            if path == "/admin/groups/new":
                html = render_page(
                    "新建抽奖组",
                    """
                    <div class="page-header">
                      <div class="h1">新建抽奖组</div>
                      <div><a class="btn btn-ghost" href="/admin">返回</a></div>
                    </div>
                    <div class="card">
                      <label class="label">抽奖组名称</label>
                      <input id="groupName" class="input" placeholder="例如：年会抽奖（第一轮）" />
                      <button class="btn btn-primary" style="margin-top:12px" onclick="Admin.createGroup()">创建</button>
                    </div>
                    <script>window.__PAGE__ = {name:'group_new'};</script>
                    """,
                )
                html_response(self, HTTPStatus.OK, html)
                return

            m = re.match(r"^/admin/groups/(\d+)$", path)
            if m:
                gid = int(m.group(1))
                html = render_page(
                    f"抽奖组 #{gid}",
                    f"""
                    <div class="page-header">
                      <div>
                        <div class="h1">抽奖组 #{gid}</div>
                        <div id="groupMeta" class="muted"></div>
                      </div>
                      <div class="row">
                        <a class="btn btn-ghost" href="/admin">返回</a>
                        <button class="btn btn-danger" onclick="Admin.runDraw({gid})">一键开奖</button>
                      </div>
                    </div>

                    <div class="grid2">
                      <div class="card">
                        <div class="card-title">奖项</div>
                        <div class="row">
                          <input id="prizeName" class="input" placeholder="奖项名称（如：一等奖）" />
                          <input id="prizeQty" class="input" style="max-width:140px" placeholder="数量" value="1" />
                          <button class="btn btn-primary" onclick="Admin.addPrize({gid})">添加</button>
                        </div>
                        <div id="prizeTable" class="table"></div>
                      </div>
                      <div class="card">
                        <div class="card-title">参与人员</div>
                        <div class="row">
                          <input id="pName" class="input" placeholder="姓名" />
                          <input id="pPhone" class="input" placeholder="手机号(可选)" />
                          <input id="pCode" class="input" placeholder="工号/编号(可选)" />
                          <button class="btn btn-primary" onclick="Admin.addParticipant({gid})">添加</button>
                        </div>
                        <div id="participantTable" class="table"></div>
                      </div>
                    </div>

                    <div class="card" style="margin-top:14px">
                      <div class="card-title">预分配（指定谁中什么奖）</div>
                      <div class="muted">预分配会在开奖时优先兑现；如果奖项名额不足会直接报错阻止开奖。</div>
                      <div class="row" style="margin-top:10px">
                        <select id="assignParticipant" class="select"></select>
                        <select id="assignPrize" class="select"></select>
                        <button class="btn btn-primary" onclick="Admin.createAssignment({gid})">创建预分配</button>
                      </div>
                      <div id="assignmentTable" class="table"></div>
                    </div>

                    <div class="card" style="margin-top:14px">
                      <div class="card-title">开奖结果</div>
                      <div id="resultTable" class="table"></div>
                    </div>

                    <script>window.__PAGE__ = {{name:'group_detail', groupId:{gid}}};</script>
                    """,
                )
                html_response(self, HTTPStatus.OK, html)
                return

            if path == "/admin/staff":
                # 超级管理员才可管理人员
                if not sess.is_superadmin:
                    html_response(
                        self,
                        HTTPStatus.FORBIDDEN,
                        render_page("无权限", "<div class='alert alert-error'>只有超级管理员可以管理人员</div>"),
                    )
                    return
                html = render_page(
                    "管理人员",
                    """
                    <div class="page-header">
                      <div>
                        <div class="h1">管理人员</div>
                        <div class="muted">创建/删除后台管理账号（仅超级管理员可见）</div>
                      </div>
                    </div>
                    <div class="card">
                      <div class="row">
                        <input id="staffUsername" class="input" placeholder="用户名" />
                        <input id="staffPassword" class="input" placeholder="初始密码" type="password" />
                        <label class="row" style="gap:8px; align-items:center;">
                          <input id="staffSuper" type="checkbox" />
                          <span class="muted">超级管理员</span>
                        </label>
                        <button class="btn btn-primary" onclick="Admin.createStaff()">创建</button>
                      </div>
                      <div id="staffTable" class="table"></div>
                    </div>
                    <script>window.__PAGE__ = {name:'staff'};</script>
                    """,
                )
                html_response(self, HTTPStatus.OK, html)
                return

            if path == "/admin/live":
                html = render_page(
                    "现场活动配置",
                    """
                    <div class="page-header">
                      <div>
                        <div class="h1">现场活动配置</div>
                        <div class="muted">这里负责配置“到场手牌数量”和“抽几轮（组数）”；现场大屏请使用 <code>/live</code>。</div>
                      </div>
                      <div class="row">
                        <a class="btn btn-ghost" href="/live" target="_blank">打开现场大屏</a>
                      </div>
                    </div>

                    <div class="card">
                      <div class="card-title">配置</div>
                      <div class="row">
                        <div style="min-width:260px">
                          <label class="label">到场人数</label>
                          <input id="attendeesCount" class="input" placeholder="例如：100" />
                        </div>
                        <div style="min-width:260px">
                          <label class="label">抽几轮（组数）</label>
                          <input id="roundsCount" class="input" placeholder="例如：7" />
                        </div>
                      </div>
                      <div class="row" style="margin-top:12px">
                        <button class="btn btn-primary" onclick="LiveAdmin.save()">保存配置</button>
                        <button class="btn btn-danger" onclick="LiveAdmin.reset()">清空抽取结果并回到第1轮</button>
                      </div>
                      <div class="muted" style="margin-top:10px">系统会自动平均分配每轮抽取人数，若无法整除，最后一轮会把剩余全部抽出。规则：任何包含“4”的号码都不会出现（如 4/14/24/...）。</div>
                    </div>

                    <div class="card" style="margin-top:14px">
                      <div class="card-title">当前进度</div>
                      <div id="liveStateBox" class="muted">加载中...</div>
                    </div>

                    <script>window.__PAGE__ = {name:'live_admin'};</script>
                    """,
                )
                html_response(self, HTTPStatus.OK, html)
                return

            # 未匹配到页面
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        # 其他所有路由：404
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        # 现场活动 API（无需登录）
        if path.startswith("/api/live/"):
            if path == "/api/live/state":
                conn = open_db()
                try:
                    api_ok(self, get_live_state(conn))
                    return
                finally:
                    conn.close()

            if path == "/api/live/config":
                # 配置只能在 /admin 下操作（需要登录），/live 只负责抽取与展示
                sess = require_admin(self)
                if not sess:
                    api_error(self, HTTPStatus.UNAUTHORIZED, "未登录")
                    return
                data = parse_json_body(self)
                attendees_count = int(data.get("attendees_count") or 0)
                rounds_count = int(data.get("rounds_count") or 0)
                round_counts = data.get("round_counts")
                if attendees_count <= 0:
                    api_error(self, HTTPStatus.BAD_REQUEST, "到场人数必须大于0")
                    return
                # 推荐/默认：只输入“抽几轮”，系统自动分配；为兼容旧前端也允许 round_counts
                if rounds_count > 0:
                    if rounds_count > attendees_count:
                        api_error(self, HTTPStatus.BAD_REQUEST, "轮数不能大于到场人数")
                        return
                    base = attendees_count // rounds_count
                    last = attendees_count - base * (rounds_count - 1)
                    round_counts = ([base] * (rounds_count - 1)) + [last]
                else:
                    if not isinstance(round_counts, list) or not round_counts:
                        api_error(self, HTTPStatus.BAD_REQUEST, "请提供抽几轮（rounds_count）")
                        return
                    try:
                        round_counts = [int(x) for x in round_counts]
                    except Exception:
                        api_error(self, HTTPStatus.BAD_REQUEST, "每轮抽取人数必须是整数数组")
                        return
                    if any(x <= 0 for x in round_counts):
                        api_error(self, HTTPStatus.BAD_REQUEST, "每轮抽取人数必须都大于0")
                        return

                # 校验：总抽取人数必须等于到场人数（每个手牌最终都会被抽到一次）
                total_needed = sum(round_counts)
                if total_needed != attendees_count:
                    api_error(self, HTTPStatus.BAD_REQUEST, "总抽取人数必须等于到场人数（最后一轮抽剩下全部）")
                    return

                conn = open_db()
                try:
                    conn.execute("BEGIN")
                    # 清空旧进度
                    conn.execute("DELETE FROM live_pick")
                    ts = now_ts()
                    conn.execute(
                        """
                        INSERT INTO live_config(id, attendees_count, round_counts_json, current_round_index, created_at, updated_at)
                        VALUES(1, ?, ?, 0, ?, ?)
                        ON CONFLICT(id) DO UPDATE SET
                          attendees_count=excluded.attendees_count,
                          round_counts_json=excluded.round_counts_json,
                          current_round_index=0,
                          updated_at=excluded.updated_at
                        """,
                        (attendees_count, json.dumps(round_counts, ensure_ascii=False), ts, ts),
                    )
                    conn.commit()
                    api_ok(self, {"message": "配置已保存"})
                    return
                except Exception as e:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:
                        pass
                    api_error(self, HTTPStatus.INTERNAL_SERVER_ERROR, f"服务器错误：{e}")
                    return
                finally:
                    conn.close()

            if path == "/api/live/reset":
                sess = require_admin(self)
                if not sess:
                    api_error(self, HTTPStatus.UNAUTHORIZED, "未登录")
                    return
                conn = open_db()
                try:
                    conn.execute("BEGIN")
                    conn.execute("DELETE FROM live_pick")
                    conn.execute("UPDATE live_config SET current_round_index=0, updated_at=? WHERE id=1", (now_ts(),))
                    conn.commit()
                    api_ok(self, {"message": "已重置"})
                    return
                except Exception as e:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:
                        pass
                    api_error(self, HTTPStatus.INTERNAL_SERVER_ERROR, f"服务器错误：{e}")
                    return
                finally:
                    conn.close()

            if path == "/api/live/draw":
                conn = open_db()
                try:
                    conn.execute("BEGIN")
                    cfg = conn.execute("SELECT * FROM live_config WHERE id=1").fetchone()
                    if not cfg:
                        conn.execute("ROLLBACK")
                        api_error(self, HTTPStatus.BAD_REQUEST, "请先配置活动")
                        return
                    attendees_count = int(cfg["attendees_count"])
                    round_counts = json.loads(cfg["round_counts_json"] or "[]")
                    current_round_index = int(cfg["current_round_index"])
                    if current_round_index >= len(round_counts):
                        conn.execute("ROLLBACK")
                        api_error(self, HTTPStatus.BAD_REQUEST, "已抽完所有轮次")
                        return

                    # 计算剩余号码池
                    pool = gen_live_numbers(attendees_count)
                    used_rows = conn.execute("SELECT value FROM live_pick").fetchall()
                    used = {int(r["value"]) for r in used_rows}
                    remaining = [v for v in pool if v not in used]

                    need = int(round_counts[current_round_index])
                    if need > len(remaining):
                        conn.execute("ROLLBACK")
                        api_error(self, HTTPStatus.BAD_REQUEST, "剩余人数不足，无法完成本轮抽取")
                        return

                    rng = secrets.SystemRandom()
                    picked = rng.sample(remaining, need)
                    ts = now_ts()
                    for i, v in enumerate(picked, start=1):
                        conn.execute(
                            "INSERT INTO live_pick(round_index, pick_order, value, created_at) VALUES(?,?,?,?)",
                            (current_round_index, i, int(v), ts),
                        )
                    conn.execute(
                        "UPDATE live_config SET current_round_index=?, updated_at=? WHERE id=1",
                        (current_round_index + 1, ts),
                    )
                    conn.commit()
                    api_ok(
                        self,
                        {
                            "round_index": current_round_index,
                            "picked": picked,
                            "next_round_index": current_round_index + 1,
                        },
                    )
                    return
                except sqlite3.IntegrityError:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:
                        pass
                    api_error(self, HTTPStatus.BAD_REQUEST, "号码重复冲突，请重试")
                    return
                except Exception as e:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:
                        pass
                    api_error(self, HTTPStatus.INTERNAL_SERVER_ERROR, f"服务器错误：{e}")
                    return
                finally:
                    conn.close()

            api_error(self, HTTPStatus.NOT_FOUND, "未知API")
            return

        if path == "/admin/login":
            form = parse_form_body(self)
            username = (form.get("username") or "").strip()
            password = form.get("password") or ""
            if not username or not password:
                html_response(self, HTTPStatus.OK, render_login("请输入用户名和密码"))
                return
            conn = open_db()
            try:
                row = conn.execute("SELECT * FROM staff WHERE username=?", (username,)).fetchone()
                if not row or not pbkdf2_verify_password(password, row["password_hash"]):
                    html_response(self, HTTPStatus.OK, render_login("用户名或密码错误"))
                    return
                sess = AdminSession(
                    staff_id=int(row["id"]),
                    is_superadmin=bool(int(row["is_superadmin"])),
                    exp=now_ts() + SESSION_TTL_SECONDS,
                )
                token = encode_session(sess)
                self.send_response(HTTPStatus.FOUND)
                set_cookie(self, COOKIE_NAME, token, SESSION_TTL_SECONDS)
                self.send_header("Location", "/admin")
                self.end_headers()
                return
            finally:
                conn.close()

        if path == "/admin/logout":
            self.send_response(HTTPStatus.FOUND)
            clear_cookie(self, COOKIE_NAME)
            self.send_header("Location", "/admin/login")
            self.end_headers()
            return

        # API：必须登录且必须在 /admin/api 下
        if path.startswith("/admin/api/"):
            sess = require_admin(self)
            if not sess:
                api_error(self, HTTPStatus.UNAUTHORIZED, "未登录")
                return

            # 路由分发
            if path == "/admin/api/groups/create":
                data = parse_json_body(self)
                name = (data.get("name") or "").strip()
                if not name:
                    api_error(self, HTTPStatus.BAD_REQUEST, "名称不能为空")
                    return
                conn = open_db()
                try:
                    cur = conn.execute(
                        "INSERT INTO lottery_group(name, status, created_at) VALUES(?,?,?)",
                        (name, "draft", now_ts()),
                    )
                    conn.commit()
                    api_ok(self, {"id": cur.lastrowid})
                    return
                finally:
                    conn.close()

            if path == "/admin/api/groups/delete":
                data = parse_json_body(self)
                gid = int(data.get("group_id") or 0)
                conn = open_db()
                try:
                    conn.execute("DELETE FROM lottery_group WHERE id=?", (gid,))
                    conn.commit()
                    api_ok(self, {})
                    return
                finally:
                    conn.close()

            if path == "/admin/api/prizes/add":
                data = parse_json_body(self)
                gid = int(data.get("group_id") or 0)
                name = (data.get("name") or "").strip()
                qty = int(data.get("quantity") or 0)
                if gid <= 0 or not name or qty <= 0:
                    api_error(self, HTTPStatus.BAD_REQUEST, "参数错误")
                    return
                conn = open_db()
                try:
                    if not db_get_group(conn, gid):
                        api_error(self, HTTPStatus.NOT_FOUND, "抽奖组不存在")
                        return
                    conn.execute(
                        "INSERT INTO prize(group_id, name, quantity, created_at) VALUES(?,?,?,?)",
                        (gid, name, qty, now_ts()),
                    )
                    conn.commit()
                    api_ok(self, {})
                    return
                finally:
                    conn.close()

            if path == "/admin/api/prizes/delete":
                data = parse_json_body(self)
                pid = int(data.get("prize_id") or 0)
                conn = open_db()
                try:
                    conn.execute("DELETE FROM prize WHERE id=?", (pid,))
                    conn.commit()
                    api_ok(self, {})
                    return
                finally:
                    conn.close()

            if path == "/admin/api/participants/add":
                data = parse_json_body(self)
                gid = int(data.get("group_id") or 0)
                name = (data.get("name") or "").strip()
                phone = (data.get("phone") or "").strip() or None
                code = (data.get("code") or "").strip() or None
                if gid <= 0 or not name:
                    api_error(self, HTTPStatus.BAD_REQUEST, "参数错误")
                    return
                conn = open_db()
                try:
                    if not db_get_group(conn, gid):
                        api_error(self, HTTPStatus.NOT_FOUND, "抽奖组不存在")
                        return
                    conn.execute(
                        "INSERT INTO participant(group_id, name, phone, code, created_at) VALUES(?,?,?,?,?)",
                        (gid, name, phone, code, now_ts()),
                    )
                    conn.commit()
                    api_ok(self, {})
                    return
                finally:
                    conn.close()

            if path == "/admin/api/participants/delete":
                data = parse_json_body(self)
                pid = int(data.get("participant_id") or 0)
                conn = open_db()
                try:
                    conn.execute("DELETE FROM participant WHERE id=?", (pid,))
                    conn.commit()
                    api_ok(self, {})
                    return
                finally:
                    conn.close()

            if path == "/admin/api/assignments/create":
                data = parse_json_body(self)
                gid = int(data.get("group_id") or 0)
                participant_id = int(data.get("participant_id") or 0)
                prize_id = int(data.get("prize_id") or 0)
                if gid <= 0 or participant_id <= 0 or prize_id <= 0:
                    api_error(self, HTTPStatus.BAD_REQUEST, "参数错误")
                    return
                conn = open_db()
                try:
                    # 校验同组
                    p = conn.execute("SELECT group_id FROM participant WHERE id=?", (participant_id,)).fetchone()
                    z = conn.execute("SELECT group_id FROM prize WHERE id=?", (prize_id,)).fetchone()
                    if not p or not z:
                        api_error(self, HTTPStatus.NOT_FOUND, "参与者或奖项不存在")
                        return
                    if int(p["group_id"]) != gid or int(z["group_id"]) != gid:
                        api_error(self, HTTPStatus.BAD_REQUEST, "参与者/奖项必须属于同一抽奖组")
                        return
                    conn.execute(
                        "INSERT OR REPLACE INTO assignment(group_id, participant_id, prize_id, locked, created_at) VALUES(?,?,?,?,?)",
                        (gid, participant_id, prize_id, 1, now_ts()),
                    )
                    conn.commit()
                    api_ok(self, {})
                    return
                finally:
                    conn.close()

            if path == "/admin/api/assignments/delete":
                data = parse_json_body(self)
                aid = int(data.get("assignment_id") or 0)
                conn = open_db()
                try:
                    conn.execute("DELETE FROM assignment WHERE id=?", (aid,))
                    conn.commit()
                    api_ok(self, {})
                    return
                finally:
                    conn.close()

            if path == "/admin/api/draw/run":
                data = parse_json_body(self)
                gid = int(data.get("group_id") or 0)
                if gid <= 0:
                    api_error(self, HTTPStatus.BAD_REQUEST, "参数错误")
                    return
                conn = open_db()
                try:
                    conn.execute("BEGIN")
                    ok, msg = draw_group(conn, gid)
                    if not ok:
                        conn.execute("ROLLBACK")
                        api_error(self, HTTPStatus.BAD_REQUEST, msg)
                        return
                    conn.commit()
                    api_ok(self, {"message": msg})
                    return
                except Exception as e:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:
                        pass
                    api_error(self, HTTPStatus.INTERNAL_SERVER_ERROR, f"服务器错误：{e}")
                    return
                finally:
                    conn.close()

            if path == "/admin/api/staff/create":
                if not sess.is_superadmin:
                    api_error(self, HTTPStatus.FORBIDDEN, "无权限")
                    return
                data = parse_json_body(self)
                username = (data.get("username") or "").strip()
                password = data.get("password") or ""
                is_super = bool(data.get("is_superadmin") or False)
                if not username or not password:
                    api_error(self, HTTPStatus.BAD_REQUEST, "用户名/密码不能为空")
                    return
                conn = open_db()
                try:
                    conn.execute(
                        "INSERT INTO staff(username, password_hash, is_superadmin, created_at) VALUES(?,?,?,?)",
                        (username, pbkdf2_hash_password(password), 1 if is_super else 0, now_ts()),
                    )
                    conn.commit()
                    api_ok(self, {})
                    return
                except sqlite3.IntegrityError:
                    api_error(self, HTTPStatus.BAD_REQUEST, "用户名已存在")
                    return
                finally:
                    conn.close()

            if path == "/admin/api/staff/delete":
                if not sess.is_superadmin:
                    api_error(self, HTTPStatus.FORBIDDEN, "无权限")
                    return
                data = parse_json_body(self)
                staff_id = int(data.get("staff_id") or 0)
                if staff_id <= 0:
                    api_error(self, HTTPStatus.BAD_REQUEST, "参数错误")
                    return
                if staff_id == sess.staff_id:
                    api_error(self, HTTPStatus.BAD_REQUEST, "不能删除当前登录账号")
                    return
                conn = open_db()
                try:
                    conn.execute("DELETE FROM staff WHERE id=?", (staff_id,))
                    conn.commit()
                    api_ok(self, {})
                    return
                finally:
                    conn.close()

            api_error(self, HTTPStatus.NOT_FOUND, "未知API")
            return

        self.send_error(HTTPStatus.NOT_FOUND)

    def do_DELETE(self) -> None:
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_PUT(self) -> None:
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self.end_headers()


class ApiGetHandler(BaseHTTPRequestHandler):
    pass


def handle_admin_api_get(handler: BaseHTTPRequestHandler, path: str, sess: AdminSession) -> None:
    parsed = urlparse(handler.path)
    qs = parse_qs(parsed.query)

    def q_int(name: str, default: int = 0) -> int:
        v = qs.get(name, [str(default)])[0]
        try:
            return int(v)
        except Exception:
            return default

    conn = open_db()
    try:
        if path == "/admin/api/groups/list":
            rows = conn.execute(
                "SELECT id, name, status, created_at FROM lottery_group ORDER BY id DESC"
            ).fetchall()
            api_ok(handler, [dict(r) for r in rows])
            return

        if path == "/admin/api/groups/get":
            gid = q_int("group_id")
            row = conn.execute(
                "SELECT id, name, status, created_at FROM lottery_group WHERE id=?", (gid,)
            ).fetchone()
            if not row:
                api_error(handler, HTTPStatus.NOT_FOUND, "抽奖组不存在")
                return
            api_ok(handler, dict(row))
            return

        if path == "/admin/api/prizes/list":
            gid = q_int("group_id")
            rows = conn.execute(
                "SELECT id, name, quantity FROM prize WHERE group_id=? ORDER BY id DESC",
                (gid,),
            ).fetchall()
            api_ok(handler, [dict(r) for r in rows])
            return

        if path == "/admin/api/participants/list":
            gid = q_int("group_id")
            rows = conn.execute(
                "SELECT id, name, phone, code FROM participant WHERE group_id=? ORDER BY id DESC",
                (gid,),
            ).fetchall()
            api_ok(handler, [dict(r) for r in rows])
            return

        if path == "/admin/api/assignments/list":
            gid = q_int("group_id")
            rows = conn.execute(
                """
                SELECT a.id, a.participant_id, a.prize_id, a.locked,
                       p.name AS participant_name,
                       z.name AS prize_name
                FROM assignment a
                JOIN participant p ON p.id=a.participant_id
                JOIN prize z ON z.id=a.prize_id
                WHERE a.group_id=?
                ORDER BY a.id DESC
                """,
                (gid,),
            ).fetchall()
            api_ok(handler, [dict(r) for r in rows])
            return

        if path == "/admin/api/results/list":
            gid = q_int("group_id")
            rows = conn.execute(
                """
                SELECT r.id, r.participant_id, r.prize_id, r.source, r.drawn_at,
                       p.name AS participant_name,
                       z.name AS prize_name
                FROM draw_result r
                JOIN participant p ON p.id=r.participant_id
                JOIN prize z ON z.id=r.prize_id
                WHERE r.group_id=?
                ORDER BY z.id ASC, r.id ASC
                """,
                (gid,),
            ).fetchall()
            api_ok(handler, [dict(r) for r in rows])
            return

        if path == "/admin/api/staff/list":
            if not sess.is_superadmin:
                api_error(handler, HTTPStatus.FORBIDDEN, "无权限")
                return
            rows = conn.execute(
                "SELECT id, username, is_superadmin, created_at FROM staff ORDER BY id DESC"
            ).fetchall()
            api_ok(handler, [dict(r) for r in rows])
            return

        api_error(handler, HTTPStatus.NOT_FOUND, "未知API")
    finally:
        conn.close()


def patch_get_into_handler() -> None:
    # 把 GET 的 /admin/api/* 交给 handle_admin_api_get 处理
    old_do_get = Handler.do_GET

    def new_do_get(self: Handler) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path.startswith("/admin/api/"):
            sess = require_admin(self)
            if not sess:
                api_error(self, HTTPStatus.UNAUTHORIZED, "未登录")
                return
            handle_admin_api_get(self, path, sess)
            return
        return old_do_get(self)

    Handler.do_GET = new_do_get  # type: ignore[method-assign]


def main() -> None:
    init_db()
    patch_get_into_handler()
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"✅ 抽奖后台已启动： http://127.0.0.1:{port}/admin")
    server.serve_forever()


if __name__ == "__main__":
    main()


