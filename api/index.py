import base64
import json
import os
import re
import secrets
import sqlite3
import time
from dataclasses import dataclass
from hashlib import pbkdf2_hmac
from hmac import compare_digest, new as hmac_new
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles


# =========================
# 基础配置
# =========================

APP_DIR = Path(__file__).resolve().parent.parent  # repo root
DATA_DIR = APP_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Vercel 上函数文件系统不可写（除 /tmp），所以默认写到 /tmp
DEFAULT_DB = Path("/tmp/app.sqlite3") if os.environ.get("VERCEL") else (DATA_DIR / "app.sqlite3")
DB_PATH = Path(os.environ.get("DB_PATH", str(DEFAULT_DB)))

COOKIE_NAME = "admin_session"
SESSION_TTL_SECONDS = 60 * 60 * 8
SECRET_KEY = os.environ.get("ADMIN_SECRET", "dev-secret-change-me").encode("utf-8")


def now_ts() -> int:
    return int(time.time())


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
    data = base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")
    return sign_session(data)


def decode_session(token: str) -> Optional[AdminSession]:
    data = verify_session(token)
    if not data:
        return None
    try:
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

CREATE TABLE IF NOT EXISTS live_config (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  attendees_count INTEGER NOT NULL,
  round_counts_json TEXT NOT NULL,
  current_round_index INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

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
        row = conn.execute("SELECT COUNT(*) AS c FROM staff").fetchone()
        if row and int(row["c"]) == 0:
            conn.execute(
                "INSERT INTO staff(username, password_hash, is_superadmin, created_at) VALUES(?,?,?,?)",
                ("admin", pbkdf2_hash_password("admin123"), 1, now_ts()),
            )
            conn.commit()
    finally:
        conn.close()


def render_page(title: str, body_html: str) -> str:
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <link rel="stylesheet" href="/static/admin.css" />
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


def require_admin(request: Request) -> Optional[AdminSession]:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    return decode_session(token)


def api_ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"ok": True, "data": {} if data is None else data})


def api_error(status: int, message: str) -> JSONResponse:
    return JSONResponse({"ok": False, "error": message}, status_code=status)


def gen_live_numbers(attendees_count: int) -> list[int]:
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


def db_get_group(conn: sqlite3.Connection, group_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM lottery_group WHERE id=?", (group_id,)).fetchone()


def draw_group(conn: sqlite3.Connection, group_id: int) -> Tuple[bool, str]:
    group = db_get_group(conn, group_id)
    if not group:
        return False, "抽奖组不存在"
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
    existing = conn.execute("SELECT COUNT(*) AS c FROM draw_result WHERE group_id=?", (group_id,)).fetchone()
    if existing and int(existing["c"]) > 0:
        return False, "该抽奖组已开奖，如需重开请先清空结果"

    prize_remaining: Dict[int, int] = {int(p["id"]): int(p["quantity"]) for p in prizes}
    assignments = conn.execute(
        """
        SELECT a.id, a.participant_id, a.prize_id,
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
            return False, "存在跨组预分配数据"
        if pid in used_participants:
            return False, "存在同一参与者重复预分配"
        if prize_remaining.get(prize_id, 0) <= 0:
            return False, "预分配奖项数量不足"
        prize_remaining[prize_id] -= 1
        used_participants.add(pid)
        results_to_insert.append((group_id, pid, prize_id, "assignment", now_ts()))

    participant_ids = [int(x["id"]) for x in participants if int(x["id"]) not in used_participants]
    rng = secrets.SystemRandom()
    rng.shuffle(participant_ids)
    slots = []
    for prize_id, remaining in prize_remaining.items():
        slots.extend([prize_id] * remaining)
    if len(slots) > len(participant_ids):
        return False, "奖项总名额大于可用参与者数量"
    rng.shuffle(slots)
    for prize_id, pid in zip(slots, participant_ids):
        used_participants.add(pid)
        results_to_insert.append((group_id, pid, prize_id, "random", now_ts()))

    conn.executemany(
        "INSERT INTO draw_result(group_id, participant_id, prize_id, source, drawn_at) VALUES(?,?,?,?,?)",
        results_to_insert,
    )
    conn.execute("UPDATE lottery_group SET status='finished' WHERE id=?", (group_id,))
    return True, "开奖成功"


app = FastAPI()

# 非 Vercel 环境需要由应用本身提供静态资源（Vercel 由 routes 直出 /static）
app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.get("/")
def root() -> RedirectResponse:
    return RedirectResponse("/live")


@app.get("/live")
def live_page() -> HTMLResponse:
    # /live 不出现任何 admin 文案/入口
    html = """<!doctype html>
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
</html>"""
    return HTMLResponse(html)


@app.get("/admin/login")
def admin_login_page() -> HTMLResponse:
    return HTMLResponse(render_login())


@app.post("/admin/login")
async def admin_login(request: Request) -> HTMLResponse | RedirectResponse:
    form = await request.form()
    username = str(form.get("username") or "").strip()
    password = str(form.get("password") or "")
    if not username or not password:
        return HTMLResponse(render_login("请输入用户名和密码"))
    conn = open_db()
    try:
        row = conn.execute("SELECT * FROM staff WHERE username=?", (username,)).fetchone()
        if not row or not pbkdf2_verify_password(password, row["password_hash"]):
            return HTMLResponse(render_login("用户名或密码错误"))
        sess = AdminSession(
            staff_id=int(row["id"]),
            is_superadmin=bool(int(row["is_superadmin"])),
            exp=now_ts() + SESSION_TTL_SECONDS,
        )
        token = encode_session(sess)
        resp = RedirectResponse("/admin", status_code=302)
        resp.set_cookie(
            COOKIE_NAME,
            token,
            max_age=SESSION_TTL_SECONDS,
            httponly=True,
            samesite="lax",
            secure=(request.url.scheme == "https"),
            path="/",
        )
        return resp
    finally:
        conn.close()


@app.post("/admin/logout")
def admin_logout() -> RedirectResponse:
    resp = RedirectResponse("/admin/login", status_code=302)
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp


def admin_guard(request: Request) -> Optional[RedirectResponse]:
    if not require_admin(request):
        return RedirectResponse("/admin/login", status_code=302)
    return None


@app.get("/admin")
def admin_home(request: Request) -> HTMLResponse | RedirectResponse:
    redir = admin_guard(request)
    if redir:
        return redir
    html = render_page(
        "抽奖组",
        """
        <div class="page-header">
          <div>
            <div class="h1">抽奖组</div>
            <div class="muted">（可选功能）通用抽奖后台：奖项/人员/预分配/一键开奖</div>
          </div>
          <div>
            <a class="btn btn-primary" href="/admin/groups/new">新建抽奖组</a>
          </div>
        </div>
        <div id="groupsTable" class="card"></div>
        <script>window.__PAGE__ = {name:'groups'};</script>
        """,
    )
    return HTMLResponse(html)


@app.get("/admin/groups/new")
def admin_group_new(request: Request) -> HTMLResponse | RedirectResponse:
    redir = admin_guard(request)
    if redir:
        return redir
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
    return HTMLResponse(html)


@app.get("/admin/groups/{gid}")
def admin_group_detail(gid: int, request: Request) -> HTMLResponse | RedirectResponse:
    redir = admin_guard(request)
    if redir:
        return redir
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
    return HTMLResponse(html)


@app.get("/admin/staff")
def admin_staff(request: Request) -> HTMLResponse | RedirectResponse:
    redir = admin_guard(request)
    if redir:
        return redir
    sess = require_admin(request)
    if not sess or not sess.is_superadmin:
        return HTMLResponse(render_page("无权限", "<div class='alert alert-error'>只有超级管理员可以管理人员</div>"), status_code=403)
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
    return HTMLResponse(html)


@app.get("/admin/live")
def admin_live(request: Request) -> HTMLResponse | RedirectResponse:
    redir = admin_guard(request)
    if redir:
        return redir
    html = render_page(
        "现场活动配置",
        """
        <div class="page-header">
          <div>
            <div class="h1">现场活动配置</div>
            <div class="muted">录入“到场手牌数量”和“抽几轮（组数）”，系统自动分配每轮人数（最后一轮抽剩下全部）。</div>
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
          <div class="muted" style="margin-top:10px">规则：任何包含“4”的号码都不会出现（如 4/14/24/...）。</div>
        </div>
        <div class="card" style="margin-top:14px">
          <div class="card-title">每轮要抽多少人</div>
          <div class="muted">按轮手动配置每轮抽取人数；总和必须等于到场人数。</div>
          <div id="roundCountsEditor" class="table" style="margin-top:10px"></div>
          <div class="row" style="margin-top:10px">
            <button class="btn btn-ghost" onclick="LiveAdmin.fillAverage()">平均填充（可再手动改）</button>
          </div>
          <div id="roundCountsSummary" class="muted" style="margin-top:8px"></div>
        </div>
        <div class="card" style="margin-top:14px">
          <div class="card-title">当前进度</div>
          <div id="liveStateBox" class="muted">加载中...</div>
        </div>
        <script>window.__PAGE__ = {name:'live_admin'};</script>
        """,
    )
    return HTMLResponse(html)


# ============ API：live ============

@app.post("/api/live/state")
def live_state() -> JSONResponse:
    conn = open_db()
    try:
        return api_ok(get_live_state(conn))
    finally:
        conn.close()


@app.post("/api/live/config")
async def live_config(request: Request) -> JSONResponse:
    if not require_admin(request):
        return api_error(401, "未登录")
    data = await request.json()
    attendees_count = int(data.get("attendees_count") or 0)
    rounds_count = int(data.get("rounds_count") or 0)
    round_counts = data.get("round_counts")
    if attendees_count <= 0:
        return api_error(400, "到场人数必须大于0")

    if isinstance(round_counts, list) and round_counts:
        try:
            round_counts = [int(x) for x in round_counts]
        except Exception:
            return api_error(400, "每轮抽取人数必须是整数数组")
        if any(x <= 0 for x in round_counts):
            return api_error(400, "每轮抽取人数必须都大于0")
        if rounds_count > 0 and len(round_counts) != rounds_count:
            return api_error(400, "每轮抽取人数的数量必须等于轮数")
        rounds_count = len(round_counts)
        if rounds_count > attendees_count:
            return api_error(400, "轮数不能大于到场人数")
    else:
        if rounds_count <= 0:
            return api_error(400, "抽几轮必须大于0")
        if rounds_count > attendees_count:
            return api_error(400, "轮数不能大于到场人数")
        base = attendees_count // rounds_count
        last = attendees_count - base * (rounds_count - 1)
        round_counts = ([base] * (rounds_count - 1)) + [last]

    if sum(round_counts) != attendees_count:
        return api_error(400, "每轮抽取人数合计必须等于到场人数")

    conn = open_db()
    try:
        conn.execute("BEGIN")
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
        return api_ok({"message": "配置已保存"})
    except Exception as e:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        return api_error(500, f"服务器错误：{e}")
    finally:
        conn.close()


@app.post("/api/live/reset")
def live_reset(request: Request) -> JSONResponse:
    if not require_admin(request):
        return api_error(401, "未登录")
    conn = open_db()
    try:
        conn.execute("BEGIN")
        conn.execute("DELETE FROM live_pick")
        conn.execute("UPDATE live_config SET current_round_index=0, updated_at=? WHERE id=1", (now_ts(),))
        conn.commit()
        return api_ok({"message": "已重置"})
    except Exception as e:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        return api_error(500, f"服务器错误：{e}")
    finally:
        conn.close()


@app.post("/api/live/draw")
def live_draw() -> JSONResponse:
    conn = open_db()
    try:
        conn.execute("BEGIN")
        cfg = conn.execute("SELECT * FROM live_config WHERE id=1").fetchone()
        if not cfg:
            conn.execute("ROLLBACK")
            return api_error(400, "请先配置活动")
        attendees_count = int(cfg["attendees_count"])
        round_counts = json.loads(cfg["round_counts_json"] or "[]")
        current_round_index = int(cfg["current_round_index"])
        if current_round_index >= len(round_counts):
            conn.execute("ROLLBACK")
            return api_error(400, "已抽完所有轮次")

        pool = gen_live_numbers(attendees_count)
        used_rows = conn.execute("SELECT value FROM live_pick").fetchall()
        used = {int(r["value"]) for r in used_rows}
        remaining = [v for v in pool if v not in used]

        need = int(round_counts[current_round_index])
        if need > len(remaining):
            conn.execute("ROLLBACK")
            return api_error(400, "剩余人数不足，无法完成本轮抽取")

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
        return api_ok({"round_index": current_round_index, "picked": picked, "next_round_index": current_round_index + 1})
    except sqlite3.IntegrityError:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        return api_error(400, "号码重复冲突，请重试")
    except Exception as e:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        return api_error(500, f"服务器错误：{e}")
    finally:
        conn.close()


# ============ API：admin（保持与你现有前端一致的路径） ============

@app.get("/admin/api/groups/list")
def groups_list(request: Request) -> JSONResponse:
    if not require_admin(request):
        return api_error(401, "未登录")
    conn = open_db()
    try:
        rows = conn.execute("SELECT id, name, status, created_at FROM lottery_group ORDER BY id DESC").fetchall()
        return api_ok([dict(r) for r in rows])
    finally:
        conn.close()


@app.get("/admin/api/groups/get")
def groups_get(group_id: int, request: Request) -> JSONResponse:
    if not require_admin(request):
        return api_error(401, "未登录")
    conn = open_db()
    try:
        row = conn.execute("SELECT id, name, status, created_at FROM lottery_group WHERE id=?", (group_id,)).fetchone()
        if not row:
            return api_error(404, "抽奖组不存在")
        return api_ok(dict(row))
    finally:
        conn.close()


@app.post("/admin/api/groups/create")
async def groups_create(request: Request) -> JSONResponse:
    if not require_admin(request):
        return api_error(401, "未登录")
    data = await request.json()
    name = str(data.get("name") or "").strip()
    if not name:
        return api_error(400, "名称不能为空")
    conn = open_db()
    try:
        cur = conn.execute(
            "INSERT INTO lottery_group(name, status, created_at) VALUES(?,?,?)",
            (name, "draft", now_ts()),
        )
        conn.commit()
        return api_ok({"id": cur.lastrowid})
    finally:
        conn.close()


@app.post("/admin/api/groups/delete")
async def groups_delete(request: Request) -> JSONResponse:
    if not require_admin(request):
        return api_error(401, "未登录")
    data = await request.json()
    gid = int(data.get("group_id") or 0)
    conn = open_db()
    try:
        conn.execute("DELETE FROM lottery_group WHERE id=?", (gid,))
        conn.commit()
        return api_ok({})
    finally:
        conn.close()


@app.get("/admin/api/prizes/list")
def prizes_list(group_id: int, request: Request) -> JSONResponse:
    if not require_admin(request):
        return api_error(401, "未登录")
    conn = open_db()
    try:
        rows = conn.execute("SELECT id, name, quantity FROM prize WHERE group_id=? ORDER BY id DESC", (group_id,)).fetchall()
        return api_ok([dict(r) for r in rows])
    finally:
        conn.close()


@app.post("/admin/api/prizes/add")
async def prizes_add(request: Request) -> JSONResponse:
    if not require_admin(request):
        return api_error(401, "未登录")
    data = await request.json()
    gid = int(data.get("group_id") or 0)
    name = str(data.get("name") or "").strip()
    qty = int(data.get("quantity") or 0)
    if gid <= 0 or not name or qty <= 0:
        return api_error(400, "参数错误")
    conn = open_db()
    try:
        if not db_get_group(conn, gid):
            return api_error(404, "抽奖组不存在")
        conn.execute("INSERT INTO prize(group_id, name, quantity, created_at) VALUES(?,?,?,?)", (gid, name, qty, now_ts()))
        conn.commit()
        return api_ok({})
    finally:
        conn.close()


@app.post("/admin/api/prizes/delete")
async def prizes_delete(request: Request) -> JSONResponse:
    if not require_admin(request):
        return api_error(401, "未登录")
    data = await request.json()
    pid = int(data.get("prize_id") or 0)
    conn = open_db()
    try:
        conn.execute("DELETE FROM prize WHERE id=?", (pid,))
        conn.commit()
        return api_ok({})
    finally:
        conn.close()


@app.get("/admin/api/participants/list")
def participants_list(group_id: int, request: Request) -> JSONResponse:
    if not require_admin(request):
        return api_error(401, "未登录")
    conn = open_db()
    try:
        rows = conn.execute("SELECT id, name, phone, code FROM participant WHERE group_id=? ORDER BY id DESC", (group_id,)).fetchall()
        return api_ok([dict(r) for r in rows])
    finally:
        conn.close()


@app.post("/admin/api/participants/add")
async def participants_add(request: Request) -> JSONResponse:
    if not require_admin(request):
        return api_error(401, "未登录")
    data = await request.json()
    gid = int(data.get("group_id") or 0)
    name = str(data.get("name") or "").strip()
    phone = str(data.get("phone") or "").strip() or None
    code = str(data.get("code") or "").strip() or None
    if gid <= 0 or not name:
        return api_error(400, "参数错误")
    conn = open_db()
    try:
        if not db_get_group(conn, gid):
            return api_error(404, "抽奖组不存在")
        conn.execute(
            "INSERT INTO participant(group_id, name, phone, code, created_at) VALUES(?,?,?,?,?)",
            (gid, name, phone, code, now_ts()),
        )
        conn.commit()
        return api_ok({})
    finally:
        conn.close()


@app.post("/admin/api/participants/delete")
async def participants_delete(request: Request) -> JSONResponse:
    if not require_admin(request):
        return api_error(401, "未登录")
    data = await request.json()
    pid = int(data.get("participant_id") or 0)
    conn = open_db()
    try:
        conn.execute("DELETE FROM participant WHERE id=?", (pid,))
        conn.commit()
        return api_ok({})
    finally:
        conn.close()


@app.get("/admin/api/assignments/list")
def assignments_list(group_id: int, request: Request) -> JSONResponse:
    if not require_admin(request):
        return api_error(401, "未登录")
    conn = open_db()
    try:
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
            (group_id,),
        ).fetchall()
        return api_ok([dict(r) for r in rows])
    finally:
        conn.close()


@app.post("/admin/api/assignments/create")
async def assignments_create(request: Request) -> JSONResponse:
    if not require_admin(request):
        return api_error(401, "未登录")
    data = await request.json()
    gid = int(data.get("group_id") or 0)
    participant_id = int(data.get("participant_id") or 0)
    prize_id = int(data.get("prize_id") or 0)
    if gid <= 0 or participant_id <= 0 or prize_id <= 0:
        return api_error(400, "参数错误")
    conn = open_db()
    try:
        p = conn.execute("SELECT group_id FROM participant WHERE id=?", (participant_id,)).fetchone()
        z = conn.execute("SELECT group_id FROM prize WHERE id=?", (prize_id,)).fetchone()
        if not p or not z:
            return api_error(404, "参与者或奖项不存在")
        if int(p["group_id"]) != gid or int(z["group_id"]) != gid:
            return api_error(400, "参与者/奖项必须属于同一抽奖组")
        conn.execute(
            "INSERT OR REPLACE INTO assignment(group_id, participant_id, prize_id, locked, created_at) VALUES(?,?,?,?,?)",
            (gid, participant_id, prize_id, 1, now_ts()),
        )
        conn.commit()
        return api_ok({})
    finally:
        conn.close()


@app.post("/admin/api/assignments/delete")
async def assignments_delete(request: Request) -> JSONResponse:
    if not require_admin(request):
        return api_error(401, "未登录")
    data = await request.json()
    aid = int(data.get("assignment_id") or 0)
    conn = open_db()
    try:
        conn.execute("DELETE FROM assignment WHERE id=?", (aid,))
        conn.commit()
        return api_ok({})
    finally:
        conn.close()


@app.get("/admin/api/results/list")
def results_list(group_id: int, request: Request) -> JSONResponse:
    if not require_admin(request):
        return api_error(401, "未登录")
    conn = open_db()
    try:
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
            (group_id,),
        ).fetchall()
        return api_ok([dict(r) for r in rows])
    finally:
        conn.close()


@app.post("/admin/api/draw/run")
async def draw_run(request: Request) -> JSONResponse:
    if not require_admin(request):
        return api_error(401, "未登录")
    data = await request.json()
    gid = int(data.get("group_id") or 0)
    if gid <= 0:
        return api_error(400, "参数错误")
    conn = open_db()
    try:
        conn.execute("BEGIN")
        ok, msg = draw_group(conn, gid)
        if not ok:
            conn.execute("ROLLBACK")
            return api_error(400, msg)
        conn.commit()
        return api_ok({"message": msg})
    except Exception as e:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        return api_error(500, f"服务器错误：{e}")
    finally:
        conn.close()


@app.get("/admin/api/staff/list")
def staff_list(request: Request) -> JSONResponse:
    sess = require_admin(request)
    if not sess:
        return api_error(401, "未登录")
    if not sess.is_superadmin:
        return api_error(403, "无权限")
    conn = open_db()
    try:
        rows = conn.execute("SELECT id, username, is_superadmin, created_at FROM staff ORDER BY id DESC").fetchall()
        return api_ok([dict(r) for r in rows])
    finally:
        conn.close()


@app.post("/admin/api/staff/create")
async def staff_create(request: Request) -> JSONResponse:
    sess = require_admin(request)
    if not sess:
        return api_error(401, "未登录")
    if not sess.is_superadmin:
        return api_error(403, "无权限")
    data = await request.json()
    username = str(data.get("username") or "").strip()
    password = str(data.get("password") or "")
    is_super = bool(data.get("is_superadmin") or False)
    if not username or not password:
        return api_error(400, "用户名/密码不能为空")
    conn = open_db()
    try:
        conn.execute(
            "INSERT INTO staff(username, password_hash, is_superadmin, created_at) VALUES(?,?,?,?)",
            (username, pbkdf2_hash_password(password), 1 if is_super else 0, now_ts()),
        )
        conn.commit()
        return api_ok({})
    except sqlite3.IntegrityError:
        return api_error(400, "用户名已存在")
    finally:
        conn.close()


@app.post("/admin/api/staff/delete")
async def staff_delete(request: Request) -> JSONResponse:
    sess = require_admin(request)
    if not sess:
        return api_error(401, "未登录")
    if not sess.is_superadmin:
        return api_error(403, "无权限")
    data = await request.json()
    staff_id = int(data.get("staff_id") or 0)
    if staff_id <= 0:
        return api_error(400, "参数错误")
    if staff_id == sess.staff_id:
        return api_error(400, "不能删除当前登录账号")
    conn = open_db()
    try:
        conn.execute("DELETE FROM staff WHERE id=?", (staff_id,))
        conn.commit()
        return api_ok({})
    finally:
        conn.close()


