const Admin = (() => {
  async function apiGet(path) {
    const res = await fetch(path, { credentials: "same-origin" });
    const json = await res.json().catch(() => ({}));
    if (!res.ok || !json.ok) throw new Error((json && json.error) || "请求失败");
    return json.data;
  }

  async function apiPost(path, body) {
    const res = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok || !json.ok) throw new Error((json && json.error) || "请求失败");
    return json.data;
  }

  function el(id) {
    return document.getElementById(id);
  }

  function escapeHtml(s) {
    return String(s || "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function fmtTs(ts) {
    if (!ts) return "-";
    const d = new Date(ts * 1000);
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")} ${String(
      d.getHours()
    ).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
  }

  function toast(msg, type = "ok") {
    const n = document.createElement("div");
    n.className = `alert ${type === "error" ? "alert-error" : "alert-ok"}`;
    n.textContent = msg;
    document.querySelector(".container").prepend(n);
    setTimeout(() => n.remove(), 2600);
  }

  async function renderGroups() {
    const box = el("groupsTable");
    const groups = await apiGet("/admin/api/groups/list");
    if (!groups.length) {
      box.innerHTML = `<div class="muted">还没有抽奖组，先新建一个吧。</div>`;
      return;
    }
    const rows = groups
      .map(
        (g) => `
      <div class="tr">
        <div class="td">
          <div style="font-weight:800">${escapeHtml(g.name)}</div>
          <div class="muted">#${g.id} · ${escapeHtml(g.status)} · ${fmtTs(g.created_at)}</div>
        </div>
        <div class="actions">
          <a class="btn btn-primary" href="/admin/groups/${g.id}">进入</a>
          <button class="btn btn-danger" onclick="Admin.deleteGroup(${g.id})">删除</button>
        </div>
      </div>`
      )
      .join("");
    box.innerHTML = `<div class="table">
      <div class="tr th">
        <div class="td">抽奖组</div><div class="td" style="text-align:right">操作</div>
      </div>
      ${rows}
    </div>`;
  }

  async function createGroup() {
    const name = (el("groupName").value || "").trim();
    if (!name) return toast("请输入抽奖组名称", "error");
    try {
      const data = await apiPost("/admin/api/groups/create", { name });
      location.href = `/admin/groups/${data.id}`;
    } catch (e) {
      toast(e.message || "创建失败", "error");
    }
  }

  async function deleteGroup(groupId) {
    if (!confirm("确认删除该抽奖组？将同时删除奖项/人员/预分配/开奖结果。")) return;
    try {
      await apiPost("/admin/api/groups/delete", { group_id: groupId });
      toast("已删除");
      await renderGroups();
    } catch (e) {
      toast(e.message || "删除失败", "error");
    }
  }

  async function renderGroupDetail(gid) {
    const g = await apiGet(`/admin/api/groups/get?group_id=${gid}`);
    el("groupMeta").textContent = `${g.name} · 状态：${g.status} · 创建时间：${fmtTs(g.created_at)}`;
    await Promise.all([renderPrizes(gid), renderParticipants(gid), renderAssignments(gid), renderResults(gid)]);
  }

  async function renderPrizes(gid) {
    const box = el("prizeTable");
    const prizes = await apiGet(`/admin/api/prizes/list?group_id=${gid}`);
    const rows = prizes
      .map(
        (p) => `
      <div class="tr" style="grid-template-columns:1fr 110px 140px;">
        <div class="td"><div style="font-weight:800">${escapeHtml(p.name)}</div><div class="muted">#${p.id}</div></div>
        <div class="td"><span class="badge">数量：${p.quantity}</span></div>
        <div class="actions">
          <button class="btn btn-danger" onclick="Admin.deletePrize(${p.id}, ${gid})">删除</button>
        </div>
      </div>`
      )
      .join("");
    box.innerHTML = prizes.length
      ? `<div class="table">${rows}</div>`
      : `<div class="muted">还没有奖项</div>`;

    // 预分配下拉
    const prizeSel = el("assignPrize");
    if (prizeSel) {
      prizeSel.innerHTML = prizes.map((p) => `<option value="${p.id}">${escapeHtml(p.name)}（数量:${p.quantity}）</option>`).join("");
    }
  }

  async function addPrize(gid) {
    const name = (el("prizeName").value || "").trim();
    const qty = parseInt(el("prizeQty").value || "0", 10);
    if (!name || !(qty > 0)) return toast("请填写奖项名称与数量", "error");
    try {
      await apiPost("/admin/api/prizes/add", { group_id: gid, name, quantity: qty });
      el("prizeName").value = "";
      el("prizeQty").value = "1";
      toast("已添加奖项");
      await renderPrizes(gid);
      await renderAssignments(gid);
    } catch (e) {
      toast(e.message || "添加失败", "error");
    }
  }

  async function deletePrize(prizeId, gid) {
    if (!confirm("确认删除该奖项？")) return;
    try {
      await apiPost("/admin/api/prizes/delete", { prize_id: prizeId });
      toast("已删除");
      await renderPrizes(gid);
      await renderAssignments(gid);
    } catch (e) {
      toast(e.message || "删除失败", "error");
    }
  }

  async function renderParticipants(gid) {
    const box = el("participantTable");
    const ps = await apiGet(`/admin/api/participants/list?group_id=${gid}`);
    const rows = ps
      .map(
        (p) => `
      <div class="tr" style="grid-template-columns:1fr 140px;">
        <div class="td">
          <div style="font-weight:800">${escapeHtml(p.name)}</div>
          <div class="muted">#${p.id}${p.code ? ` · 编号:${escapeHtml(p.code)}` : ""}${p.phone ? ` · ${escapeHtml(p.phone)}` : ""}</div>
        </div>
        <div class="actions">
          <button class="btn btn-danger" onclick="Admin.deleteParticipant(${p.id}, ${gid})">删除</button>
        </div>
      </div>`
      )
      .join("");
    box.innerHTML = ps.length ? `<div class="table">${rows}</div>` : `<div class="muted">还没有参与人员</div>`;

    const pSel = el("assignParticipant");
    if (pSel) {
      pSel.innerHTML = ps.map((p) => `<option value="${p.id}">${escapeHtml(p.name)}（#${p.id}）</option>`).join("");
    }
  }

  async function addParticipant(gid) {
    const name = (el("pName").value || "").trim();
    const phone = (el("pPhone").value || "").trim();
    const code = (el("pCode").value || "").trim();
    if (!name) return toast("请输入姓名", "error");
    try {
      await apiPost("/admin/api/participants/add", { group_id: gid, name, phone, code });
      el("pName").value = "";
      el("pPhone").value = "";
      el("pCode").value = "";
      toast("已添加参与人员");
      await renderParticipants(gid);
      await renderAssignments(gid);
    } catch (e) {
      toast(e.message || "添加失败", "error");
    }
  }

  async function deleteParticipant(participantId, gid) {
    if (!confirm("确认删除该参与人员？")) return;
    try {
      await apiPost("/admin/api/participants/delete", { participant_id: participantId });
      toast("已删除");
      await renderParticipants(gid);
      await renderAssignments(gid);
      await renderResults(gid);
    } catch (e) {
      toast(e.message || "删除失败", "error");
    }
  }

  async function renderAssignments(gid) {
    const box = el("assignmentTable");
    if (!box) return;
    const list = await apiGet(`/admin/api/assignments/list?group_id=${gid}`);
    const rows = list
      .map(
        (a) => `
      <div class="tr" style="grid-template-columns:1fr 1fr 120px;">
        <div class="td"><div style="font-weight:800">${escapeHtml(a.participant_name)}</div><div class="muted">参与者 #${a.participant_id}</div></div>
        <div class="td"><div style="font-weight:800">${escapeHtml(a.prize_name)}</div><div class="muted">奖项 #${a.prize_id}</div></div>
        <div class="actions">
          <button class="btn btn-danger" onclick="Admin.deleteAssignment(${a.id}, ${gid})">删除</button>
        </div>
      </div>`
      )
      .join("");
    box.innerHTML = list.length ? `<div class="table">${rows}</div>` : `<div class="muted">还没有预分配</div>`;
  }

  async function createAssignment(gid) {
    const participantId = parseInt(el("assignParticipant").value || "0", 10);
    const prizeId = parseInt(el("assignPrize").value || "0", 10);
    if (!(participantId > 0 && prizeId > 0)) return toast("请选择参与者和奖项", "error");
    try {
      await apiPost("/admin/api/assignments/create", { group_id: gid, participant_id: participantId, prize_id: prizeId });
      toast("预分配已保存");
      await renderAssignments(gid);
    } catch (e) {
      toast(e.message || "保存失败", "error");
    }
  }

  async function deleteAssignment(assignmentId, gid) {
    if (!confirm("确认删除该预分配？")) return;
    try {
      await apiPost("/admin/api/assignments/delete", { assignment_id: assignmentId });
      toast("已删除");
      await renderAssignments(gid);
    } catch (e) {
      toast(e.message || "删除失败", "error");
    }
  }

  async function runDraw(gid) {
    if (!confirm("确认一键开奖？开奖后会写入结果并锁定状态为 finished。")) return;
    try {
      const data = await apiPost("/admin/api/draw/run", { group_id: gid });
      toast(data.message || "开奖成功");
      await renderGroupDetail(gid);
    } catch (e) {
      toast(e.message || "开奖失败", "error");
    }
  }

  async function renderResults(gid) {
    const box = el("resultTable");
    if (!box) return;
    const list = await apiGet(`/admin/api/results/list?group_id=${gid}`);
    if (!list.length) {
      box.innerHTML = `<div class="muted">还没有开奖结果</div>`;
      return;
    }
    const rows = list
      .map(
        (r) => `
      <div class="tr" style="grid-template-columns:1fr 1fr 140px;">
        <div class="td"><div style="font-weight:800">${escapeHtml(r.prize_name)}</div><div class="muted">奖项 #${r.prize_id}</div></div>
        <div class="td"><div style="font-weight:800">${escapeHtml(r.participant_name)}</div><div class="muted">参与者 #${r.participant_id}</div></div>
        <div class="td" style="text-align:right"><span class="badge">${r.source === "assignment" ? "预分配" : "随机"} · ${fmtTs(r.drawn_at)}</span></div>
      </div>`
      )
      .join("");
    box.innerHTML = `<div class="table">${rows}</div>`;
  }

  async function renderStaff() {
    const box = el("staffTable");
    const list = await apiGet("/admin/api/staff/list");
    const rows = list
      .map(
        (s) => `
      <div class="tr" style="grid-template-columns:1fr 140px;">
        <div class="td">
          <div style="font-weight:800">${escapeHtml(s.username)}</div>
          <div class="muted">#${s.id} · ${s.is_superadmin ? "superadmin" : "admin"} · ${fmtTs(s.created_at)}</div>
        </div>
        <div class="actions">
          <button class="btn btn-danger" onclick="Admin.deleteStaff(${s.id})">删除</button>
        </div>
      </div>`
      )
      .join("");
    box.innerHTML = list.length ? `<div class="table">${rows}</div>` : `<div class="muted">暂无管理人员</div>`;
  }

  async function createStaff() {
    const username = (el("staffUsername").value || "").trim();
    const password = (el("staffPassword").value || "").trim();
    const isSuper = !!el("staffSuper").checked;
    if (!username || !password) return toast("请输入用户名与初始密码", "error");
    try {
      await apiPost("/admin/api/staff/create", { username, password, is_superadmin: isSuper });
      el("staffUsername").value = "";
      el("staffPassword").value = "";
      el("staffSuper").checked = false;
      toast("已创建");
      await renderStaff();
    } catch (e) {
      toast(e.message || "创建失败", "error");
    }
  }

  async function deleteStaff(staffId) {
    if (!confirm("确认删除该管理人员？")) return;
    try {
      await apiPost("/admin/api/staff/delete", { staff_id: staffId });
      toast("已删除");
      await renderStaff();
    } catch (e) {
      toast(e.message || "删除失败", "error");
    }
  }

  async function boot() {
    const page = window.__PAGE__ || {};
    try {
      if (page.name === "groups") await renderGroups();
      if (page.name === "group_detail") await renderGroupDetail(page.groupId);
      if (page.name === "staff") await renderStaff();
    } catch (e) {
      toast(e.message || "加载失败", "error");
    }
  }

  return {
    boot,
    // groups
    createGroup,
    deleteGroup,
    // detail
    addPrize,
    deletePrize,
    addParticipant,
    deleteParticipant,
    createAssignment,
    deleteAssignment,
    runDraw,
    // staff
    createStaff,
    deleteStaff,
  };
})();

window.Admin = Admin;
window.addEventListener("DOMContentLoaded", () => Admin.boot());

// 现场活动配置（/admin/live）
const LiveAdmin = (() => {
  let localRoundCounts = [];
  async function apiPost(path, body) {
    const res = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok || !json.ok) throw new Error((json && json.error) || "请求失败");
    return json.data;
  }

  async function apiGet(path) {
    const res = await fetch(path, { credentials: "same-origin" });
    const json = await res.json().catch(() => ({}));
    if (!res.ok || !json.ok) throw new Error((json && json.error) || "请求失败");
    return json.data;
  }

  function el(id) {
    return document.getElementById(id);
  }

  function toast(msg, type = "ok") {
    const n = document.createElement("div");
    n.className = `alert ${type === "error" ? "alert-error" : "alert-ok"}`;
    n.textContent = msg;
    const container = document.querySelector(".container") || document.body;
    container.prepend(n);
    setTimeout(() => n.remove(), 2600);
  }

  function parseRoundsCount(v) {
    const n = parseInt(String(v || "0"), 10);
    if (!Number.isFinite(n) || n <= 0) throw new Error("抽几轮必须是正整数");
    return n;
  }

  function calcAverage(attendeesCount, roundsCount) {
    const base = Math.floor(attendeesCount / roundsCount);
    const last = attendeesCount - base * (roundsCount - 1);
    return Array.from({ length: roundsCount }, (_, i) => (i === roundsCount - 1 ? last : base));
  }

  function renderRoundEditor() {
    const page = window.__PAGE__ || {};
    if (page.name !== "live_admin") return;
    const editor = el("roundCountsEditor");
    const summary = el("roundCountsSummary");
    if (!editor || !summary) return;

    const roundsCount = parseInt(el("roundsCount").value || "0", 10) || 0;
    if (roundsCount <= 0) {
      editor.innerHTML = `<div class="muted">请先填写“抽几轮（组数）”，系统会生成对应输入框。</div>`;
      summary.textContent = "";
      return;
    }

    // 确保数组长度正确
    if (!Array.isArray(localRoundCounts)) localRoundCounts = [];
    if (localRoundCounts.length !== roundsCount) {
      const next = new Array(roundsCount).fill(1);
      for (let i = 0; i < Math.min(localRoundCounts.length, roundsCount); i++) next[i] = localRoundCounts[i];
      localRoundCounts = next;
    }

    editor.innerHTML = `
      <div class="tr th" style="grid-template-columns:140px 1fr;">
        <div class="td">轮次</div>
        <div class="td">抽取人数</div>
      </div>
      ${Array.from({ length: roundsCount })
        .map(
          (_, i) => `
          <div class="tr" style="grid-template-columns:140px 1fr;">
            <div class="td"><span class="badge">第 ${i + 1} 轮</span></div>
            <div class="td">
              <input class="input" style="max-width:220px" value="${localRoundCounts[i] ?? ""}"
                oninput="LiveAdmin.updateRoundCount(${i}, this.value)" />
            </div>
          </div>`
        )
        .join("")}
    `;
    renderSummary();
  }

  function renderSummary() {
    const summary = el("roundCountsSummary");
    if (!summary) return;
    const attendeesCount = parseInt(el("attendeesCount").value || "0", 10) || 0;
    const total = (localRoundCounts || []).reduce((acc, x) => acc + (parseInt(String(x || "0"), 10) || 0), 0);
    const remain = attendeesCount - total;
    summary.textContent =
      attendeesCount > 0
        ? `合计：${total} / 到场人数：${attendeesCount}${remain === 0 ? "（✅ 可保存）" : remain > 0 ? `（还差 ${remain}）` : `（超出 ${-remain}）`}`
        : `合计：${total}`;
  }

  function updateRoundCount(idx, v) {
    const n = parseInt(String(v || "0"), 10);
    localRoundCounts[idx] = Number.isFinite(n) ? n : 0;
    renderSummary();
  }

  function renderState(s) {
    const box = el("liveStateBox");
    if (!box) return;
    if (!s.configured) {
      box.innerHTML = "未配置活动";
      // 未配置时也尝试渲染编辑器
      renderRoundEditor();
      return;
    }
    const rounds = s.round_counts || [];
    const picks = s.picks_by_round || {};
    const parts = rounds
      .map((need, i) => {
        const got = (picks[i] || []).length;
        const tag = i === s.current_round_index ? "（当前轮）" : "";
        return `第${i + 1}轮：${got}/${need}${tag}`;
      })
      .join(" · ");
    box.innerHTML = `
      <div>到场人数：<b>${s.attendees_count}</b> · 最大号码：<b>${s.pool_max}</b> · 当前轮：<b>${Math.min(
        s.current_round_index + 1,
        rounds.length
      )}</b>/${rounds.length} · 剩余可抽：<b>${s.remaining_count}</b></div>
      <div style="margin-top:6px" class="muted">${parts}</div>
    `;
    el("attendeesCount").value = String(s.attendees_count);
    el("roundsCount").value = String((s.round_counts || []).length);
    localRoundCounts = [...(s.round_counts || [])];
    renderRoundEditor();
  }

  async function load() {
    const page = window.__PAGE__ || {};
    if (page.name !== "live_admin") return;
    try {
      const s = await apiPost("/api/live/state", {});
      renderState(s);
    } catch (e) {
      toast(e.message || "加载失败", "error");
    }
  }

  function wireInputs() {
    const page = window.__PAGE__ || {};
    if (page.name !== "live_admin") return;
    const roundsEl = el("roundsCount");
    const attendeesEl = el("attendeesCount");
    if (roundsEl) {
      roundsEl.addEventListener("input", () => {
        // 当轮数变化时，重建输入框
        renderRoundEditor();
      });
    }
    if (attendeesEl) {
      attendeesEl.addEventListener("input", () => renderSummary());
    }
  }

  async function save() {
    try {
      const attendeesCount = parseInt(el("attendeesCount").value || "0", 10);
      if (!(attendeesCount > 0)) return toast("到场人数必须大于0", "error");
      let roundsCount;
      try {
        roundsCount = parseRoundsCount(el("roundsCount").value);
      } catch (e) {
        return toast(e.message || "参数错误", "error");
      }
      // 校验每轮配置
      if (!Array.isArray(localRoundCounts) || localRoundCounts.length !== roundsCount) {
        return toast("请先配置每轮抽取人数", "error");
      }
      const counts = localRoundCounts.map((x) => parseInt(String(x || "0"), 10) || 0);
      if (counts.some((x) => x <= 0)) return toast("每轮抽取人数必须都大于0", "error");
      const total = counts.reduce((a, b) => a + b, 0);
      if (total !== attendeesCount) {
        const diff = attendeesCount - total;
        if (diff > 0) return toast(`人数少了：还差 ${diff} 人（无法保存）`, "error");
        return toast(`人数多了：超出 ${-diff} 人（无法保存）`, "error");
      }
      await apiPost("/api/live/config", { attendees_count: attendeesCount, rounds_count: roundsCount, round_counts: counts });
      toast("已保存");
      await load();
    } catch (e) {
      toast(e.message || "保存失败", "error");
    }
  }

  function fillAverage() {
    const attendeesCount = parseInt(el("attendeesCount").value || "0", 10);
    const roundsCount = parseInt(el("roundsCount").value || "0", 10);
    if (!(attendeesCount > 0 && roundsCount > 0)) return toast("请先填写到场人数与轮数", "error");
    localRoundCounts = calcAverage(attendeesCount, roundsCount);
    renderRoundEditor();
  }

  async function reset() {
    if (!confirm("确认清空抽取结果并回到第1轮？")) return;
    try {
      await apiPost("/api/live/reset", {});
      toast("已重置");
      await load();
    } catch (e) {
      toast(e.message || "重置失败", "error");
    }
  }

  return { load, save, reset, fillAverage, updateRoundCount, wireInputs };
})();

window.LiveAdmin = LiveAdmin;
window.addEventListener("DOMContentLoaded", () => {
  LiveAdmin.load();
  LiveAdmin.wireInputs();
});


