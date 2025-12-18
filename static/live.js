const Live = (() => {
  let state = null;
  let rollingTimer = null;

  async function apiPost(path, body) {
    const res = await fetch(path, {
      method: "POST",
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

  function toast(msg, type = "ok") {
    const t = document.createElement("div");
    t.className = `toast ${type === "error" ? "error" : "ok"}`;
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 2600);
  }

  function parseCounts(text, roundsCount) {
    const parts = String(text || "")
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean);
    const nums = parts.map((x) => parseInt(x, 10));
    if (!nums.length) throw new Error("请填写每轮抽几人，例如：1,1,1,2,5");
    if (nums.some((x) => !Number.isFinite(x) || x <= 0)) throw new Error("每轮抽取人数必须是正整数");
    if (roundsCount && nums.length !== roundsCount) throw new Error("每轮抽几人的数量必须等于轮数");
    return nums;
  }

  function stopRolling() {
    if (rollingTimer) {
      clearInterval(rollingTimer);
      rollingTimer = null;
    }
  }

  function startRolling(candidates) {
    stopRolling();
    const rollNumber = el("rollNumber");
    if (!candidates || !candidates.length) {
      rollNumber.textContent = "—";
      return;
    }
    let i = 0;
    rollingTimer = setInterval(() => {
      // 简单滚动：从候选池循环展示
      rollNumber.textContent = String(candidates[i % candidates.length]);
      i++;
    }, 55);
  }

  function genPool(attendeesCount) {
    // 与后端一致：跳过任何包含“4”的号码，直到凑够 attendeesCount 个
    const out = [];
    let x = 1;
    while (out.length < attendeesCount) {
      if (!String(x).includes("4")) out.push(x);
      x++;
    }
    return out;
  }

  function renderBoard() {
    const board = el("roundBoard");
    const { round_counts, current_round_index, picks_by_round } = state;
    board.innerHTML = "";
    for (let i = 0; i < round_counts.length; i++) {
      const need = round_counts[i];
      const picked = (picks_by_round && picks_by_round[i]) || [];
      const active = i === current_round_index;
      const done = picked.length >= need;
      const card = document.createElement("div");
      card.className = `round-card${active ? " active" : ""}`;
      card.innerHTML = `
        <div class="round-title">
          <div>第 ${i + 1} 轮</div>
          <span class="badge">${done ? "已完成" : active ? "进行中" : "未开始"} · ${picked.length}/${need}</span>
        </div>
        <div class="slots">
          ${Array.from({ length: need })
            .map((_, k) => {
              const v = picked[k];
              return v
                ? `<div class="slot">${v}</div>`
                : `<div class="slot empty">—</div>`;
            })
            .join("")}
        </div>
      `;
      board.appendChild(card);
    }
  }

  function renderMeta() {
    const title = el("liveTitle");
    const meta = el("liveMeta");
    const btn = el("drawBtn");
    const label = el("rollLabel");

    const { attendees_count, round_counts, current_round_index, remaining_count, pool_max } = state;
    meta.textContent = `到场人数：${attendees_count} · 最大号码：${pool_max || "-"} · 轮数：${round_counts.length} · 剩余可抽：${remaining_count}`;

    if (current_round_index >= round_counts.length) {
      title.textContent = "已抽完所有轮次";
      btn.disabled = true;
      btn.textContent = "已完成";
      label.textContent = "活动完成";
      stopRolling();
      return;
    }

    title.textContent = `准备第 ${current_round_index + 1} 轮`;
    btn.disabled = false;
    btn.textContent = "开始本轮抽取";
    label.textContent = `第 ${current_round_index + 1} 轮：将抽 ${round_counts[current_round_index]} 人`;
  }

  function showDrawUI() {
    const need = el("needConfigCard");
    if (need) need.style.display = "none";
    el("drawCard").style.display = "block";
  }

  function showNeedConfigUI() {
    const need = el("needConfigCard");
    if (need) need.style.display = "block";
    el("drawCard").style.display = "none";
  }

  async function loadState() {
    try {
      state = await apiPost("/api/live/state", {});
      if (!state.configured) {
        showNeedConfigUI();
        return;
      }
      showDrawUI();
      renderBoard();
      renderMeta();
      // 这里不直接滚动：等点击按钮再滚动
    } catch (e) {
      toast(e.message || "加载失败", "error");
    }
  }

  async function resetAll() {
    if (!confirm("确认重置？将清空抽取结果并回到第1轮。")) return;
    try {
      await apiPost("/api/live/reset", {});
      toast("已重置");
      await loadState();
    } catch (e) {
      toast(e.message || "重置失败", "error");
    }
  }

  async function drawNext() {
    if (!state || !state.configured) return toast("请先配置活动", "error");
    const btn = el("drawBtn");
    if (btn.disabled) return;
    btn.disabled = true;

    // 先开始滚动（候选池按“到场人数”生成，保证范围足够大）
    // 最终结果仍以服务端返回为准（避免并发/刷新导致不一致）
    const pool = genPool(state.attendees_count);
    const used = new Set();
    const pbr = state.picks_by_round || {};
    Object.keys(pbr).forEach((k) => (pbr[k] || []).forEach((v) => used.add(v)));
    const visual = pool.filter((v) => !used.has(v));
    startRolling(visual.length ? visual : pool);

    let result;
    try {
      result = await apiPost("/api/live/draw", {});
    } catch (e) {
      stopRolling();
      btn.disabled = false;
      return toast(e.message || "抽取失败", "error");
    }

    const { round_index, picked } = result;
    const label = el("rollLabel");
    label.textContent = `第 ${round_index + 1} 轮抽取中...`;

    // 逐个停下并填回占位
    const revealOne = async (idx) => {
      if (idx >= picked.length) return;
      // 滚动一小段时间后“停”到一个号码
      await new Promise((r) => setTimeout(r, 650));
      stopRolling();
      el("rollNumber").textContent = String(picked[idx]);
      // 写入本地 state（用于即时渲染）
      state.picks_by_round = state.picks_by_round || {};
      state.picks_by_round[round_index] = state.picks_by_round[round_index] || [];
      state.picks_by_round[round_index].push(picked[idx]);
      state.remaining_count = Math.max(0, (state.remaining_count || 0) - 1);
      renderBoard();
      renderMeta();
      // 停顿展示这个号码一会儿，再开始下一个（更符合现场“停一下”的感觉）
      await new Promise((r) => setTimeout(r, 900));
      // 继续下一个人：重新滚动
      if (idx < picked.length - 1) startRolling(visual);
      await revealOne(idx + 1);
    };

    await revealOne(0);

    // 本轮完成后刷新一次真实 state（防止并发/刷新造成偏差）
    await loadState();
    btn.disabled = false;
  }

  function boot() {
    loadState();
  }

  return { boot, loadState, resetAll, drawNext };
})();

window.Live = Live;
window.addEventListener("DOMContentLoaded", () => Live.boot());


