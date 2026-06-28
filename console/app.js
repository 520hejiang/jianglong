// ============================================================================
// 控制台前端逻辑（纯原生 JS，零依赖，便于 Pages 静态托管）
// ============================================================================
let API = localStorage.getItem("apiBase") || "";
let TOKEN = localStorage.getItem("token") || "";
let curChapter = null; // { bookId, chapter_no }

document.getElementById("apiBase").value = API;
document.getElementById("token").value = TOKEN;

function saveConn() {
  API = document.getElementById("apiBase").value.trim().replace(/\/$/, "");
  TOKEN = document.getElementById("token").value.trim();
  localStorage.setItem("apiBase", API);
  localStorage.setItem("token", TOKEN);
  loadBooks(); fillBookSelectors();
}

async function call(path, opts = {}) {
  const res = await fetch(API + path, {
    ...opts,
    headers: { Authorization: "Bearer " + TOKEN, "Content-Type": "application/json", ...(opts.headers || {}) },
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || res.status);
  return res.json();
}

// ---- Tabs ----
document.querySelectorAll("nav button").forEach((b) =>
  b.addEventListener("click", () => {
    document.querySelectorAll("nav button").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    document.getElementById("tab-" + b.dataset.tab).classList.add("active");
  })
);

// ---- 书架 ----
async function loadBooks() {
  if (!API) return;
  const books = await call("/api/books");
  const el = document.getElementById("bookList");
  el.innerHTML = books.map((b) => `
    <div class="card">
      <div><b>${esc(b.title)}</b> <span class="badge ${b.status}">${b.status}</span></div>
      <div class="meta">进度：第 ${b.next_chapter - 1}/${b.target_chapters || "?"} 章 · 约 ${(b.total_chars/10000).toFixed(1)} 万字 · 第 ${b.cursor_volume} 卷</div>
      ${b.last_error ? `<div class="log-error meta">⚠ ${esc(b.last_error)}</div>` : ""}
      <div class="row" style="margin-top:8px">
        <button onclick="startBook('${b.id}')">▶ 开始</button>
        <button onclick="stopBook('${b.id}')">⏸ 暂停</button>
        <button onclick="genOne('${b.id}')">⚡ 立即生成一章</button>
        <code class="meta">${b.id}</code>
      </div>
    </div>`).join("") || "<p class='hint'>暂无书，点击「新建书」。</p>";
  fillBookSelectors(books);
}
async function startBook(id) { await call(`/api/books/${id}/start`, { method: "POST" }); loadBooks(); }
async function stopBook(id) { await call(`/api/books/${id}/stop`, { method: "POST" }); loadBooks(); }
async function genOne(id) { await call(`/api/books/${id}/generate`, { method: "POST", body: "{}" }); alert("已入队，约1-2分钟后出章"); }

// ======================= 新书向导 =======================
const WIZ_STEPS = ["基础·文风", "总纲·设定", "境界体系", "分卷大纲", "核心人物", "确认创建"];
const FANREN_RANKS = [
  { name: "炼气", subLayers: 13 }, { name: "筑基", subLayers: 12 }, { name: "结丹", subLayers: 9 },
  { name: "元婴", subLayers: 9 }, { name: "化神", subLayers: 9 }, { name: "炼虚", subLayers: 9 },
  { name: "合体", subLayers: 9 }, { name: "大乘", subLayers: 9 }, { name: "渡劫", subLayers: 9 },
];
let wiz = { step: 0, ranks: [], vols: [], chars: [] };

function openWizard() {
  if (!API || !TOKEN) return alert("请先在右上角连接 API");
  wiz = { step: 0, ranks: JSON.parse(JSON.stringify(FANREN_RANKS)), vols: [], chars: [] };
  ["w_title","w_master","w_settings","w_style","w_import"].forEach((id)=>{ const e=document.getElementById(id); if(e) e.value=""; });
  document.getElementById("w_start").value = 1;
  document.getElementById("w_target").value = 800;
  document.getElementById("w_stylePreset").value = "fanren";
  onStylePreset();
  renderRanks(); renderVols(); renderChars(); renderSteps();
  showStep(0);
  document.getElementById("wizard").showModal();
}

function renderSteps() {
  document.getElementById("wizSteps").innerHTML = WIZ_STEPS.map((s, i) =>
    `<span class="wiz-pill ${i === wiz.step ? "on" : ""}">${i + 1}.${s}</span>`).join("");
}
function showStep(n) {
  wiz.step = n;
  document.querySelectorAll(".wiz-step").forEach((el) => (el.hidden = +el.dataset.step !== n));
  document.getElementById("wizPrev").style.visibility = n === 0 ? "hidden" : "visible";
  const last = n === WIZ_STEPS.length - 1;
  document.getElementById("wizNext").style.display = last ? "none" : "";
  document.getElementById("wizDone").style.display = last ? "" : "none";
  if (last) document.getElementById("w_preview").textContent = JSON.stringify(buildPayload().book, null, 2);
  renderSteps();
}
function wizGo(dir) {
  const n = wiz.step + dir;
  if (n < 0 || n >= WIZ_STEPS.length) return;
  showStep(n);
}
function onStylePreset() {
  document.getElementById("w_style").disabled = document.getElementById("w_stylePreset").value !== "custom";
}

// --- 境界体系 ---
function renderRanks() {
  document.getElementById("w_ranks").innerHTML = wiz.ranks.map((r, i) => `
    <div class="row">
      <span class="hint">序${i}</span>
      <input value="${esc(r.name)}" onchange="wiz.ranks[${i}].name=this.value" placeholder="境界名" style="width:120px">
      <input type="number" value="${r.subLayers}" onchange="wiz.ranks[${i}].subLayers=+this.value" style="width:70px" title="小层数">
      <button onclick="wiz.ranks.splice(${i},1);renderRanks()">✕</button>
    </div>`).join("");
}
function addRank() { wiz.ranks.push({ name: "", subLayers: 9 }); renderRanks(); }

// --- 分卷 ---
function renderVols() {
  document.getElementById("w_vols").innerHTML = wiz.vols.map((v, i) => `
    <div class="card">
      <div class="row">
        <input value="${esc(v.title)}" onchange="wiz.vols[${i}].title=this.value" placeholder="卷名" style="flex:2">
        <input type="number" value="${v.start_ch}" onchange="wiz.vols[${i}].start_ch=+this.value" placeholder="起" style="width:70px">
        <input type="number" value="${v.end_ch}" onchange="wiz.vols[${i}].end_ch=+this.value" placeholder="止" style="width:70px">
        <button onclick="wiz.vols.splice(${i},1);renderVols()">✕</button>
      </div>
      <textarea rows="2" placeholder="本卷简介" onchange="wiz.vols[${i}].summary=this.value">${esc(v.summary)}</textarea>
      <textarea rows="2" placeholder="关键事件，每行一个" onchange="wiz.vols[${i}].key_events=this.value.split('\\n').map(s=>s.trim()).filter(Boolean)">${esc((v.key_events||[]).join("\n"))}</textarea>
    </div>`).join("");
}
function addVol() {
  const last = wiz.vols[wiz.vols.length - 1];
  const start = last ? last.end_ch + 1 : (+v("w_start") || 1);
  wiz.vols.push({ vol: wiz.vols.length + 1, title: "", start_ch: start, end_ch: start + 59, summary: "", key_events: [] });
  renderVols();
}

// --- 角色 ---
function renderChars() {
  document.getElementById("w_chars").innerHTML = wiz.chars.map((c, i) => `
    <div class="card">
      <div class="row">
        <input value="${esc(c.name)}" onchange="wiz.chars[${i}].name=this.value" placeholder="角色名" style="width:130px">
        <select onchange="wiz.chars[${i}].role=this.value">
          ${["protagonist","ally","enemy","npc"].map((r)=>`<option ${c.role===r?"selected":""}>${r}</option>`).join("")}
        </select>
        <input value="${esc(c.realm_name||"")}" onchange="wiz.chars[${i}].realm_name=this.value;syncRealmIdx(${i})" placeholder="境界名" style="width:90px">
        <input type="number" value="${c.realm_sub||0}" onchange="wiz.chars[${i}].realm_sub=+this.value" placeholder="层" style="width:55px">
        <button onclick="wiz.chars.splice(${i},1);renderChars()">✕</button>
      </div>
      <input value="${esc((c.artifacts||[]).map(a=>a.name).join(', '))}" placeholder="法宝(逗号分隔)"
        onchange="wiz.chars[${i}].artifacts=this.value.split(',').map(s=>s.trim()).filter(Boolean).map(n=>({name:n,grade:'未定',durability:100}))" style="width:100%">
      <input value="${esc(c.status_notes||"")}" onchange="wiz.chars[${i}].status_notes=this.value" placeholder="人设/近况" style="width:100%;margin-top:6px">
    </div>`).join("");
}
function addChar() { wiz.chars.push({ name: "", role: "npc", realm_name: "", realm_sub: 0, alive: true, artifacts: [], techniques: [], relations: [], aliases: [], status_notes: "" }); renderChars(); }
function syncRealmIdx(i) {
  const idx = wiz.ranks.findIndex((r) => r.name === wiz.chars[i].realm_name);
  wiz.chars[i].realm_index = idx >= 0 ? idx : 0;
}

// --- 导入解析脚本 JSON ---
function importParsed() {
  const box = document.getElementById("w_import");
  box.style.display = "block";
  const raw = box.value.trim();
  if (!raw) return alert("把 parse_outline.py 输出的 JSON 粘进文本框再点一次");
  let d;
  try { d = JSON.parse(raw); } catch (e) { return alert("JSON 解析失败：" + e); }
  if (d.title) document.getElementById("w_title").value = d.title;
  if (d.start_chapter) document.getElementById("w_start").value = d.start_chapter;
  if (d.target_chapters) document.getElementById("w_target").value = d.target_chapters;
  document.getElementById("w_master").value = d.master_outline || "";
  document.getElementById("w_settings").value = d.core_settings || "";
  try { wiz.ranks = JSON.parse(d.power_system).map((r)=>({name:r.name,subLayers:r.subLayers})); } catch {}
  try { wiz.vols = JSON.parse(d.volume_outline); } catch {}
  wiz.chars = d.characters || [];
  renderRanks(); renderVols(); renderChars();
  alert("已导入，请逐步检查后创建");
}

function buildPayload() {
  const ranks = wiz.ranks.filter((r)=>r.name).map((r, i)=>({ index: i, name: r.name, subLayers: r.subLayers }));
  const vols = wiz.vols.map((v, i)=>({ ...v, vol: i + 1 }));
  const preset = document.getElementById("w_stylePreset").value;
  const style = preset === "custom" ? v("w_style") : "";
  const book = {
    title: v("w_title") || "未命名",
    start_chapter: +v("w_start") || 1,
    target_chapters: +v("w_target") || 800,
    master_outline: v("w_master"),
    core_settings: v("w_settings"),
    power_system: JSON.stringify(ranks),
    volume_outline: JSON.stringify(vols),
    style_prompt_override: style,
  };
  return { book, chars: wiz.chars.filter((c)=>c.name) };
}

async function wizCreate() {
  const { book, chars } = buildPayload();
  if (!book.title) return alert("请填书名");
  try {
    const res = await call("/api/books", { method: "POST", body: JSON.stringify(book) });
    // style_prompt_override 通过 PUT 写入（POST 建书未含该字段）
    if (book.style_prompt_override) {
      await call(`/api/books/${res.id}`, { method: "PUT", body: JSON.stringify({ style_prompt_override: book.style_prompt_override }) });
    }
    if (chars.length) {
      chars.forEach(syncRealmIdxAll);
      await call(`/api/books/${res.id}/characters`, { method: "POST", body: JSON.stringify({ characters: chars }) });
    }
    document.getElementById("wizard").close();
    alert(`✅ 已创建《${book.title}》。到书架点「开始」即可全自动生成。`);
    loadBooks();
  } catch (e) { alert("创建失败：" + e); }
}
function syncRealmIdxAll(c) {
  const idx = WIZ_RANKS_INDEX(c.realm_name);
  c.realm_index = idx >= 0 ? idx : (c.realm_index || 0);
}
function WIZ_RANKS_INDEX(name) { return wiz.ranks.findIndex((r) => r.name === name); }

// ---- 章节 ----
async function loadChapters() {
  const id = document.getElementById("chBook").value; if (!id) return;
  const chaps = await call(`/api/books/${id}/chapters`);
  document.getElementById("chapterList").innerHTML = chaps.map((c) =>
    `<div class="item" onclick="openChapter('${id}',${c.chapter_no})">第${c.chapter_no}章 ${esc(c.title||"")} <span class="hint">(${c.word_count}字)</span></div>`
  ).join("") || "<p class='hint'>还没有已完成章节</p>";
}
async function openChapter(bookId, no) {
  const c = await call(`/api/books/${bookId}/chapters/${no}`);
  curChapter = { bookId, chapter_no: no };
  document.getElementById("chapterText").textContent = `第${c.chapter_no}章 ${c.title}\n\n${c.content}`;
}
function copyChapter() {
  const t = document.getElementById("chapterText").textContent;
  navigator.clipboard.writeText(t).then(() => {
    const b = document.getElementById("copyBtn"); b.textContent = "✅ 已复制";
    setTimeout(() => (b.textContent = "📋 一键复制本章"), 1500);
  });
}
async function rewriteCurrent() {
  if (!curChapter) return alert("先打开一章");
  if (!confirm(`重写第${curChapter.chapter_no}章？将生成新版本。`)) return;
  await call(`/api/books/${curChapter.bookId}/generate`, { method: "POST", body: JSON.stringify({ chapter: curChapter.chapter_no, rewrite: true }) });
  alert("已入队重写");
}

// ---- 记忆库 ----
async function loadMemory() {
  const id = document.getElementById("memBook").value; if (!id) return;
  const [chars, fores, plot] = await Promise.all([
    call(`/api/books/${id}/characters`), call(`/api/books/${id}/foreshadowing`), call(`/api/books/${id}/plot`),
  ]);
  document.getElementById("charList").innerHTML = `<table>
    <tr><th>名</th><th>身份</th><th>存活</th><th>境界序</th><th>境界名</th><th>层</th><th>近况</th><th></th></tr>
    ${chars.map((c) => `<tr>
      <td>${esc(c.name)}</td><td>${c.role}</td>
      <td><input type="checkbox" ${c.alive?"checked":""} id="al_${c.id}"></td>
      <td><input style="width:50px" id="ri_${c.id}" value="${c.realm_index}"></td>
      <td><input style="width:70px" id="rn_${c.id}" value="${esc(c.realm_name||"")}"></td>
      <td><input style="width:45px" id="rs_${c.id}" value="${c.realm_sub||0}"></td>
      <td><input style="width:200px" id="sn_${c.id}" value="${esc(c.status_notes||"")}"></td>
      <td><button onclick="saveChar('${c.id}')">存</button></td>
    </tr>`).join("")}
  </table>`;
  document.getElementById("foreList").innerHTML = `<table>
    <tr><th>状态</th><th>重要</th><th>埋/建议回收</th><th>标题</th></tr>
    ${fores.map((f)=>`<tr><td>${f.status}</td><td>${f.importance}</td><td>${f.planted_ch}/${f.due_ch}</td><td>${esc(f.title)}</td></tr>`).join("")}
  </table>`;
  document.getElementById("plotView").textContent = plot.map((p)=>`${p.key}: ${p.value}`).join("\n");
}
async function saveChar(cid) {
  const body = {
    alive: document.getElementById("al_"+cid).checked,
    realm_index: +document.getElementById("ri_"+cid).value,
    realm_name: document.getElementById("rn_"+cid).value,
    realm_sub: +document.getElementById("rs_"+cid).value,
    status_notes: document.getElementById("sn_"+cid).value,
  };
  await call(`/api/characters/${cid}`, { method: "PUT", body: JSON.stringify(body) });
  alert("已保存");
}

// ---- Prompt ----
async function savePrompt() {
  const body = { scope: v("pr_scope"), book_id: v("pr_book") || null, name: v("pr_name"), template: v("pr_tpl") };
  await call("/api/prompts", { method: "POST", body: JSON.stringify(body) });
  alert("已保存覆盖"); loadPrompts();
}
async function loadPrompts() {
  if (!API) return;
  const list = await call("/api/prompts");
  document.getElementById("promptList").innerHTML = list.map((p)=>
    `<div class="card"><b>${p.id}</b><div class="meta">${esc((p.template||"").slice(0,120))}...</div></div>`).join("");
}

// ---- 日志 ----
async function loadLogs() {
  const id = document.getElementById("logBook").value; if (!id) return;
  const logs = await call(`/api/books/${id}/logs`);
  document.getElementById("logList").innerHTML = logs.map((l)=>
    `<div class="card log-${l.level}"><span class="meta">${new Date(l.created_at).toLocaleString()} · ${l.stage} · 第${l.chapter_no||"-"}章</span><div>${esc(l.message)}</div></div>`).join("");
}

// ---- helpers ----
function v(id){ return document.getElementById(id).value.trim(); }
function esc(s){ return String(s??"").replace(/[&<>]/g, (c)=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c])); }
function fillBookSelectors(books){
  if(!books){ return; }
  const opts = books.map((b)=>`<option value="${b.id}">${esc(b.title)}</option>`).join("");
  ["chBook","memBook","logBook"].forEach((id)=>{ const el=document.getElementById(id); if(el) el.innerHTML=opts; });
}

if (API && TOKEN) { loadBooks(); loadPrompts(); }
