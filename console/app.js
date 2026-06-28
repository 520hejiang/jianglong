// ============================================================================
// 控制台前端逻辑（纯原生 JS，零依赖，便于 Pages 静态托管）
// ============================================================================
let API = localStorage.getItem("apiBase") || "";
let TOKEN = localStorage.getItem("token") || "";
let curChapter = null; // { bookId, chapter_no }

document.getElementById("apiBase").value = API;
document.getElementById("token").value = TOKEN;

async function saveConn() {
  API = document.getElementById("apiBase").value.trim().replace(/\/$/, "");
  TOKEN = document.getElementById("token").value.trim();
  localStorage.setItem("apiBase", API);
  localStorage.setItem("token", TOKEN);
  if (!API || !TOKEN) { alert("请先填写「后台网址」和「ADMIN_TOKEN」两个框"); return; }
  // 先做健康检查 + 鉴权测试，把真实问题暴露出来（而不是"毫无反应"）
  try {
    const h = await fetch(API + "/health").then((r) => r.json());
    // 只看真正的状态字段(值以 FAIL 开头)；排除"提示"等帮助文本(其文案里也含 FAIL 字样)
    const bad = Object.entries(h).filter(([k, v]) => k !== "提示" && String(v).startsWith("FAIL"));
    if (bad.length) { alert("后台自检发现问题，请按教程补齐：\n" + bad.map(([k, v]) => `· ${k}: ${v}`).join("\n")); return; }
  } catch (e) {
    alert("连不上后台！请检查「后台网址」是否填对(应以 .workers.dev 结尾，不要带斜杠)。\n\n技术细节：" + e); return;
  }
  try {
    const books = await call("/api/books");
    await loadBooks();
    alert(`✅ 连接成功！当前有 ${books.length} 本书。` + (books.length ? "" : "\n还没有书——可在书架点「🧙 新书向导」导入大纲。"));
  } catch (e) {
    alert("后台正常，但鉴权/读取失败：\n" + e + "\n\n多半是「ADMIN_TOKEN」填错了，要和你在 Cloudflare 设的一致。");
  }
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
        <button class="danger" onclick="resetBook('${b.id}')">🔧 重置生成</button>
        <code class="meta">${b.id}</code>
      </div>
    </div>`).join("") || "<p class='hint'>暂无书，点击「新建书」。</p>";
  fillBookSelectors(books);
}
async function startBook(id) { await call(`/api/books/${id}/start`, { method: "POST" }); loadBooks(); }
async function stopBook(id) { await call(`/api/books/${id}/stop`, { method: "POST" }); loadBooks(); }
async function genOne(id) { await call(`/api/books/${id}/generate`, { method: "POST", body: "{}" }); alert("已开始，约1-2分钟后出章"); }
async function resetBook(id) {
  if (!confirm("重置生成？会清掉卡住的生成/重写进度与锁，然后从下一章继续。已写好的章节不受影响。")) return;
  try { await call(`/api/books/${id}/reset`, { method: "POST" }); alert("已重置，约1-2分钟后会重新开始生成"); loadBooks(); }
  catch (e) { alert("重置失败：" + e); }
}

// 一键导入完整大纲 JSON（手机首选：含文风/位面/角色，无需电脑跑脚本）
function openImport() {
  if (!API || !TOKEN) return alert("请先在右上角填后台网址 + ADMIN_TOKEN 并点「连接」");
  document.getElementById("importDlg").showModal();
}
async function doImport() {
  let d;
  try { d = JSON.parse(document.getElementById("imp_json").value); }
  catch (e) { return alert("JSON 格式不对，请确认整段复制完整：\n" + e); }
  try {
    const chars = d.characters || [];
    const body = { ...d }; delete body.characters;
    const res = await call("/api/books", { method: "POST", body: JSON.stringify(body) });
    if (chars.length) await call(`/api/books/${res.id}/characters`, { method: "POST", body: JSON.stringify({ characters: chars }) });
    document.getElementById("importDlg").close();
    alert(`✅ 已创建《${d.title || "未命名"}》并导入 ${chars.length} 个角色。\n去书架点「▶ 开始」即可自动写。`);
    loadBooks();
  } catch (e) { alert("导入失败：" + e); }
}

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
  // content 已自带规范标题行，直接展示，避免标题重复
  document.getElementById("chapterText").textContent = c.content;
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
  if (!confirm(`重写第${curChapter.chapter_no}章？将用新文风覆盖本章正文（不新增、不改剧情）。`)) return;
  await call(`/api/books/${curChapter.bookId}/generate`, { method: "POST", body: JSON.stringify({ chapter: curChapter.chapter_no, rewrite: true }) });
  alert("已开始重写，约几分钟后刷新本章即可看到覆盖后的新版");
}
async function deleteCurrent() {
  if (!curChapter) return alert("先打开一章");
  if (!confirm("确定要删除这一章吗？此操作不可恢复。")) return;
  try {
    await call(`/api/books/${curChapter.bookId}/chapters/${curChapter.chapter_no}`, { method: "DELETE" });
    const bid = curChapter.bookId;
    curChapter = null;
    document.getElementById("chapterText").textContent = ""; // 清空阅读区
    await loadChapters();                                    // 刷新左侧列表
    alert("已删除");
  } catch (e) { alert("删除失败：" + e); }
}

// ---- 记忆库 ----
const _assetCache = {}; // cid -> assets 对象，供 saveChar 合并灵石用
function pj(s, fb) { try { return typeof s === "string" ? JSON.parse(s) : (s ?? fb); } catch { return fb; } }
function fmtAssets(a) {
  const pills = (a.pills||[]).map(x=>`${x.name}×${x.count}`).join("、");
  const mats = (a.materials||[]).map(x=>`${x.name}×${x.count}`).join("、");
  return [pills && "丹:"+pills, mats && "材:"+mats].filter(Boolean).join(" ｜ ") || "—";
}
async function loadMemory() {
  const id = document.getElementById("memBook").value; if (!id) return;
  const [book, chars, fores, plot] = await Promise.all([
    call(`/api/books/${id}`), call(`/api/books/${id}/characters`),
    call(`/api/books/${id}/foreshadowing`), call(`/api/books/${id}/plot`),
  ]);
  // 位面横幅
  const planes = pj(book.planes, []);
  document.getElementById("planeBanner").innerHTML = planes.length
    ? `当前位面：<b>${esc(book.current_plane||planes[0].name)}</b>　｜　位面表：${planes.map(p=>`${esc(p.name)}(序${p.min_realm}-${p.max_realm})`).join("、")}`
    : "（本书未设位面）";

  document.getElementById("charList").innerHTML = `<table>
    <tr><th>名</th><th>身份</th><th>存活</th><th>境界序</th><th>境界名</th><th>层</th><th>灵石</th><th>身法/神通</th><th>法宝</th><th>家底</th><th>近况</th><th></th></tr>
    ${chars.map((c) => {
      const assets = pj(c.assets, {spirit_stones:0,pills:[],materials:[],misc:[]});
      _assetCache[c.id] = assets;
      const moves = pj(c.movement_arts, []).map(m=>`${m.name}[${m.kind||"?"}]`).join("、") || "—";
      const arts = pj(c.artifacts, []).map(a=>`${a.name}(耐久${a.durability??"?"})`).join("、") || "—";
      return `<tr>
      <td>${esc(c.name)}</td><td>${c.role}</td>
      <td><input type="checkbox" ${c.alive?"checked":""} id="al_${c.id}"></td>
      <td><input style="width:46px" id="ri_${c.id}" value="${c.realm_index}"></td>
      <td><input style="width:64px" id="rn_${c.id}" value="${esc(c.realm_name||"")}"></td>
      <td><input style="width:40px" id="rs_${c.id}" value="${c.realm_sub||0}"></td>
      <td><input style="width:80px" id="ss_${c.id}" value="${assets.spirit_stones||0}"></td>
      <td class="hint" title="${esc(moves)}">${esc(moves.slice(0,28))}</td>
      <td class="hint" title="${esc(arts)}">${esc(arts.slice(0,28))}</td>
      <td class="hint" title="${esc(fmtAssets(assets))}">${esc(fmtAssets(assets).slice(0,28))}</td>
      <td><input style="width:160px" id="sn_${c.id}" value="${esc(c.status_notes||"")}"></td>
      <td><button onclick="saveChar('${c.id}')">存</button></td>
    </tr>`;}).join("")}
  </table>`;
  document.getElementById("foreList").innerHTML = `<table>
    <tr><th>状态</th><th>重要</th><th>埋/建议回收</th><th>标题</th></tr>
    ${fores.map((f)=>`<tr><td>${f.status}</td><td>${f.importance}</td><td>${f.planted_ch}/${f.due_ch}</td><td>${esc(f.title)}</td></tr>`).join("")}
  </table>`;
  document.getElementById("plotView").textContent = plot.map((p)=>`${p.key}: ${p.value}`).join("\n");
}
async function saveChar(cid) {
  const assets = _assetCache[cid] || {spirit_stones:0,pills:[],materials:[],misc:[]};
  assets.spirit_stones = +document.getElementById("ss_"+cid).value || 0; // 手动修正灵石，保留丹药/材料
  const body = {
    alive: document.getElementById("al_"+cid).checked,
    realm_index: +document.getElementById("ri_"+cid).value,
    realm_name: document.getElementById("rn_"+cid).value,
    realm_sub: +document.getElementById("rs_"+cid).value,
    status_notes: document.getElementById("sn_"+cid).value,
    assets,
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
