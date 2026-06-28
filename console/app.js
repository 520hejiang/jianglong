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

function showNewBook() { document.getElementById("newBookDlg").showModal(); }
async function createBook() {
  const body = {
    title: v("nb_title"), start_chapter: +v("nb_start") || 1, target_chapters: +v("nb_target") || 800,
    master_outline: v("nb_master"), core_settings: v("nb_settings"),
    power_system: v("nb_power"), volume_outline: v("nb_vol") || "[]",
  };
  await call("/api/books", { method: "POST", body: JSON.stringify(body) });
  document.getElementById("newBookDlg").close();
  loadBooks();
}

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
