// ============================================================================
// 记忆库读写层（D1 + KV）
//   - 角色 / 剧情 / 伏笔 / 章节 的存取
//   - 不用 Vectorize：用 tags 关键词匹配做"相关历史检索"
//   - 上下文编译：把当前世界状态压成一段紧凑文本喂给 LLM
// ============================================================================
import type {
  Env, Book, CharacterState, Foreshadow, StateDelta, Volume, Assets,
} from "./types";
import { emptyAssets } from "./types";

const now = () => Date.now();
const uid = () => crypto.randomUUID();

// ---------------- Book ----------------
export async function getBook(env: Env, id: string): Promise<Book | null> {
  return env.DB.prepare("SELECT * FROM books WHERE id=?").bind(id).first<Book>();
}

export async function listRunningBooks(env: Env): Promise<Book[]> {
  const r = await env.DB.prepare("SELECT * FROM books WHERE status='running'").all<Book>();
  return r.results ?? [];
}

export async function setBookStatus(env: Env, id: string, status: Book["status"], err?: string) {
  await env.DB.prepare("UPDATE books SET status=?, last_error=?, updated_at=? WHERE id=?")
    .bind(status, err ?? null, now(), id).run();
}

export function volumeForChapter(book: Book, ch: number): Volume | null {
  if (!book.volume_outline) return null;
  const vols: Volume[] = JSON.parse(book.volume_outline);
  return vols.find((v) => ch >= v.start_ch && ch <= v.end_ch) ?? vols[vols.length - 1] ?? null;
}

// ---------------- Characters ----------------
export async function loadCharacters(env: Env, bookId: string): Promise<CharacterState[]> {
  const r = await env.DB.prepare("SELECT * FROM characters WHERE book_id=?").bind(bookId).all<any>();
  return (r.results ?? []).map(rowToChar);
}

function rowToChar(row: any): CharacterState {
  return {
    id: row.id, book_id: row.book_id, name: row.name,
    aliases: safeArr(row.aliases), role: row.role ?? "npc",
    alive: !!row.alive, realm_index: row.realm_index ?? 0,
    realm_name: row.realm_name ?? "", realm_sub: row.realm_sub ?? 0,
    techniques: safeArr(row.techniques), movement_arts: safeArr(row.movement_arts),
    artifacts: safeArr(row.artifacts), assets: safeAssets(row.assets),
    relations: safeArr(row.relations), status_notes: row.status_notes ?? "",
    last_seen_ch: row.last_seen_ch ?? 0, last_breakthrough_ch: row.last_breakthrough_ch ?? 0,
  };
}

export async function upsertCharacter(env: Env, bookId: string, c: Partial<CharacterState> & { name: string }) {
  const existing = await env.DB.prepare("SELECT * FROM characters WHERE book_id=? AND name=?")
    .bind(bookId, c.name).first<any>();
  if (existing) {
    const prev = rowToChar(existing);
    const merged = { ...prev, ...c };
    // 功法/身法/法宝/人脉按 name 合并去重，避免每章覆盖丢失既有能力
    if (c.techniques) merged.techniques = mergeByName(prev.techniques, c.techniques);
    if (c.movement_arts) merged.movement_arts = mergeByName(prev.movement_arts, c.movement_arts);
    if (c.artifacts) merged.artifacts = mergeByName(prev.artifacts, c.artifacts);
    if (c.relations) merged.relations = mergeByName(prev.relations, c.relations);
    if (c.assets) merged.assets = mergeAssets(prev.assets, c.assets);
    await env.DB.prepare(
      `UPDATE characters SET aliases=?, role=?, alive=?, realm_index=?, realm_name=?, realm_sub=?,
       techniques=?, movement_arts=?, artifacts=?, assets=?, relations=?, status_notes=?,
       last_seen_ch=?, last_breakthrough_ch=?, updated_at=?
       WHERE book_id=? AND name=?`
    ).bind(
      J(merged.aliases), merged.role, merged.alive ? 1 : 0, merged.realm_index, merged.realm_name,
      merged.realm_sub, J(merged.techniques), J(merged.movement_arts), J(merged.artifacts),
      J(merged.assets), J(merged.relations), merged.status_notes, merged.last_seen_ch,
      merged.last_breakthrough_ch, now(), bookId, c.name
    ).run();
  } else {
    await env.DB.prepare(
      `INSERT INTO characters (id,book_id,name,aliases,role,alive,realm_index,realm_name,realm_sub,
       techniques,movement_arts,artifacts,assets,relations,status_notes,last_seen_ch,last_breakthrough_ch,updated_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      uid(), bookId, c.name, J(c.aliases ?? []), c.role ?? "npc", c.alive === false ? 0 : 1,
      c.realm_index ?? 0, c.realm_name ?? "", c.realm_sub ?? 0, J(c.techniques ?? []),
      J(c.movement_arts ?? []), J(c.artifacts ?? []), J(c.assets ?? emptyAssets()),
      J(c.relations ?? []), c.status_notes ?? "", c.last_seen_ch ?? 0, c.last_breakthrough_ch ?? 0, now()
    ).run();
  }
}

// ---------------- Plot state ----------------
export async function getPlot(env: Env, bookId: string, key: string): Promise<any> {
  const r = await env.DB.prepare("SELECT value FROM plot_state WHERE book_id=? AND key=?")
    .bind(bookId, key).first<{ value: string }>();
  return r ? safeJson(r.value) : null;
}

export async function setPlot(env: Env, bookId: string, key: string, value: unknown) {
  await env.DB.prepare(
    `INSERT INTO plot_state (book_id,key,value,updated_at) VALUES (?,?,?,?)
     ON CONFLICT(book_id,key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`
  ).bind(bookId, key, J(value), now()).run();
}

// ---------------- Foreshadowing ----------------
export async function openForeshadowing(env: Env, bookId: string): Promise<Foreshadow[]> {
  const r = await env.DB.prepare(
    "SELECT * FROM foreshadowing WHERE book_id=? AND status!='resolved' AND status!='dropped' ORDER BY importance DESC"
  ).bind(bookId).all<any>();
  return (r.results ?? []) as Foreshadow[];
}

export async function addForeshadow(env: Env, bookId: string, f: { title: string; detail: string; importance: number; planted_ch: number; due_ch?: number }) {
  await env.DB.prepare(
    `INSERT INTO foreshadowing (id,book_id,title,detail,status,planted_ch,due_ch,importance,updated_at)
     VALUES (?,?,?,?,'planted',?,?,?,?)`
  ).bind(uid(), bookId, f.title, f.detail, f.planted_ch, f.due_ch ?? f.planted_ch + 50, f.importance, now()).run();
}

export async function updateForeshadowByTitle(env: Env, bookId: string, title: string, status: string, ch: number) {
  await env.DB.prepare(
    `UPDATE foreshadowing SET status=?, resolved_ch=CASE WHEN ?='resolved' THEN ? ELSE resolved_ch END, updated_at=?
     WHERE book_id=? AND title=?`
  ).bind(status, status, ch, now(), bookId, title).run();
}

// ---------------- Chapters & 检索 ----------------
export async function lastChapter(env: Env, bookId: string): Promise<any | null> {
  return env.DB.prepare(
    "SELECT * FROM chapters WHERE book_id=? AND status='done' ORDER BY chapter_no DESC LIMIT 1"
  ).bind(bookId).first<any>();
}

// 无 Vectorize 的"记忆检索"：按 tag 关键词在历史章节 summary/tags 里匹配，取最相关的几条。
export async function retrieveRelevant(env: Env, bookId: string, tags: string[], limit = 5): Promise<{ chapter_no: number; summary: string }[]> {
  if (!tags.length) return [];
  const r = await env.DB.prepare(
    "SELECT chapter_no, summary, tags FROM chapters WHERE book_id=? AND status='done' ORDER BY chapter_no DESC LIMIT 400"
  ).bind(bookId).all<any>();
  const scored = (r.results ?? []).map((row) => {
    const t: string[] = safeArr(row.tags);
    const score = tags.reduce((acc, tag) => acc + (t.includes(tag) ? 2 : (row.summary || "").includes(tag) ? 1 : 0), 0);
    return { chapter_no: row.chapter_no, summary: row.summary || "", score };
  });
  return scored.filter((s) => s.score > 0).sort((a, b) => b.score - a.score).slice(0, limit);
}

export async function saveChapter(env: Env, bookId: string, ch: {
  chapter_no: number; title: string; outline: string; content: string;
  summary: string; ending_tail: string; tags: string[]; word_count: number;
  version: number; qc_report: string;
}) {
  await env.DB.prepare(
    `INSERT INTO chapters (id,book_id,chapter_no,title,outline,content,summary,ending_tail,tags,word_count,status,version,qc_report,created_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,'done',?,?,?)`
  ).bind(
    uid(), bookId, ch.chapter_no, ch.title, ch.outline, ch.content, ch.summary,
    ch.ending_tail, J(ch.tags), ch.word_count, ch.version, ch.qc_report, now()
  ).run();
}

// ---------------- Logs ----------------
export async function log(env: Env, p: { bookId?: string; chapterNo?: number; level?: string; stage?: string; message: string; meta?: unknown }) {
  await env.DB.prepare(
    `INSERT INTO logs (id,book_id,chapter_no,level,stage,message,meta,created_at) VALUES (?,?,?,?,?,?,?,?)`
  ).bind(uid(), p.bookId ?? null, p.chapterNo ?? null, p.level ?? "info", p.stage ?? null, p.message, J(p.meta ?? null), now()).run();
}

// ---------------- 并发锁（KV）：同一本书同一时刻只跑一章 ----------------
export async function acquireLock(env: Env, bookId: string, ttlSec = 300): Promise<boolean> {
  const key = `lock:${bookId}`;
  const cur = await env.KV.get(key);
  if (cur) return false;
  await env.KV.put(key, String(now()), { expirationTtl: ttlSec });
  return true;
}
export async function releaseLock(env: Env, bookId: string) {
  await env.KV.delete(`lock:${bookId}`);
}

// ---------------- 上下文编译：把世界状态压成喂给 LLM 的紧凑文本 ----------------
export function compileMemoryContext(p: {
  chars: CharacterState[];
  fores: Foreshadow[];
  mainNode: any;
  exploredMap: string[];
  relevant: { chapter_no: number; summary: string }[];
  lastSummary: string;
  lastTail: string;
  currentPlane?: string | null;
}): string {
  const charLines = p.chars
    .filter((c) => c.role === "protagonist" || c.alive)
    .slice(0, 25)
    .map((c) => {
      const tech = c.techniques.map((t) => `${t.name}(${t.layer}/${t.maxLayer}层)`).join("、");
      const move = (c.movement_arts || []).map((m) => `${m.name}[${m.kind}]`).join("、");
      const arts = c.artifacts.map((a) => `${a.name}[${a.grade},耐久${a.durability}]`).join("、");
      return `- ${c.name}${c.aliases.length ? `(${c.aliases.join("/")})` : ""}｜${c.role}｜${c.alive ? "在世" : "已死"}｜境界:${c.realm_name}${c.realm_sub}层(序${c.realm_index})｜功法:${tech || "无"}｜身法/神通:${move || "无"}｜法宝:${arts || "无"}｜近况:${c.status_notes || "—"}`;
    }).join("\n");

  // 主角家底单列，强约束"只能花已有的、只能用已习得的"
  const hero = p.chars.find((c) => c.role === "protagonist");
  const heroAssets = hero ? (() => {
    const a = hero.assets || { spirit_stones: 0, pills: [], materials: [], misc: [] };
    const pills = (a.pills || []).map((x) => `${x.name}×${x.count}`).join("、") || "无";
    const mats = (a.materials || []).map((x) => `${x.name}×${x.count}`).join("、") || "无";
    const move = (hero.movement_arts || []).map((m) => `${m.name}[${m.kind}]`).join("、") || "无";
    return `主角「${hero.name}」当前家底——灵石:${a.spirit_stones}｜丹药:${pills}｜材料:${mats}｜杂项:${(a.misc || []).join("、") || "无"}\n主角已习得身法/神通/秘术:${move}（本章只能动用此清单内能力，新能力须经剧情习得并交代来历）`;
  })() : "（无主角记录）";

  const foreLines = p.fores.slice(0, 20).map(
    (f) => `- [${f.status}|重要度${f.importance}|建议第${f.due_ch}章前回收] ${f.title}：${f.detail}`
  ).join("\n");

  const relLines = p.relevant.map((r) => `- 第${r.chapter_no}章：${r.summary}`).join("\n");

  return [
    `【当前位面】${p.currentPlane || "（未设/凡界）"}`,
    `【主线进度】\n${p.mainNode ? JSON.stringify(p.mainNode) : "（起始）"}`,
    `【已探索地图/势力】\n${(p.exploredMap || []).join("、") || "（无）"}`,
    `【主角家底与已习得能力（硬约束）】\n${heroAssets}`,
    `【在世/关键角色状态】\n${charLines || "（暂无）"}`,
    `【未了结伏笔/因果】\n${foreLines || "（无）"}`,
    `【相关历史剧情（按相关度检索）】\n${relLines || "（无）"}`,
    `【上一章摘要】\n${p.lastSummary || "（这是第一章）"}`,
    `【上一章结尾原文（用于无缝衔接，勿重复其内容）】\n${p.lastTail || "（无）"}`,
  ].join("\n\n");
}

// ---- helpers ----
// 按 name 合并两个对象数组，后者覆盖同名项（更新耐久/层数），其余保留
function mergeByName<T extends { name: string }>(prev: T[], next: T[]): T[] {
  const map = new Map(prev.map((x) => [x.name, x]));
  for (const n of next) map.set(n.name, { ...map.get(n.name), ...n });
  return Array.from(map.values());
}
// 家底解析与合并：灵石累加，丹药/材料按 name 累加数量
function safeAssets(s: any): Assets {
  const a = safeJson(s);
  if (!a || typeof a !== "object") return emptyAssets();
  return {
    spirit_stones: a.spirit_stones ?? 0,
    pills: Array.isArray(a.pills) ? a.pills : [],
    materials: Array.isArray(a.materials) ? a.materials : [],
    misc: Array.isArray(a.misc) ? a.misc : [],
  };
}
function mergeAssets(prev: Assets, next: Partial<Assets>): Assets {
  const addCount = (base: { name: string; count: number }[], add?: { name: string; count: number }[]) => {
    const map = new Map(base.map((x) => [x.name, x.count]));
    for (const x of add || []) map.set(x.name, (map.get(x.name) ?? 0) + x.count);
    return Array.from(map.entries()).map(([name, count]) => ({ name, count })).filter((x) => x.count > 0);
  };
  return {
    spirit_stones: Math.max(0, (prev.spirit_stones ?? 0) + (next.spirit_stones ?? 0)),
    pills: mergeCount(prev.pills, next.pills),
    materials: mergeCount(prev.materials, next.materials),
    misc: Array.from(new Set([...(prev.misc || []), ...(next.misc || [])])),
  };
  function mergeCount(base: { name: string; count: number }[], add?: { name: string; count: number }[]) {
    return addCount(base, add);
  }
}
const J = (v: unknown) => JSON.stringify(v ?? null);
const safeArr = (s: any): any[] => { try { const v = JSON.parse(s); return Array.isArray(v) ? v : []; } catch { return []; } };
const safeJson = (s: any): any => { try { return JSON.parse(s); } catch { return null; } };
