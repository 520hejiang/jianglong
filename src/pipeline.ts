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
    // 【新增】还原性格与口癖
    personality_traits: safeArr(row.personality_traits),
    speech_pattern: row.speech_pattern ?? "",
  };
}

export async function upsertCharacter(env: Env, bookId: string, c: Partial<CharacterState> & { name: string }) {
  const existing = await env.DB.prepare("SELECT * FROM characters WHERE book_id=? AND name=?")
    .bind(bookId, c.name).first<any>();
  if (existing) {
    const prev = rowToChar(existing);
    const merged = { ...prev, ...c };
    if (c.techniques) merged.techniques = mergeByName(prev.techniques, c.techniques);
    if (c.movement_arts) merged.movement_arts = mergeByName(prev.movement_arts, c.movement_arts);
    if (c.artifacts) merged.artifacts = mergeByName(prev.artifacts, c.artifacts);
    if (c.relations) merged.relations = mergeByName(prev.relations, c.relations);
    if (c.assets) merged.assets = mergeAssets(prev.assets, c.assets);
    // 【新增】合并性格与口癖（用新值覆盖旧值）
    if (c.personality_traits) merged.personality_traits = c.personality_traits;
    if (c.speech_pattern) merged.speech_pattern = c.speech_pattern;
    
    await env.DB.prepare(
      `UPDATE characters SET aliases=?, role=?, alive=?, realm_index=?, realm_name=?, realm_sub=?,
       techniques=?, movement_arts=?, artifacts=?, assets=?, relations=?, status_notes=?,
       last_seen_ch=?, last_breakthrough_ch=?, personality_traits=?, speech_pattern=?, updated_at=?
       WHERE book_id=? AND name=?`
    ).bind(
      J(merged.aliases), merged.role, merged.alive ? 1 : 0, merged.realm_index, merged.realm_name,
      merged.realm_sub, J(merged.techniques), J(merged.movement_arts), J(merged.artifacts),
      J(merged.assets), J(merged.relations), merged.status_notes, merged.last_seen_ch,
      merged.last_breakthrough_ch, J(merged.personality_traits ?? []), merged.speech_pattern ?? "",
      now(), bookId, c.name
    ).run();
  } else {
    await env.DB.prepare(
      `INSERT INTO characters (id,book_id,name,aliases,role,alive,realm_index,realm_name,realm_sub,
       techniques,movement_arts,artifacts,assets,relations,status_notes,last_seen_ch,last_breakthrough_ch,personality_traits,speech_pattern,updated_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      uid(), bookId, c.name, J(c.aliases ?? []), c.role ?? "npc", c.alive === false ? 0 : 1,
      c.realm_index ?? 0, c.realm_name ?? "", c.realm_sub ?? 0, J(c.techniques ?? []),
      J(c.movement_arts ?? []), J(c.artifacts ?? []), J(c.assets ?? emptyAssets()),
      J(c.relations ?? []), c.status_notes ?? "", c.last_seen_ch ?? 0, c.last_breakthrough_ch ?? 0,
      J(c.personality_traits ?? []), c.speech_pattern ?? "", now()
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

export async function recentOpenings(env: Env, bookId: string, n = 5): Promise<string[]> {
  const r = await env.DB.prepare(
    "SELECT content FROM chapters WHERE book_id=? AND status='done' ORDER BY chapter_no DESC LIMIT ?"
  ).bind(bookId, n).all<{ content: string }>();
  return (r.results ?? []).map((row) => {
    const bodyStart = row.content.indexOf("\n\n");
    const body = bodyStart >= 0 ? row.content.slice(bodyStart + 2) : row.content;
    const firstLine = body.trim().split("\n")[0] || "";
    const m = firstLine.match(/^[^。！？…]{0,40}[。！？…]?/);
    return (m ? m[0] : firstLine).slice(0, 40);
  }).filter(Boolean);
}

export async function retrieveRelevant(env: Env, bookId: string, tags: string[], limit = 5): Promise<{ chapter_no: number; summary: string }[]> {
  if (!tags.length) return [];
  const r = await env.DB.prepare(
    "SELECT chapter_no, summary, tags FROM chapters WHERE book_id=? AND status='done' ORDER BY chapter_no DESC LIMIT 2000"
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

// ---------------- 并发锁（KV） ----------------
export async function acquireLock(env: Env, bookId: string, ttlSec = 120): Promise<boolean> {
  const key = `genlock:${bookId}`;
  const cur = await env.KV.get(key);
  if (cur) return false;
  await env.KV.put(key, String(now()), { expirationTtl: Math.max(60, ttlSec) });
  return true;
}
export async function releaseLock(env: Env, bookId: string) {
  await env.KV.delete(`genlock:${bookId}`);
}

// ---------------- 上下文编译：分层记忆 ----------------
function compileRecentSceneContext(chars: CharacterState[], relevant: { chapter_no: number; summary: string }[]): string {
  const recentSideChars = chars
    .filter(c => c.role !== 'protagonist' && c.alive && c.last_seen_ch > 0)
    .sort((a, b) => (b.last_seen_ch || 0) - (a.last_seen_ch || 0))
    .slice(0, 10)
    .map(c => `- ${c.name}（身份：${c.role}，境界：${c.realm_name}，上次出现于：第${c.last_seen_ch}章）`)
    .join('\n') || '（无近期出场配角）';

  const recentLocations = Array.from(new Set(
    (relevant || []).flatMap(r => {
      const summary = r.summary || '';
      const locMatch = summary.match(/[（(]?(?:位于|来到|身处|抵达|在|于)([^，,。、！？)]{1,15}[城/山/谷/府/殿/岛])[）)]?/);
      return locMatch ? [locMatch[1]] : [];
    })
  )).slice(0, 8).join('、') || '（无近期关键地点）';
  
  return `【近期关键配角（近100章内出场）】\n${recentSideChars}\n【近期活跃地点】\n${recentLocations}`;
}

export function compileMemoryContext(p: {
  chars: CharacterState[];
  fores: Foreshadow[];
  mainNode: any;
  exploredMap: string[];
  relevant: { chapter_no: number; summary: string }[];
  lastSummary: string;
  lastTail: string;
  currentPlane?: string | null;
  storyDigest?: string;
}): string {
  const truncateList = (arr: any[], label: string): string => {
    if (!arr || arr.length === 0) return '无';
    const s = arr.slice(0, 15).map((t) => `${t.name}${t.layer !== undefined ? `(${t.layer}/${t.maxLayer}层)` : `[${t.grade || ''}]`}`).join('、');
    return s + (arr.length > 15 ? `，及其他 ${arr.length - 15} 种${label}` : '');
  };

  const charLines = p.chars
    .filter((c) => c.role === "protagonist" || c.alive)
    .sort((a, b) => (a.role === "protagonist" ? -1 : b.role === "protagonist" ? 1 : (b.last_seen_ch || 0) - (a.last_seen_ch || 0)))
    .slice(0, 25)
    .map((c) => {
      const tech = truncateList(c.techniques, '功法');
      // 【注入】性格与口癖
      const personality = c.personality_traits?.length ? `【性格】${c.personality_traits.join('、')}` : '';
      const speech = c.speech_pattern ? `【口癖】${c.speech_pattern}` : '';
      return `- ${c.name}${c.aliases.length ? `(${c.aliases.join("/")})` : ""}｜${c.role}｜${c.alive ? "在世" : "已死"}｜境界:${c.realm_name}${c.realm_sub}层｜功法:${tech}｜${personality} ${speech}｜近况:${c.status_notes || "—"}`;
    }).join("\n");

  const hero = p.chars.find((c) => c.role === "protagonist");
  const heroAssets = hero ? (() => {
    const a = hero.assets || { spirit_stones: 0, pills: [], materials: [], misc: [] };
    const pills = truncateList(a.pills || [], '丹药');
    const mats = truncateList(a.materials || [], '材料');
    const move = truncateList(hero.movement_arts || [], '身法/神通');
    return `主角「${hero.name}」当前家底——灵石:${a.spirit_stones}｜丹药:${pills}｜材料:${mats}\n主角已习得身法/神通:${move}（本章只能动用此清单内能力，新能力须经剧情习得并交代来历）`;
  })() : "（无主角记录）";

  const foreLines = [...p.fores]
    .sort((a, b) => (b.importance - a.importance) || ((a.due_ch || 9e9) - (b.due_ch || 9e9)))
    .slice(0, 20)
    .map((f) => `- [${f.status}|重要度${f.importance}|建议第${f.due_ch}章前回收] ${f.title}：${f.detail}`)
    .join("\n");

  const relLines = p.relevant.map((r) => `- 第${r.chapter_no}章：${r.summary}`).join("\n");
  const map40 = (p.exploredMap || []).slice(-40);
  const sceneContext = compileRecentSceneContext(p.chars, p.relevant);
  const progression = `【当前时间线】\n主角已修炼 ${hero?.last_breakthrough_ch || 0} 章，当前处于 ${p.currentPlane || '凡界'}，主角境界 ${hero?.realm_name || '凡人'} 第 ${hero?.realm_sub || 0} 层`;

  return [
    `【全书前情提要（已压缩，长程主线记忆）】\n${p.storyDigest || "（暂无，靠前章节）"}`,
    `【当前位面】${p.currentPlane || "（未设/凡界）"}`,
    `【主线进度】\n${p.mainNode ? JSON.stringify(p.mainNode) : "（起始）"}`,
    `【已探索地图/势力（近40）】\n${map40.join("、") || "（无）"}`,
    `【主角家底与已习得能力（硬约束·面板为准）】\n${heroAssets}`,
    `【在世/关键角色状态（按活跃度，最多25）】\n${charLines || "（暂无）"}`,
    `【未了结伏笔/因果（按重要度，最多20）】\n${foreLines || "（无）"}`,
    sceneContext,
    progression,
    `【相关历史剧情（按相关度检索）】\n${relLines || "（无）"}`,
    `【上一章摘要】\n${p.lastSummary || "（这是第一章）"}`,
    `【上一章结尾原文（用于无缝衔接，勿重复其内容）】\n${p.lastTail || "（无）"}`,
  ].join("\n\n");
}

// ---------------- 全书前情提要压缩 ----------------
export async function updateStoryDigest(env: Env, bookId: string, uptoChapter: number, summarize: (oldDigest: string, recent: string) => Promise<string>): Promise<void> {
  const firstFive = await env.DB.prepare(
    "SELECT chapter_no, summary FROM chapters WHERE book_id=? AND status='done' AND chapter_no <= 5 ORDER BY chapter_no ASC"
  ).bind(bookId).all<{ chapter_no: number; summary: string }>();
  const firstSum = (firstFive.results ?? []).map((x) => `第${x.chapter_no}章：${x.summary}`).join("\n");
  if (firstSum) {
    await setPlot(env, bookId, "__first_chapters_anchor", firstSum);
  }
  const firstAnchor = (await getPlot(env, bookId, "__first_chapters_anchor")) || "";

  const old = (await getPlot(env, bookId, "story_digest")) || "";
  const r = await env.DB.prepare(
    "SELECT chapter_no, summary FROM chapters WHERE book_id=? AND status='done' AND chapter_no<=? ORDER BY chapter_no DESC LIMIT 15"
  ).bind(bookId, uptoChapter).all<{ chapter_no: number; summary: string }>();
  const recent = (r.results ?? []).reverse().map((x) => `第${x.chapter_no}章：${x.summary}`).join("\n");
  if (!recent) return;
  try {
    const oldStr = typeof old === 'string' ? old : JSON.stringify(old);
    const finalOldDigest = `【绝对不可删减的开篇核心根源】\n${firstAnchor}\n\n【后续历史压缩】\n${oldStr}`;
    const digest = await summarize(finalOldDigest, recent);
    if (digest && digest.trim()) await setPlot(env, bookId, "story_digest", digest.trim().slice(0, 1200));
  } catch { /* 压缩失败不影响主流程 */ }
}

export async function pruneDeadThreads(env: Env, bookId: string, chapterNo: number): Promise<void> {
  await env.DB.prepare(
    "UPDATE foreshadowing SET status='dropped', updated_at=? WHERE book_id=? AND status NOT IN ('resolved','dropped') AND importance<=2 AND due_ch IS NOT NULL AND ?-due_ch>100"
  ).bind(Date.now(), bookId, chapterNo).run();
}

// ---- helpers ----
function mergeByName<T extends { name: string }>(prev: T[], next: T[]): T[] {
  const map = new Map(prev.map((x) => [x.name, x]));
  for (const n of next) map.set(n.name, { ...map.get(n.name), ...n });
  return Array.from(map.values());
}
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
```

// ============================================================================
// 多 Agent 流水线：读取记忆 -> 提取焦点 -> 细纲 -> 审核 -> 正文 -> 润色质检 -> 更新记忆
// 一次 generateChapter 完整产出并落库一章。
// ============================================================================
import type { Env, Book, ChapterOutline, StateDelta, Plane } from "./types";
import { cfg, DEFAULT_PLANES } from "./config";
import { chat, parseJson, chatJSON } from "./llm";
import * as M from "./memory";
import { validateDelta, hasBlocking, formatIssues, detectSlop } from "./validators";
import {
  PROMPT_EXTRACT, PROMPT_OUTLINE, PROMPT_REVIEW, PROMPT_DRAFT, PROMPT_POLISH, PROMPT_UPDATE, PROMPT_DIGEST,
} from "./prompts";
import { tg } from "./telegram";

// 允许控制台覆盖默认模板
async function tpl(env: Env, bookId: string, name: string, fallback: string): Promise<string> {
  // 用字符串拼接代替模板字符串，彻底绕开不可见字符导致的解析报错
  const bookIdFull = bookId + ":" + name;
  const globalId = "global:" + name;
  const row = await env.DB.prepare(
    "SELECT template FROM prompts WHERE name=? AND (id=? OR id=?) ORDER BY scope DESC LIMIT 1"
  ).bind(name, bookIdFull, globalId).first<{ template: string }>();
  return row?.template || fallback;
}
const fill = (t: string, vars: Record<string, string | number>) =>
  t.replace(/\{\{(\w+)\}\}/g, (_, k) => String(vars[k] ?? ""));

function safeParse<T>(s: string, fallback: T): T {
  try { return JSON.parse(s) as T; } catch { return fallback; }
}

export interface ChapterResult {
  chapterNo: number;
  title: string;
  wordCount: number;
  issues: string[];
}

// 生成阶段（断点续传：每完成一步存档，被掐断也能从断点继续）
type Stage = "extract" | "outline" | "review" | "draft" | "polish" | "update" | "finalize" | "rewrite" | "complete";

export interface GenState {
  chapterNo: number;
  version: number;
  stage: Stage;
  attempt: number;
  focusJson?: string;
  memory?: string;
  openings?: string;
  lastTail?: string;
  outlineJson?: string;
  draft?: string;
  finalText?: string;
  deltaJson?: string;
  issues?: string[];
  title?: string;
  wc?: number;
  isRewrite?: boolean;
  startedAt?: number;
}

const GENJOB_KEY = "__genjob";
const REWRITE_KEY = "__rewritejob";

// 执行当前阶段的一步
async function runStep(env: Env, bookId: string, st: GenState): Promise<GenState> {
  const c = cfg(env);
  const book = await M.getBook(env, bookId);
  if (!book) throw new Error(`book not found: ${bookId}`);
  const ch = st.chapterNo;
  const vol = M.volumeForChapter(book, ch);
  const volText = vol ? JSON.stringify(vol) : (book.master_outline || "（无卷纲，依据总纲推进）");
  const stylePrefix = book.style_prompt_override
    ? `【本书特别文风/设定要求（优先级最高，与下列通用铁律冲突时以此为准）】\n${book.style_prompt_override}\n\n`
    : "";
  const chars = await M.loadCharacters(env, bookId);
  const charMap = new Map(chars.map((x) => [x.name, x]));
  const fores = await M.openForeshadowing(env, bookId);
  const planes: Plane[] = book.planes ? safeParse<Plane[]>(book.planes, []) : DEFAULT_PLANES;
  const currentPlane = book.current_plane || planes[0]?.name || null;

  switch (st.stage) {
    case "extract": {
      const mainNode = await M.getPlot(env, bookId, "main_node");
      const exploredMap: string[] = (await M.getPlot(env, bookId, "explored_map")) || [];
      const storyDigest: string = (await M.getPlot(env, bookId, "story_digest")) || "";
      const last = await M.lastChapter(env, bookId);
      const baseMem = M.compileMemoryContext({
        chars, fores, mainNode, exploredMap, relevant: [], currentPlane, storyDigest,
        lastSummary: last?.summary || "", lastTail: last?.ending_tail || "",
      });
      const extractRaw = await chat(env, [
        { role: "system", content: stylePrefix + fill(await tpl(env, bookId, "extract", PROMPT_EXTRACT), { CH: ch }) },
        { role: "user", content: fill("【本卷大纲】\n{{VOLUME}}\n\n【当前世界状态】\n{{MEMORY}}", { VOLUME: volText, MEMORY: baseMem }) },
      ], { temperature: 0.4, maxTokens: 800, json: true });
      let focus: any = {};
      try { focus = parseJson(extractRaw.text); } catch { focus = { must_use_entities: [] }; }
      await M.log(env, { bookId, chapterNo: ch, stage: "extract", message: `focus: ${focus.focus || "-"}`, meta: focus });
      const relevant = await M.retrieveRelevant(env, bookId, focus.must_use_entities || [], 5);
      const memory = M.compileMemoryContext({
        chars, fores, mainNode, exploredMap, relevant, currentPlane, storyDigest,
        lastSummary: last?.summary || "", lastTail: last?.ending_tail || "",
      });
      const ops = await M.recentOpenings(env, bookId, 5);
      const openings = ops.length ? ops.map((o, i) => `${i + 1}. ${o}…`).join("\n") : "（暂无，本章为靠前章节）";
      return { ...st, stage: "outline", focusJson: JSON.stringify(focus), memory, openings, lastTail: last?.ending_tail || "" };
    }
    case "outline": {
      const outline = await genOutline(env, bookId, ch, volText, st.memory!, st.focusJson!, c, stylePrefix);
      return { ...st, stage: "review", outlineJson: JSON.stringify(outline) };
    }
    case "review": {
      let outline = JSON.parse(st.outlineJson!) as ChapterOutline;
      const overdue = fores.filter((f) => f.due_ch && ch > f.due_ch)
        .map((f) => `「${f.title}」(建议第${f.due_ch}章前)`).join("；") || "（无）";
      for (let i = 0; i < c.maxReviewLoop; i++) {
        const reviewRaw = await chat(env, [
          { role: "system", content: stylePrefix + fill(await tpl(env, bookId, "review", PROMPT_REVIEW), { CH: ch }) },
          { role: "user", content: fill("【待审细纲】\n{{OUTLINE}}\n\n【当前世界状态】\n{{MEMORY}}\n\n【超期伏笔提醒】\n{{OVERDUE}}",
              { OUTLINE: JSON.stringify(outline), MEMORY: st.memory!, OVERDUE: overdue }) },
        ], { temperature: 0.3, maxTokens: 2000, json: true });
        let review: any;
        try { review = parseJson(reviewRaw.text); } catch { break; }
        if (review.approved) break;
        await M.log(env, { bookId, chapterNo: ch, level: "warn", stage: "review", message: `细纲打回: ${(review.issues || []).join("; ")}` });
        if (review.revised_outline) outline = review.revised_outline as ChapterOutline;
      }
      return { ...st, stage: "draft", outlineJson: JSON.stringify(outline) };
    }
    case "draft": {
      const outline = JSON.parse(st.outlineJson!) as ChapterOutline;
      const draft = await genDraft(env, bookId, ch, outline, st.memory!, st.lastTail || "", c, stylePrefix, st.openings || "");
      return { ...st, stage: "polish", draft };
    }
    case "polish": {
      const slop = detectSlop(st.draft!);
      const needPolish = c.polishMode === "always" || (c.polishMode === "auto" && (slop.hit || st.attempt > 0));
      let finalText = st.draft!;
      if (needPolish) {
        if (slop.hit) await M.log(env, { bookId, chapterNo: ch, stage: "polish", message: `触发润色去AI味: ${slop.reasons.join("；")}` });
        finalText = await polish(env, bookId, ch, st.draft!, st.memory!, c, stylePrefix);
      }
      return { ...st, stage: "update", finalText };
    }
    case "update": {
      const delta = await extractDelta(env, bookId, ch, st.finalText!, st.memory!, stylePrefix);
      const issues = validateDelta(charMap, delta, fores, {
        chapterNo: ch, planes, currentPlane,
        minBreakthroughGap: c.minBreakthroughGap, assetSurgeFactor: c.assetSurgeFactor,
      });
      const issuesText = issues.map((x) => `[${x.level}] ${x.rule}: ${x.detail}`);
      if (!st.isRewrite && hasBlocking(issues) && st.attempt < c.maxRewrite - 1) {
        await M.log(env, { bookId, chapterNo: ch, level: "warn", stage: "update", message: `质检未过(尝试${st.attempt + 1})，回炉重写: ${formatIssues(issues)}` });
        return { ...st, stage: "draft", attempt: st.attempt + 1, memory: st.memory! + `\n\n【上一次生成违反了以下硬规则，本次务必修正】\n${formatIssues(issues)}` };
      }
      return { ...st, stage: "finalize", deltaJson: JSON.stringify(delta), issues: issuesText };
    }
    case "finalize": {
      const delta = JSON.parse(st.deltaJson!) as StateDelta;
      const outline = JSON.parse(st.outlineJson!) as ChapterOutline;
      const title = outline.title || `第${ch}章`;
      const body = normalizeText(stripLeadingTitle(st.finalText!));
      const cleaned = `第${ch}章 ${title}\n\n${body}`;
      const wc = body.replace(/\s/g, "").length;
      const issuesText = [...(st.issues || [])];
      if (wc < Math.floor(c.charsMin * 0.7)) issuesText.push(`[warn] LENGTH: 本章仅 ${wc} 字，短于目标下限 ${c.charsMin}`);
      else if (wc > Math.ceil(c.charsMax * 1.6)) issuesText.push(`[warn] LENGTH: 本章 ${wc} 字，明显超出目标上限 ${c.charsMax}`);

      await M.saveChapter(env, bookId, {
        chapter_no: ch, title, outline: JSON.stringify(outline), content: cleaned,
        summary: delta.summary || "", ending_tail: body.slice(-320), tags: delta.tags || [],
        word_count: wc, version: st.version, qc_report: JSON.stringify({ issues: issuesText }),
      });

      if (st.isRewrite) {
        await M.log(env, { bookId, chapterNo: ch, stage: "update", message: `第${ch}章已重写(v${st.version})，${wc}字`, meta: { wc, issues: issuesText } });
        return { ...st, stage: "complete", title, wc, issues: issuesText };
      }

      await applyDelta(env, bookId, ch, delta, charMap);
      if (ch === book.next_chapter) {
        await env.DB.prepare(
          "UPDATE books SET next_chapter=?, total_chars=total_chars+?, cursor_volume=?, updated_at=? WHERE id=?"
        ).bind(ch + 1, wc, vol?.vol ?? book.cursor_volume, Date.now(), bookId).run();
      }
      if (book.target_chapters && ch >= book.target_chapters) await M.setBookStatus(env, bookId, "finished");
      await M.log(env, { bookId, chapterNo: ch, stage: "update", message: `第${ch}章完成，${wc}字`, meta: { wc, issues: issuesText } });

      await M.pruneDeadThreads(env, bookId, ch);
      if (ch % 10 === 0) {
        await M.updateStoryDigest(env, bookId, ch, async (oldDigest, recent) => {
          const r = await chat(env, [
            { role: "system", content: fill(await tpl(env, bookId, "digest", PROMPT_DIGEST), {}) },
            { role: "user", content: `【已有前情提要】\n${oldDigest || "（无）"}\n\n【最近章节摘要】\n${recent}` },
          ], { temperature: 0.3, maxTokens: 900 });
          return r.text;
        });
      }
      const hero = (await M.loadCharacters(env, bookId)).find((x) => x.role === "protagonist");
      const heroLine = hero ? `${hero.name} ${hero.realm_name}${hero.realm_sub}层｜灵石${hero.assets?.spirit_stones ?? 0}` : "—";
      const rewrites = st.attempt || 0;
      const qc = issuesText.length ? `\n质检: ${issuesText.join("；").slice(0, 300)}` : "";
      await tg(env, `📖 <b>${book.title}</b> 第${ch}章 ${title}（${wc}字｜重写${rewrites}次）\n摘要: ${delta.summary || "—"}\n主角: ${heroLine}${qc}`);

      return { ...st, stage: "complete", title, wc, issues: issuesText };
    }
    default:
      return { ...st, stage: "complete" };
  }
}

export async function generateChapter(env: Env, bookId: string, chapterNo: number, version = 1): Promise<ChapterResult> {
  const dup = await env.DB.prepare(
    "SELECT 1 FROM chapters WHERE book_id=? AND chapter_no=? AND version=? AND status='done' LIMIT 1"
  ).bind(bookId, chapterNo, version).first();
  if (dup) {
    await M.log(env, { bookId, chapterNo, stage: "queue", message: `第${chapterNo}章(v${version})已存在，跳过` });
    return { chapterNo, title: "(已存在)", wordCount: 0, issues: [] };
  }
  let st: GenState = { chapterNo, version, stage: "extract", attempt: 0 };
  let guard = 0;
  while (st.stage !== "complete" && guard++ < 40) st = await runStep(env, bookId, st);
  return { chapterNo, title: st.title || `第${chapterNo}章`, wordCount: st.wc || 0, issues: st.issues || [] };
}

export async function advanceBook(env: Env, bookId: string, budgetMs = 18000): Promise<"completed" | "progress" | "idle"> {
  const start = Date.now();
  const got = await M.acquireLock(env, bookId, 120);
  if (!got) return "idle";
  try {
    const book = await M.getBook(env, bookId);
    if (!book) return "idle";

    const rj = (await M.getPlot(env, bookId, REWRITE_KEY)) as GenState | null;
    if (rj && rj.stage && rj.stage !== "complete") {
      const stale = rj.startedAt && Date.now() - rj.startedAt > 8 * 60 * 1000;
      if (stale) {
        await M.setPlot(env, bookId, REWRITE_KEY, null);
        await M.log(env, { bookId, chapterNo: rj.chapterNo, level: "warn", stage: "rewrite", message: "重写长时间未完成，已放弃，恢复正常生成" });
      } else {
        try {
          const st = await rewriteStep(env, bookId, rj);
          await M.setPlot(env, bookId, REWRITE_KEY, st.stage === "complete" ? null : st);
          return st.stage === "complete" ? "completed" : "progress";
        } catch (e) {
          const attempt = (rj.attempt || 0) + 1;
          await M.log(env, { bookId, chapterNo: rj.chapterNo, level: "error", stage: "rewrite", message: `重写失败(第${attempt}次): ${String(e)}` });
          if (attempt >= 3) {
            await M.setPlot(env, bookId, REWRITE_KEY, null);
            await M.log(env, { bookId, chapterNo: rj.chapterNo, level: "warn", stage: "rewrite", message: "重写多次失败已放弃，恢复正常生成" });
          } else {
            await M.setPlot(env, bookId, REWRITE_KEY, { ...rj, attempt });
          }
          return "progress";
        }
      }
    }

    if (book.status !== "running") return "idle";
    if (book.target_chapters && book.next_chapter > book.target_chapters) {
      await M.setBookStatus(env, bookId, "finished");
      return "idle";
    }
    let st = (await M.getPlot(env, bookId, GENJOB_KEY)) as GenState | null;
    if (!st || !st.stage) {
      st = { chapterNo: book.next_chapter, version: 1, stage: "extract", attempt: 0 };
      await M.setPlot(env, bookId, GENJOB_KEY, st);
      await M.log(env, { bookId, chapterNo: st.chapterNo, stage: "start", message: `▶ 开始生成第${st.chapterNo}章` });
    }
    while (st.stage !== "complete" && Date.now() - start < budgetMs) {
      st = await runStep(env, bookId, st);
      await M.setPlot(env, bookId, GENJOB_KEY, st);
    }
    if (st.stage === "complete") {
      await M.setPlot(env, bookId, GENJOB_KEY, null);
      return "completed";
    }
    return "progress";
  } finally {
    await M.releaseLock(env, bookId);
  }
}

export async function startRewrite(env: Env, bookId: string, chapterNo: number): Promise<number> {
  const r = await env.DB.prepare(
    "SELECT COALESCE(MAX(version),0) v FROM chapters WHERE book_id=? AND chapter_no=?"
  ).bind(bookId, chapterNo).first<{ v: number }>();
  const version = (r?.v ?? 0) + 1;
  const job: GenState = { chapterNo, version, stage: "rewrite", attempt: 0, isRewrite: true, startedAt: Date.now() };
  await M.setPlot(env, bookId, REWRITE_KEY, job);
  return version;
}

// 重写模式：使用强制人类指令进行去AI味重写，不会误伤原有剧情和结尾
async function rewriteStep(env: Env, bookId: string, st: GenState): Promise<GenState> {
  const book = await M.getBook(env, bookId);
  if (!book) return { ...st, stage: "complete" };
  const ex = await env.DB.prepare(
    "SELECT id, title, content FROM chapters WHERE book_id=? AND chapter_no=? AND status='done' ORDER BY version ASC LIMIT 1"
  ).bind(bookId, st.chapterNo).first<any>();
  if (!ex) {
    await M.log(env, { bookId, chapterNo: st.chapterNo, level: "warn", stage: "rewrite", message: "找不到原章节，无法重写" });
    return { ...st, stage: "complete" };
  }
  
  const humanized = await chat(env, [
    { role: "system", content: `你是一位纯正的人类网文作家。请把【初稿】里的“AI腔、生硬的词汇、模板化的套路”全部磨掉，换成中文人类的口语化表达、真实的动作细节和内心戏。
【关键底线】严禁使用：仿佛、不禁、瞬间、竟然、居然、与此同时、不仅...而且、首先/其次。禁止替换原文的专有名词、人物名字、境界等级和灵石数量，只改文笔！` },
    { role: "user", content: `【初稿】\n${ex.content}` }
  ], { temperature: 0.6, maxTokens: 5000 });
  const polished = humanized.text;

  const body = normalizeText(stripLeadingTitle(polished));
  const title = ex.title || `第${st.chapterNo}章`;
  const cleaned = `第${st.chapterNo}章 ${title}\n\n${body}`;
  const wc = body.replace(/\s/g, "").length;
  await env.DB.prepare(
    "UPDATE chapters SET content=?, word_count=?, ending_tail=?, qc_report=? WHERE id=?"
  ).bind(cleaned, wc, body.slice(-320), JSON.stringify({ rewrite: true }), ex.id).run();
  await env.DB.prepare(
    "DELETE FROM chapters WHERE book_id=? AND chapter_no=? AND id<>?"
  ).bind(bookId, st.chapterNo, ex.id).run();
  await M.log(env, { bookId, chapterNo: st.chapterNo, stage: "rewrite", message: `第${st.chapterNo}章已重写覆盖，${wc}字` });
  return { ...st, stage: "complete", title, wc };
}

async function genOutline(env: Env, bookId: string, ch: number, volText: string, memory: string, focus: string, c: ReturnType<typeof cfg>, sp: string): Promise<ChapterOutline> {
  return chatJSON<ChapterOutline>(env, [
    { role: "system", content: sp + fill(await tpl(env, bookId, "outline", PROMPT_OUTLINE), { CH: ch, CMIN: c.charsMin, CMAX: c.charsMax }) },
    { role: "user", content: fill("【本章焦点】\n{{FOCUS}}\n\n【本卷大纲】\n{{VOLUME}}\n\n【当前世界状态】\n{{MEMORY}}",
        { FOCUS: focus, VOLUME: volText, MEMORY: memory }) },
  ], { temperature: 0.7, maxTokens: 1600 });
}

async function genDraft(env: Env, bookId: string, ch: number, outline: ChapterOutline, memory: string, tail: string, c: ReturnType<typeof cfg>, sp: string, openings: string): Promise<string> {
  let memorySlim = memory;
  const prefixRegex = /\n【全书前情提要（已压缩，长程主线记忆）】[\s\S]*?(?=\n【当前位面】)/;
  if (prefixRegex.test(memory)) {
    memorySlim = memory.replace(prefixRegex, '');
  }
  memorySlim = memorySlim.slice(0, 2000);

  const raw = await chat(env, [
    { role: "system", content: sp + fill(await tpl(env, bookId, "draft", PROMPT_DRAFT),
        { CH: ch, CMIN: c.charsMin, CMAX: c.charsMax, TITLE: outline.title, OPENINGS: openings }) },
    { role: "user", content: fill("【本章细纲】\n{{OUTLINE}}\n\n【当前关键角色状态】\n{{MEMORY}}\n\n【上一章结尾】\n{{TAIL}}",
        { OUTLINE: JSON.stringify(outline), MEMORY: memorySlim, TAIL: tail }) },
  ], { temperature: 0.85, maxTokens: 6000 });
  return raw.text;
}

async function polish(env: Env, bookId: string, ch: number, draft: string, memory: string, c: ReturnType<typeof cfg>, sp: string): Promise<string> {
  const raw = await chat(env, [
    { role: "system", content: sp + fill(await tpl(env, bookId, "polish", PROMPT_POLISH), { CH: ch, CMIN: c.charsMin, CMAX: c.charsMax }) },
    { role: "user", content: fill("【初稿】\n{{DRAFT}}\n\n【当前世界状态】\n{{MEMORY}}", { DRAFT: draft, MEMORY: memory }) },
  ], { temperature: 0.6, maxTokens: 6000 });
  return raw.text || draft;
}

async function extractDelta(env: Env, bookId: string, ch: number, text: string, memory: string, sp: string): Promise<StateDelta> {
  const d = await chatJSON<StateDelta>(env, [
    { role: "system", content: sp + fill(await tpl(env, bookId, "update", PROMPT_UPDATE), { CH: ch }) },
    { role: "user", content: fill("【本章定稿】\n{{TEXT}}\n\n【当前世界状态】\n{{MEMORY}}", { TEXT: text, MEMORY: memory }) },
  ], { temperature: 0.2, maxTokens: 2000 });
  d.characters ??= []; d.foreshadow_new ??= []; d.foreshadow_update ??= [];
  d.plot ??= {}; d.tags ??= []; d.summary ??= "";
  return d;
}

async function applyDelta(env: Env, bookId: string, ch: number, d: StateDelta, before: Map<string, import("./types").CharacterState>) {
  for (const cu of d.characters) {
    if (!cu.name) continue;
    const prev = before.get(cu.name);
    const isUp = typeof cu.realm_index === "number" && prev && cu.realm_index > prev.realm_index;
    const hasAsset = typeof cu.spirit_stones_delta === "number" || cu.add_pills?.length || cu.add_materials?.length;
    
    await M.upsertCharacter(env, bookId, {
      name: cu.name,
      ...(typeof cu.realm_index === "number" ? { realm_index: cu.realm_index } : {}),
      ...(cu.realm_name ? { realm_name: cu.realm_name } : {}),
      ...(typeof cu.realm_sub === "number" ? { realm_sub: cu.realm_sub } : {}),
      ...(typeof cu.alive === "boolean" ? { alive: cu.alive } : {}),
      ...(cu.relations ? { relations: cu.relations } : {}),
      ...(cu.status_notes ? { status_notes: cu.status_notes } : {}),
      last_seen_ch: ch,
      ...(isUp ? { last_breakthrough_ch: ch } : {}),
      ...(cu.add_techniques?.length ? { techniques: cu.add_techniques } : {}),
      ...(cu.add_movement_arts?.length ? { movement_arts: cu.add_movement_arts } : {}),
      ...(cu.add_artifacts?.length ? { artifacts: cu.add_artifacts } : {}),
      ...(hasAsset ? { assets: {
        spirit_stones: cu.spirit_stones_delta ?? 0,
        pills: cu.add_pills ?? [], materials: cu.add_materials ?? [], misc: [],
      } } : {}),
      // 【新增】动态更新人物性格和口癖
      ...(cu.personality_traits ? { personality_traits: cu.personality_traits } : {}),
      ...(cu.speech_pattern ? { speech_pattern: cu.speech_pattern } : {}),
    });
  }
  if (d.plane_change) {
    await env.DB.prepare("UPDATE books SET current_plane=?, updated_at=? WHERE id=?")
      .bind(d.plane_change, Date.now(), bookId).run();
  }
  for (const f of d.foreshadow_new) {
    if (f.title) await M.addForeshadow(env, bookId, { ...f, planted_ch: ch });
  }
  for (const f of d.foreshadow_update) {
    if (f.title) await M.updateForeshadowByTitle(env, bookId, f.title, f.status, ch);
  }
  if (d.plot.main_node) await M.setPlot(env, bookId, "main_node", d.plot.main_node);
  if (d.plot.explored_map_add?.length) {
    const cur: string[] = (await M.getPlot(env, bookId, "explored_map")) || [];
    await M.setPlot(env, bookId, "explored_map", Array.from(new Set([...cur, ...d.plot.explored_map_add])));
  }
  if (d.plot.open_threads?.length) {
    const cur: string[] = (await M.getPlot(env, bookId, "open_threads")) || [];
    await M.setPlot(env, bookId, "open_threads", Array.from(new Set([...cur, ...d.plot.open_threads])).slice(-50));
  }
}

function stripLeadingTitle(t: string): string {
  const lines = t.replace(/\r\n/g, "\n").split("\n");
  let i = 0;
  while (i < lines.length && lines[i].trim() === "") i++;
  if (i < lines.length && /^第\s*[\d〇零一二三四五六七八九十百千两]+\s*章/.test(lines[i].trim())) {
    i++;
  }
  return lines.slice(i).join("\n");
}

// 【核心修正】绝对保护“未完待续”等人类结尾收尾，只删除 AI 生成时的占位符废话
export function normalizeText(t: string): string {
  let s = t
    .replace(/\r\n/g, "\n")
    .replace(/```[a-z]*\n?|```/gi, "")
    .replace(/^#{1,6}\s+/gm, "")
    .replace(/^[-*]{3,}\s*$/gm, "")
    .replace(/[ \t]+\n/g, "\n");
    
  // 只过滤掉“作者的话”、“占位符”、“TODO”等确凿AI遗留物
  const junk = /^\s*[（(【\[]?\s*(作者的话|作者[：:].*|PS[：:].*|注[：:].*|TODO.*|\[.*待补充.*\]|\[.*此处.*\])\s*[）)】\]]?\s*$/i;
  s = s.split("\n").filter((line) => !junk.test(line.trim())).join("\n");
  
  return s
    .split(/\n+/).map((p) => p.trim()).filter(Boolean).join("\n")
    .replace(/^[ \t]+/gm, "")
    .trim();
}
