// ============================================================================
// 记忆库读写层（D1 + KV）
//   - 角色 / 剧情 / 伏笔 / 章节 的存取
//   - 不用 Vectorize：用 tags 关键词匹配做"相关历史检索"
//   - 上下文编译：把当前世界状态压成一段紧凑文本喂给 LLM
// ============================================================================
import type {
  Env, Book, CharacterState, Foreshadow, StateDelta, Volume, Assets,
  LoreEntry, LoreKind, GraphEdge, PowerRank,
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
    personality_traits: row.personality_traits ?? "", speech_pattern: row.speech_pattern ?? "",
    secrets: row.secrets ?? "", goals: row.goals ?? "",
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
       personality_traits=?, speech_pattern=?, secrets=?, goals=?,
       last_seen_ch=?, last_breakthrough_ch=?, updated_at=?
       WHERE book_id=? AND name=?`
    ).bind(
      J(merged.aliases), merged.role, merged.alive ? 1 : 0, merged.realm_index, merged.realm_name,
      merged.realm_sub, J(merged.techniques), J(merged.movement_arts), J(merged.artifacts),
      J(merged.assets), J(merged.relations), merged.status_notes,
      merged.personality_traits ?? "", merged.speech_pattern ?? "", merged.secrets ?? "", merged.goals ?? "",
      merged.last_seen_ch, merged.last_breakthrough_ch, now(), bookId, c.name
    ).run();
  } else {
    await env.DB.prepare(
      `INSERT INTO characters (id,book_id,name,aliases,role,alive,realm_index,realm_name,realm_sub,
       techniques,movement_arts,artifacts,assets,relations,status_notes,
       personality_traits,speech_pattern,secrets,goals,last_seen_ch,last_breakthrough_ch,updated_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      uid(), bookId, c.name, J(c.aliases ?? []), c.role ?? "npc", c.alive === false ? 0 : 1,
      c.realm_index ?? 0, c.realm_name ?? "", c.realm_sub ?? 0, J(c.techniques ?? []),
      J(c.movement_arts ?? []), J(c.artifacts ?? []), J(c.assets ?? emptyAssets()),
      J(c.relations ?? []), c.status_notes ?? "",
      c.personality_traits ?? "", c.speech_pattern ?? "", c.secrets ?? "", c.goals ?? "",
      c.last_seen_ch ?? 0, c.last_breakthrough_ch ?? 0, now()
    ).run();
  }
}

// ---------------- 设定卡（五层记忆·数据库层） ----------------
// 势力/地点/神器/神通/事件/世界规则各一类卡片；写入时按 (kind,name) upsert，
// detail 用最新的覆盖但保留首次出现章，保证"第 1 章的设定 2000 章后原样召回"。
export async function upsertLore(env: Env, bookId: string, e: {
  kind: LoreKind; name: string; detail: string; tags?: string[]; importance?: number; status?: string;
}, ch: number) {
  const existing = await env.DB.prepare(
    "SELECT id, tags, importance, first_ch FROM lore WHERE book_id=? AND kind=? AND name=?"
  ).bind(bookId, e.kind, e.name).first<any>();
  if (existing) {
    const tags = Array.from(new Set([...safeArr(existing.tags), ...(e.tags || [])]));
    await env.DB.prepare(
      "UPDATE lore SET detail=?, tags=?, last_ch=?, importance=?, status=?, updated_at=? WHERE id=?"
    ).bind(e.detail, J(tags), ch, Math.max(existing.importance ?? 2, e.importance ?? 2),
      e.status ?? "", now(), existing.id).run();
  } else {
    await env.DB.prepare(
      `INSERT INTO lore (id,book_id,kind,name,detail,tags,first_ch,last_ch,importance,status,updated_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(uid(), bookId, e.kind, e.name, e.detail, J(e.tags ?? []), ch, ch,
      e.importance ?? 2, e.status ?? "", now()).run();
  }
}

// 按实体名/标签召回设定卡：名字精确命中优先，其次标签命中；核心设定(importance=3)优先。
export async function relevantLore(env: Env, bookId: string, entities: string[], limit = 12): Promise<LoreEntry[]> {
  if (!entities.length) return [];
  const qs = entities.map(() => "?").join(",");
  const byName = await env.DB.prepare(
    `SELECT * FROM lore WHERE book_id=? AND name IN (${qs}) ORDER BY importance DESC LIMIT ?`
  ).bind(bookId, ...entities, limit).all<any>();
  const hits = new Map<string, any>((byName.results ?? []).map((r) => [r.id, r]));
  if (hits.size < limit) {
    // 标签匹配：LIKE 兜底（tags 是 JSON 数组文本，含实体名即命中）
    for (const ent of entities) {
      if (hits.size >= limit) break;
      const r = await env.DB.prepare(
        `SELECT * FROM lore WHERE book_id=? AND tags LIKE ? ORDER BY importance DESC, last_ch DESC LIMIT 4`
      ).bind(bookId, `%${ent}%`).all<any>();
      for (const row of r.results ?? []) if (hits.size < limit) hits.set(row.id, row);
    }
  }
  return Array.from(hits.values()).map((r) => ({ ...r, tags: safeArr(r.tags) })) as LoreEntry[];
}

// 大事记：最近的重大事件（kind=event），按发生章倒序，构成时间线
export async function recentEvents(env: Env, bookId: string, n = 8): Promise<LoreEntry[]> {
  const r = await env.DB.prepare(
    "SELECT * FROM lore WHERE book_id=? AND kind='event' ORDER BY first_ch DESC LIMIT ?"
  ).bind(bookId, n).all<any>();
  return (r.results ?? []).map((x) => ({ ...x, tags: safeArr(x.tags) })) as LoreEntry[];
}

// ---------------- 知识图谱 ----------------
export async function upsertEdges(env: Env, bookId: string, edges: { src: string; dst: string; rel: string; note?: string }[], ch: number) {
  for (const e of edges) {
    if (!e.src || !e.dst || !e.rel) continue;
    await env.DB.prepare(
      `INSERT INTO graph_edges (book_id,src,dst,rel,note,updated_ch,updated_at) VALUES (?,?,?,?,?,?,?)
       ON CONFLICT(book_id,src,dst,rel) DO UPDATE SET note=excluded.note, updated_ch=excluded.updated_ch, updated_at=excluded.updated_at`
    ).bind(bookId, e.src, e.dst, e.rel, e.note ?? "", ch, now()).run();
  }
}

// 取与给定实体直接相连的关系边（一跳邻居），写作前先查"他认识谁、恨谁、属于谁"
export async function edgesFor(env: Env, bookId: string, entities: string[], limit = 20): Promise<GraphEdge[]> {
  if (!entities.length) return [];
  const qs = entities.map(() => "?").join(",");
  const r = await env.DB.prepare(
    `SELECT * FROM graph_edges WHERE book_id=? AND (src IN (${qs}) OR dst IN (${qs}))
     ORDER BY updated_ch DESC LIMIT ?`
  ).bind(bookId, ...entities, ...entities, limit).all<any>();
  return (r.results ?? []) as GraphEdge[];
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
  // 【核心修改】：过滤掉冷宫(cold_storage)状态的伏笔，避免挤占单章 Token
  const r = await env.DB.prepare(
    "SELECT * FROM foreshadowing WHERE book_id=? AND status NOT IN ('resolved', 'dropped', 'cold_storage') ORDER BY importance DESC"
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

// 取最近 n 章的开头首句，喂给 draft 提示"别和这些雷同"，根治"每章开头都一样"
export async function recentOpenings(env: Env, bookId: string, n = 5): Promise<string[]> {
  const r = await env.DB.prepare(
    "SELECT content FROM chapters WHERE book_id=? AND status='done' ORDER BY chapter_no DESC LIMIT ?"
  ).bind(bookId, n).all<{ content: string }>();
  return (r.results ?? []).map((row) => {
    // content 形如 "第N章 标题\n\n正文..."，取正文首句（到第一个句末标点）
    const bodyStart = row.content.indexOf("\n\n");
    const body = bodyStart >= 0 ? row.content.slice(bodyStart + 2) : row.content;
    const firstLine = body.trim().split("\n")[0] || "";
    const m = firstLine.match(/^[^。！？…]{0,40}[。！？…]?/);
    return (m ? m[0] : firstLine).slice(0, 40);
  }).filter(Boolean);
}

// 🛡️【RAG 检索】倒排索引版：chapter_tags 表按标签直查相关章节号（索引级查询，
// 五百万字/几千章也不全表扫描），再取这些章的摘要按命中数排序。
// 补一层"最近 200 章摘要模糊匹配"兜底，覆盖老库标签未回填/标签口径不一的情况。
export async function retrieveRelevant(env: Env, bookId: string, tags: string[], limit = 5): Promise<{ chapter_no: number; summary: string }[]> {
  if (!tags.length) return [];
  const score = new Map<number, number>();
  // 1) 倒排索引精确命中（含第 1 章埋的伏笔，多少章后都能召回）
  const qs = tags.map(() => "?").join(",");
  const idx = await env.DB.prepare(
    `SELECT chapter_no, COUNT(*) c FROM chapter_tags WHERE book_id=? AND tag IN (${qs})
     GROUP BY chapter_no ORDER BY c DESC, chapter_no ASC LIMIT 30`
  ).bind(bookId, ...tags).all<{ chapter_no: number; c: number }>();
  for (const row of idx.results ?? []) score.set(row.chapter_no, row.c * 2);
  // 2) 近期章节摘要模糊匹配兜底（固定窗口，不随书变长而变慢）
  const recent = await env.DB.prepare(
    "SELECT chapter_no, summary, tags FROM chapters WHERE book_id=? AND status='done' ORDER BY chapter_no DESC LIMIT 200"
  ).bind(bookId).all<any>();
  for (const row of recent.results ?? []) {
    const t: string[] = safeArr(row.tags);
    const s = tags.reduce((acc, tag) => acc + (t.includes(tag) ? 2 : (row.summary || "").includes(tag) ? 1 : 0), 0);
    if (s > 0) score.set(row.chapter_no, Math.max(score.get(row.chapter_no) ?? 0, s));
  }
  const top = Array.from(score.entries()).sort((a, b) => b[1] - a[1]).slice(0, limit).map(([no]) => no);
  if (!top.length) return [];
  const qs2 = top.map(() => "?").join(",");
  const rows = await env.DB.prepare(
    `SELECT chapter_no, summary FROM chapters WHERE book_id=? AND status='done' AND chapter_no IN (${qs2})
     GROUP BY chapter_no`
  ).bind(bookId, ...top).all<{ chapter_no: number; summary: string }>();
  const byNo = new Map((rows.results ?? []).map((r) => [r.chapter_no, r.summary || ""]));
  return top.filter((no) => byNo.has(no)).map((no) => ({ chapter_no: no, summary: byNo.get(no)! }));
}

// 把本章标签写进倒排索引（saveChapter 时调用）
export async function indexChapterTags(env: Env, bookId: string, chapterNo: number, tags: string[]) {
  for (const tag of Array.from(new Set(tags)).slice(0, 16)) {
    if (!tag || !tag.trim()) continue;
    await env.DB.prepare(
      "INSERT OR IGNORE INTO chapter_tags (book_id,tag,chapter_no) VALUES (?,?,?)"
    ).bind(bookId, tag.trim(), chapterNo).run();
  }
}

// 老库标签回填：把已完成章节的 tags 批量灌进倒排索引（升级后跑一次即可）
export async function backfillChapterTags(env: Env, bookId: string): Promise<number> {
  const r = await env.DB.prepare(
    "SELECT chapter_no, tags FROM chapters WHERE book_id=? AND status='done'"
  ).bind(bookId).all<any>();
  let n = 0;
  for (const row of r.results ?? []) {
    const tags: string[] = safeArr(row.tags);
    if (tags.length) { await indexChapterTags(env, bookId, row.chapter_no, tags); n++; }
  }
  return n;
}

// 最近 n 章摘要（滚动短期记忆层，防止只看上一章导致中期剧情漂移）
export async function recentSummaries(env: Env, bookId: string, n = 10): Promise<{ chapter_no: number; summary: string }[]> {
  const r = await env.DB.prepare(
    "SELECT chapter_no, summary FROM chapters WHERE book_id=? AND status='done' ORDER BY chapter_no DESC LIMIT ?"
  ).bind(bookId, n).all<{ chapter_no: number; summary: string }>();
  return (r.results ?? []).reverse();
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
  await indexChapterTags(env, bookId, ch.chapter_no, ch.tags);
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

// ---------------- 境界显示 ----------------
// 大境界只分四档时(subLayers=4)用"初期/中期/后期/巅峰"，其余用"N层"（如练气九层）。
const STAGE4 = ["初期", "中期", "后期", "巅峰"];
export function formatRealmSub(ranks: PowerRank[] | undefined, realmIndex: number, sub: number): string {
  const rank = ranks?.find((r) => r.index === realmIndex);
  if (rank && rank.subLayers === 4) return STAGE4[Math.min(4, Math.max(1, sub)) - 1];
  if (rank && rank.subLayers === 1) return "";
  return `${sub}层`;
}
export function realmLadderText(ranks: PowerRank[] | undefined): string {
  if (!ranks?.length) return "";
  return ranks.map((r) =>
    `${r.name}(${r.subLayers === 4 ? "初/中/后/巅峰" : r.subLayers === 1 ? "唯一" : `1-${r.subLayers}层`})`
  ).join(" → ");
}

// ---------------- 上下文编译：分层记忆 ----------------
// 🛡️【核心防遗忘修复】：新增获取近期关键配角与地点的辅助函数（防止大模型在500万字后把同一个人名字记混）
function compileRecentSceneContext(chars: CharacterState[], relevant: { chapter_no: number; summary: string }[]): string {
  // 捞取最近 100 章内出场的配角（非主角），按出场时间倒序防止遗忘
  const recentSideChars = chars
    .filter(c => c.role !== 'protagonist' && c.alive && c.last_seen_ch > 0)
    .sort((a, b) => (b.last_seen_ch || 0) - (a.last_seen_ch || 0))
    .slice(0, 10)
    .map(c => `- ${c.name}（身份：${c.role}，境界：${c.realm_name}，上次出现于：第${c.last_seen_ch}章）`)
    .join('\n') || '（无近期出场配角）';

  // 尝试从历史摘要中提取出高频出现的“地点”，强塞进去，防主角在500万章后地名人名错乱
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
  lore?: LoreEntry[];                                    // 本章相关设定卡（势力/神器/神通/地点/规则）
  edges?: GraphEdge[];                                   // 本章相关关系网（知识图谱一跳邻居）
  events?: LoreEntry[];                                  // 近期大事记（时间线）
  recentSums?: { chapter_no: number; summary: string }[]; // 最近10章摘要（滚动短期记忆）
  powerRanks?: PowerRank[];                              // 本书境界体系（决定境界叫法：N层 或 初/中/后/巅峰）
  settlement?: string;                                   // 上一章收支结算单（代码生成的系统账）
}): string {
  const realmOf = (c: CharacterState) => `${c.realm_name}${formatRealmSub(p.powerRanks, c.realm_index, c.realm_sub)}`;
  // 截断函数：法宝、功法、丹药等永远只列前 15 个，防止上下文被堆爆
  const truncateList = (arr: any[], label: string): string => {
    if (!arr || arr.length === 0) return '无';
    const s = arr.slice(0, 15).map((t) => `${t.name}${t.layer !== undefined ? `(${t.layer}/${t.maxLayer}层)` : `[${t.grade || ''}]`}`).join('、');
    return s + (arr.length > 15 ? `，及其他 ${arr.length - 15} 种${label}` : '');
  };

  // 角色按"主角优先→最近出场优先"排序后封顶 25，长期不出场的路人自然被挤出（防膨胀）
  const charLines = p.chars
    .filter((c) => c.role === "protagonist" || c.alive)
    .sort((a, b) => (a.role === "protagonist" ? -1 : b.role === "protagonist" ? 1 : (b.last_seen_ch || 0) - (a.last_seen_ch || 0)))
    .slice(0, 25)
    .map((c) => {
      const persona = [
        c.personality_traits && `性格:${c.personality_traits}`,
        c.speech_pattern && `口癖:${c.speech_pattern}`,
        c.goals && `目标:${c.goals}`,
        c.secrets && `秘密:${c.secrets}`,
      ].filter(Boolean).join("｜");
      return `- ${c.name}${c.aliases.length ? `(${c.aliases.join("/")})` : ""}｜${c.role}｜${c.alive ? "在世" : "已死"}｜境界:${realmOf(c)}｜功法:${truncateList(c.techniques, '功法')}｜近况:${c.status_notes || "—"}${persona ? `｜${persona}` : ""}`;
    }).join("\n");

  // 主角全部身家单列（系统面板=唯一事实来源），带数量/耐久，前15种防膨胀
  const fmtCount = (arr?: { name: string; count: number }[]) =>
    arr?.length
      ? arr.slice(0, 15).map((x) => `${x.name}×${x.count}`).join("、") + (arr.length > 15 ? `，另有${arr.length - 15}种` : "")
      : "无";
  const hero = p.chars.find((c) => c.role === "protagonist");
  const heroAssets = hero ? (() => {
    const a = hero.assets || { spirit_stones: 0, pills: [], materials: [], misc: [] };
    const arts = hero.artifacts?.length
      ? hero.artifacts.slice(0, 15).map((x) => `${x.name}(${x.grade || "?"}·耐久${x.durability ?? "?"})`).join("、")
      : "无";
    const move = truncateList(hero.movement_arts || [], '身法/神通');
    const misc = a.misc?.length ? a.misc.slice(0, 15).join("、") : "无";
    return [
      `主角「${hero.name}」全部身家（系统面板·唯一事实来源）：`,
      `- 灵石：${a.spirit_stones} 块`,
      `- 丹药：${fmtCount(a.pills)}`,
      `- 材料：${fmtCount(a.materials)}`,
      `- 法宝/器物：${arts}`,
      `- 杂项：${misc}`,
      `- 身法/神通/秘术：${move}`,
      `【道具白名单硬规则】本章主角动用、消耗、"从怀里摸出"的任何丹药/法宝/符箓/材料/能力，必须出自上述清单，清单里没有的东西绝不存在；剧情需要新道具，必须先写清获得经过（缴获/购买/赠予/炼制）才能使用；消耗任何物品不得超过清单数量。`,
    ].join("\n");
  })() : "（无主角记录）";

  // 伏笔按重要度→建议回收章排序，封顶 20（S 级硬记忆只留最关键的）
  const foreLines = [...p.fores]
    .sort((a, b) => (b.importance - a.importance) || ((a.due_ch || 9e9) - (b.due_ch || 9e9)))
    .slice(0, 20)
    .map((f) => `- [${f.status}|重要度${f.importance}|建议第${f.due_ch}章前回收] ${f.title}：${f.detail}`)
    .join("\n");

  const relLines = p.relevant.map((r) => `- 第${r.chapter_no}章：${r.summary}`).join("\n");
  const map40 = (p.exploredMap || []).slice(-40);

  // 🛡️【核心防遗忘修复】：植入近期配角、近期地点、时间线进度，防大模型逻辑混淆
  const sceneContext = compileRecentSceneContext(p.chars, p.relevant);
  const progression = `【当前时间线】\n主角上次大境界突破于第 ${hero?.last_breakthrough_ch || 0} 章，当前处于 ${p.currentPlane || '凡界'}，主角境界 ${hero ? realmOf(hero) : '凡人'}`;
  const ladder = realmLadderText(p.powerRanks);

  // 设定卡：势力/神器/神通/地点/世界规则（按相关度检索出的本章会用到的卡）
  const kindLabel: Record<string, string> = {
    faction: "势力", location: "地点", artifact: "神器/法宝", technique: "神通/功法", event: "事件", worldrule: "世界规则",
  };
  const loreLines = (p.lore || [])
    .filter((l) => l.kind !== "event")
    .map((l) => `- [${kindLabel[l.kind] || l.kind}] ${l.name}${l.status ? `(${l.status})` : ""}：${(l.detail || "").slice(0, 160)}（首见第${l.first_ch}章）`)
    .join("\n");

  // 关系网：知识图谱一跳邻居，写之前先知道"谁认识谁、谁恨谁、谁属于哪"
  const edgeLines = (p.edges || [])
    .map((e) => `- ${e.src} —[${e.rel}]→ ${e.dst}${e.note ? `（${e.note}）` : ""}`)
    .join("\n");

  // 大事记：时间线层，事件带发生章与影响
  const eventLines = (p.events || [])
    .map((ev) => `- 第${ev.first_ch}章「${ev.name}」${ev.status ? `[${ev.status}]` : ""}：${(ev.detail || "").slice(0, 120)}`)
    .join("\n");

  // 最近10章摘要：滚动短期记忆，防中期剧情漂移
  const recentLines = (p.recentSums || [])
    .map((r) => `- 第${r.chapter_no}章：${(r.summary || "").slice(0, 100)}`)
    .join("\n");

  return [
    `【全书前情提要（已压缩，长程主线记忆）】\n${p.storyDigest || "（暂无，靠前章节）"}`,
    ladder ? `【境界体系（叫法硬口径：标"初/中/后/巅峰"的境界绝不用"N层"称呼，反之亦然）】\n${ladder}` : "",
    `【当前位面】${p.currentPlane || "（未设/凡界）"}`,
    `【主线进度】\n${p.mainNode ? JSON.stringify(p.mainNode) : "（起始）"}`,
    `【已探索地图/势力（近40）】\n${map40.join("、") || "（无）"}`,
    `【主角家底与已习得能力（硬约束·面板为准）】\n${heroAssets}`,
    p.settlement ? `【上一章收支结算（系统对账单·与本章衔接的账目起点）】\n${p.settlement}` : "",
    `【在世/关键角色状态（按活跃度，最多25）】\n${charLines || "（暂无）"}`,
    loreLines ? `【本章相关设定卡（硬设定·不得违背，神通克制关系以此为准）】\n${loreLines}` : "",
    edgeLines ? `【相关人物/势力关系网（知识图谱）】\n${edgeLines}` : "",
    eventLines ? `【大事记/时间线（近期重大事件及其影响）】\n${eventLines}` : "",
    `【未了结伏笔/因果（按重要度，最多20）】\n${foreLines || "（无）"}`,
    sceneContext,
    progression,
    `【相关历史剧情（按相关度检索）】\n${relLines || "（无）"}`,
    recentLines ? `【最近10章摘要（短期记忆，保持剧情连续）】\n${recentLines}` : "",
    `【上一章摘要】\n${p.lastSummary || "（这是第一章）"}`,
    `【上一章结尾原文（用于无缝衔接，勿重复其内容）】\n${p.lastTail || "（无）"}`,
  ].filter(Boolean).join("\n\n");
}

// ---------------- 全书前情提要压缩 ----------------
export async function updateStoryDigest(env: Env, bookId: string, uptoChapter: number, summarize: (oldDigest: string, recent: string) => Promise<string>): Promise<void> {
  const old = (await getPlot(env, bookId, "story_digest")) || "";
  
  const r = await env.DB.prepare(
    "SELECT chapter_no, summary FROM chapters WHERE book_id=? AND status='done' AND chapter_no<=? ORDER BY chapter_no DESC LIMIT 15"
  ).bind(bookId, uptoChapter).all<{ chapter_no: number; summary: string }>();
  
  const recent = (r.results ?? []).reverse().map((x) => `第${x.chapter_no}章：${x.summary}`).join("\n");
  if (!recent) return;
  
  try {
    // 确保 old 是纯字符串
    const oldStr = typeof old === 'string' ? old : JSON.stringify(old);
    const digest = await summarize(oldStr, recent);
    
    if (digest && digest.trim()) {
      // 【核心修改】：放宽 1200 字的死锁，提升到 3000，防止 LLM 过度删减早期主线
      const newDigest = digest.trim().slice(0, 3000); 
      await setPlot(env, bookId, "story_digest", newDigest);

      // 【核心修改】：分卷防遗忘机制（每 100 章强制打一个“记忆锚点”归档）
      if (uptoChapter > 0 && uptoChapter % 100 === 0) {
        const volumeNo = Math.floor(uptoChapter / 100);
        await setPlot(env, bookId, `volume_archive_${volumeNo}`, newDigest);
        console.log(`[卷宗归档] 第 ${volumeNo} 卷 (至第${uptoChapter}章) 核心提要已永久保存为 volume_archive_${volumeNo}`);
      }
    }
  } catch (error) { 
    console.error(`[StoryDigest Error] 第 ${uptoChapter} 章前情提要压缩失败:`, error); 
  }
}

// ---------------- 死线清理（自动归档过期伏笔） ----------------
export async function pruneDeadThreads(env: Env, bookId: string, chapterNo: number): Promise<void> {
  // 【核心修改】：过期的伏笔不再被 dropped 彻底抛弃，而是进入 cold_storage（冷宫）。
  // 防止修仙文动辄上千章的长线伏笔（如炼气期拿到的神秘断剑）被自动系统彻底抹杀。
  await env.DB.prepare(
    "UPDATE foreshadowing SET status='cold_storage', updated_at=? WHERE book_id=? AND status NOT IN ('resolved','dropped','cold_storage') AND importance<=2 AND due_ch IS NOT NULL AND ?-due_ch>100"
  ).bind(Date.now(), bookId, chapterNo).run();
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