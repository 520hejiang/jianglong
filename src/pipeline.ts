// ============================================================================
// 多 Agent 流水线：读取记忆 -> 提取焦点 -> 细纲 -> 审核 -> 正文 -> 润色质检 -> 更新记忆
// 一次 generateChapter 完整产出并落库一章。
// ============================================================================
import type { Env, Book, ChapterOutline, StateDelta } from "./types";
import { cfg, DEFAULT_POWER_RANKS } from "./config";
import { chat, parseJson } from "./llm";
import * as M from "./memory";
import { validateDelta, hasBlocking, formatIssues } from "./validators";
import {
  PROMPT_EXTRACT, PROMPT_OUTLINE, PROMPT_REVIEW, PROMPT_DRAFT, PROMPT_POLISH, PROMPT_UPDATE,
} from "./prompts";

// 允许控制台覆盖默认模板
async function tpl(env: Env, bookId: string, name: string, fallback: string): Promise<string> {
  const row = await env.DB.prepare(
    "SELECT template FROM prompts WHERE name=? AND (id=? OR id=?) ORDER BY scope DESC LIMIT 1"
  ).bind(name, `${bookId}:${name}`, `global:${name}`).first<{ template: string }>();
  return row?.template || fallback;
}

const fill = (t: string, vars: Record<string, string | number>) =>
  t.replace(/\{\{(\w+)\}\}/g, (_, k) => String(vars[k] ?? ""));

export interface ChapterResult {
  chapterNo: number;
  title: string;
  wordCount: number;
  issues: string[];
}

export async function generateChapter(env: Env, bookId: string, chapterNo: number, version = 1): Promise<ChapterResult> {
  const c = cfg(env);
  const book = await M.getBook(env, bookId);
  if (!book) throw new Error(`book not found: ${bookId}`);
  const vol = M.volumeForChapter(book, chapterNo);
  const volText = vol ? JSON.stringify(vol) : (book.master_outline || "（无卷纲，依据总纲推进）");

  // 本书自定义文风（向导/控制台可设），优先级最高，叠加在通用铁律之上
  const stylePrefix = book.style_prompt_override
    ? `【本书特别文风/设定要求（优先级最高，与下列通用铁律冲突时以此为准）】\n${book.style_prompt_override}\n\n`
    : "";

  // ---------- 0. 读取记忆，编译上下文 ----------
  const chars = await M.loadCharacters(env, bookId);
  const fores = await M.openForeshadowing(env, bookId);
  const mainNode = await M.getPlot(env, bookId, "main_node");
  const exploredMap: string[] = (await M.getPlot(env, bookId, "explored_map")) || [];
  const last = await M.lastChapter(env, bookId);

  const charMap = new Map(chars.map((x) => [x.name, x]));

  // ---------- 1. 焦点提取 ----------
  const baseMemoryNoRetrieval = M.compileMemoryContext({
    chars, fores, mainNode, exploredMap, relevant: [],
    lastSummary: last?.summary || "", lastTail: last?.ending_tail || "",
  });

  const extractRaw = await chat(env, [
    { role: "system", content: stylePrefix + fill(await tpl(env, bookId, "extract", PROMPT_EXTRACT), { CH: chapterNo }) },
    { role: "user", content: fill("【本卷大纲】\n{{VOLUME}}\n\n【当前世界状态】\n{{MEMORY}}", { VOLUME: volText, MEMORY: baseMemoryNoRetrieval }) },
  ], { temperature: 0.4, maxTokens: 800, json: true });

  let focus: any = {};
  try { focus = parseJson(extractRaw.text); } catch { focus = { must_use_entities: [] }; }
  await M.log(env, { bookId, chapterNo, stage: "extract", message: `focus: ${focus.focus || "-"}`, meta: focus });

  // 基于焦点实体做"无 Vectorize 的记忆检索"
  const relevant = await M.retrieveRelevant(env, bookId, focus.must_use_entities || [], 5);
  let memory = M.compileMemoryContext({
    chars, fores, mainNode, exploredMap, relevant,
    lastSummary: last?.summary || "", lastTail: last?.ending_tail || "",
  });

  // ---------- 2. 单章细纲 ----------
  let outline = await genOutline(env, bookId, chapterNo, volText, memory, JSON.stringify(focus), c, stylePrefix);

  // ---------- 3. 审核（最多打回 maxReviewLoop 次） ----------
  const overdue = fores.filter((f) => f.due_ch && chapterNo > f.due_ch)
    .map((f) => `「${f.title}」(建议第${f.due_ch}章前)`).join("；") || "（无）";

  for (let i = 0; i < c.maxReviewLoop; i++) {
    const reviewRaw = await chat(env, [
      { role: "system", content: stylePrefix + fill(await tpl(env, bookId, "review", PROMPT_REVIEW), { CH: chapterNo }) },
      { role: "user", content: fill("【待审细纲】\n{{OUTLINE}}\n\n【当前世界状态】\n{{MEMORY}}\n\n【超期伏笔提醒】\n{{OVERDUE}}",
          { OUTLINE: JSON.stringify(outline), MEMORY: memory, OVERDUE: overdue }) },
    ], { temperature: 0.3, maxTokens: 2000, json: true });
    let review: any;
    try { review = parseJson(reviewRaw.text); } catch { break; }
    if (review.approved) break;
    await M.log(env, { bookId, chapterNo, level: "warn", stage: "review", message: `细纲打回: ${(review.issues || []).join("; ")}` });
    if (review.revised_outline) outline = review.revised_outline as ChapterOutline;
  }

  // ---------- 4. 正文生成 + 5. 润色质检 + 硬校验（不过则重写） ----------
  let finalText = "";
  let delta: StateDelta | null = null;
  let issuesText: string[] = [];

  for (let attempt = 0; attempt < c.maxRewrite; attempt++) {
    const draft = await genDraft(env, bookId, chapterNo, outline, memory, last?.ending_tail || "", c, stylePrefix);
    finalText = await polish(env, bookId, chapterNo, draft, memory, c, stylePrefix);

    // 抽取状态增量
    delta = await extractDelta(env, bookId, chapterNo, finalText, memory, stylePrefix);

    // 硬规则校验
    const issues = validateDelta(charMap, delta, fores, chapterNo);
    issuesText = issues.map((x) => `[${x.level}] ${x.rule}: ${x.detail}`);
    if (!hasBlocking(issues)) break;

    await M.log(env, { bookId, chapterNo, level: "warn", stage: "polish",
      message: `质检未过(尝试${attempt + 1}): ${formatIssues(issues)}` });
    // 把违规反馈进 memory，提示下一次重写规避
    memory += `\n\n【上一次生成违反了以下硬规则，本次务必修正】\n${formatIssues(issues)}`;
  }

  if (!delta) throw new Error("delta 抽取失败");

  // ---------- 6. 更新记忆库（落库 + 应用增量） ----------
  const cleaned = normalizeText(finalText);
  const title = (focus && outline?.title) || `第${chapterNo}章`;
  const wc = cleaned.replace(/\s/g, "").length;

  await M.saveChapter(env, bookId, {
    chapter_no: chapterNo,
    title: outline.title || `第${chapterNo}章`,
    outline: JSON.stringify(outline),
    content: cleaned,
    summary: delta.summary || "",
    ending_tail: cleaned.slice(-320),
    tags: delta.tags || [],
    word_count: wc,
    version,
    qc_report: JSON.stringify({ issues: issuesText }),
  });

  await applyDelta(env, bookId, chapterNo, delta);

  // 推进 book 进度
  await env.DB.prepare(
    "UPDATE books SET next_chapter=?, total_chars=total_chars+?, cursor_volume=?, updated_at=? WHERE id=?"
  ).bind(chapterNo + 1, wc, vol?.vol ?? book.cursor_volume, Date.now(), bookId).run();

  // 是否完结
  if (book.target_chapters && chapterNo >= book.target_chapters) {
    await M.setBookStatus(env, bookId, "finished");
  }

  await M.log(env, { bookId, chapterNo, stage: "update", message: `第${chapterNo}章完成，${wc}字`,
    meta: { wc, issues: issuesText } });

  return { chapterNo, title: outline.title || title, wordCount: wc, issues: issuesText };
}

// ---------------- 各阶段封装 ----------------
async function genOutline(env: Env, bookId: string, ch: number, volText: string, memory: string, focus: string, c: ReturnType<typeof cfg>, sp: string): Promise<ChapterOutline> {
  const raw = await chat(env, [
    { role: "system", content: sp + fill(await tpl(env, bookId, "outline", PROMPT_OUTLINE), { CH: ch, CMIN: c.charsMin, CMAX: c.charsMax }) },
    { role: "user", content: fill("【本章焦点】\n{{FOCUS}}\n\n【本卷大纲】\n{{VOLUME}}\n\n【当前世界状态】\n{{MEMORY}}",
        { FOCUS: focus, VOLUME: volText, MEMORY: memory }) },
  ], { temperature: 0.7, maxTokens: 1600, json: true });
  return parseJson<ChapterOutline>(raw.text);
}

async function genDraft(env: Env, bookId: string, ch: number, outline: ChapterOutline, memory: string, tail: string, c: ReturnType<typeof cfg>, sp: string): Promise<string> {
  const raw = await chat(env, [
    { role: "system", content: sp + fill(await tpl(env, bookId, "draft", PROMPT_DRAFT),
        { CH: ch, CMIN: c.charsMin, CMAX: c.charsMax, TITLE: outline.title }) },
    { role: "user", content: fill("【本章细纲】\n{{OUTLINE}}\n\n【当前世界状态】\n{{MEMORY}}\n\n【上一章结尾】\n{{TAIL}}",
        { OUTLINE: JSON.stringify(outline), MEMORY: memory, TAIL: tail }) },
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
  const raw = await chat(env, [
    { role: "system", content: sp + fill(await tpl(env, bookId, "update", PROMPT_UPDATE), { CH: ch }) },
    { role: "user", content: fill("【本章定稿】\n{{TEXT}}\n\n【当前世界状态】\n{{MEMORY}}", { TEXT: text, MEMORY: memory }) },
  ], { temperature: 0.2, maxTokens: 2000, json: true });
  const d = parseJson<StateDelta>(raw.text);
  // 兜底字段
  d.characters ??= []; d.foreshadow_new ??= []; d.foreshadow_update ??= [];
  d.plot ??= {}; d.tags ??= []; d.summary ??= "";
  return d;
}

async function applyDelta(env: Env, bookId: string, ch: number, d: StateDelta) {
  for (const cu of d.characters) {
    if (!cu.name) continue;
    await M.upsertCharacter(env, bookId, {
      name: cu.name,
      ...(typeof cu.realm_index === "number" ? { realm_index: cu.realm_index } : {}),
      ...(cu.realm_name ? { realm_name: cu.realm_name } : {}),
      ...(typeof cu.realm_sub === "number" ? { realm_sub: cu.realm_sub } : {}),
      ...(typeof cu.alive === "boolean" ? { alive: cu.alive } : {}),
      ...(cu.relations ? { relations: cu.relations } : {}),
      ...(cu.status_notes ? { status_notes: cu.status_notes } : {}),
      last_seen_ch: ch,
      // techniques / artifacts 走"追加并去重"
      ...(cu.add_techniques?.length ? { techniques: cu.add_techniques } : {}),
      ...(cu.add_artifacts?.length ? { artifacts: cu.add_artifacts } : {}),
    });
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

// ---------------- 排版规整：保证段间空行、去除多余空白 ----------------
export function normalizeText(t: string): string {
  return t
    .replace(/\r\n/g, "\n")
    .replace(/[ \t]+\n/g, "\n")
    .split(/\n{2,}/).map((p) => p.trim()).filter(Boolean).join("\n\n")
    .replace(/^[ \t]+/gm, "")
    .trim();
}
