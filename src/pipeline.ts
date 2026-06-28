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
type Stage = "extract" | "outline" | "review" | "draft" | "polish" | "update" | "finalize" | "complete";

export interface GenState {
  chapterNo: number;
  version: number;
  stage: Stage;
  attempt: number;
  // 各步产物（存档到 plot_state，跨调用续传）
  focusJson?: string;
  memory?: string;
  openings?: string;
  lastTail?: string;
  outlineJson?: string;
  draft?: string;
  finalText?: string;
  deltaJson?: string;
  issues?: string[];
  // 完成时回填，供 result 使用
  title?: string;
  wc?: number;
}

const GENJOB_KEY = "__genjob";

// 执行当前阶段的一步，返回推进后的状态。每步只做一次（或极少次）LLM 调用，确保单次调用很短。
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
      const last = await M.lastChapter(env, bookId);
      const baseMem = M.compileMemoryContext({
        chars, fores, mainNode, exploredMap, relevant: [], currentPlane,
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
        chars, fores, mainNode, exploredMap, relevant, currentPlane,
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
      if (hasBlocking(issues) && st.attempt < c.maxRewrite - 1) {
        await M.log(env, { bookId, chapterNo: ch, level: "warn", stage: "update", message: `质检未过(尝试${st.attempt + 1})，回炉重写: ${formatIssues(issues)}` });
        // 回到 draft 重写，把违规反馈并入 memory
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
      await applyDelta(env, bookId, ch, delta, charMap);

      // 仅"向前生成"时推进 next_chapter；重写旧章不推进
      if (ch === book.next_chapter) {
        await env.DB.prepare(
          "UPDATE books SET next_chapter=?, total_chars=total_chars+?, cursor_volume=?, updated_at=? WHERE id=?"
        ).bind(ch + 1, wc, vol?.vol ?? book.cursor_volume, Date.now(), bookId).run();
      }
      if (book.target_chapters && ch >= book.target_chapters) await M.setBookStatus(env, bookId, "finished");
      await M.log(env, { bookId, chapterNo: ch, stage: "update", message: `第${ch}章完成，${wc}字`, meta: { wc, issues: issuesText } });
      return { ...st, stage: "complete", title, wc, issues: issuesText };
    }
    default:
      return { ...st, stage: "complete" };
  }
}

// 一口气生成一章（用于测试 / 付费队列等执行时长充足的环境）
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

/**
 * 断点续传式推进一本书（免费计划 / Cron 用）：在 budgetMs 时间预算内尽量多走几步，
 * 每完成一步就存档到 plot_state。被平台掐断也只丢失正在进行的那一步，下次从断点续。
 * @returns "completed" 完成一章 | "progress" 推进了但未完 | "idle" 没活干/被锁
 */
export async function advanceBook(env: Env, bookId: string, budgetMs = 18000): Promise<"completed" | "progress" | "idle"> {
  const start = Date.now();
  const got = await M.acquireLock(env, bookId, 120); // 短锁：被掐断后 2 分钟内自动解开续传
  if (!got) return "idle";
  try {
    const book = await M.getBook(env, bookId);
    if (!book || book.status !== "running") return "idle";
    if (book.target_chapters && book.next_chapter > book.target_chapters) {
      await M.setBookStatus(env, bookId, "finished");
      return "idle";
    }
    let st = (await M.getPlot(env, bookId, GENJOB_KEY)) as GenState | null;
    if (!st || !st.stage) {
      st = { chapterNo: book.next_chapter, version: 1, stage: "extract", attempt: 0 };
      await M.setPlot(env, bookId, GENJOB_KEY, st);
    }
    while (st.stage !== "complete" && Date.now() - start < budgetMs) {
      st = await runStep(env, bookId, st);
      await M.setPlot(env, bookId, GENJOB_KEY, st); // 每步存档
    }
    if (st.stage === "complete") {
      await M.setPlot(env, bookId, GENJOB_KEY, null); // 清空，下次开新章
      return "completed";
    }
    return "progress";
  } finally {
    await M.releaseLock(env, bookId);
  }
}

// ---------------- 各阶段封装 ----------------
async function genOutline(env: Env, bookId: string, ch: number, volText: string, memory: string, focus: string, c: ReturnType<typeof cfg>, sp: string): Promise<ChapterOutline> {
  return chatJSON<ChapterOutline>(env, [
    { role: "system", content: sp + fill(await tpl(env, bookId, "outline", PROMPT_OUTLINE), { CH: ch, CMIN: c.charsMin, CMAX: c.charsMax }) },
    { role: "user", content: fill("【本章焦点】\n{{FOCUS}}\n\n【本卷大纲】\n{{VOLUME}}\n\n【当前世界状态】\n{{MEMORY}}",
        { FOCUS: focus, VOLUME: volText, MEMORY: memory }) },
  ], { temperature: 0.7, maxTokens: 1600 });
}

async function genDraft(env: Env, bookId: string, ch: number, outline: ChapterOutline, memory: string, tail: string, c: ReturnType<typeof cfg>, sp: string, openings: string): Promise<string> {
  const raw = await chat(env, [
    { role: "system", content: sp + fill(await tpl(env, bookId, "draft", PROMPT_DRAFT),
        { CH: ch, CMIN: c.charsMin, CMAX: c.charsMax, TITLE: outline.title, OPENINGS: openings }) },
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
  const d = await chatJSON<StateDelta>(env, [
    { role: "system", content: sp + fill(await tpl(env, bookId, "update", PROMPT_UPDATE), { CH: ch }) },
    { role: "user", content: fill("【本章定稿】\n{{TEXT}}\n\n【当前世界状态】\n{{MEMORY}}", { TEXT: text, MEMORY: memory }) },
  ], { temperature: 0.2, maxTokens: 2000 });
  // 兜底字段
  d.characters ??= []; d.foreshadow_new ??= []; d.foreshadow_update ??= [];
  d.plot ??= {}; d.tags ??= []; d.summary ??= "";
  return d;
}

async function applyDelta(env: Env, bookId: string, ch: number, d: StateDelta, before: Map<string, import("./types").CharacterState>) {
  for (const cu of d.characters) {
    if (!cu.name) continue;
    const prev = before.get(cu.name);
    // 大境界突破 -> 记录本章为突破章，供节奏校验
    const isUp = typeof cu.realm_index === "number" && prev && cu.realm_index > prev.realm_index;
    // 家底增量（灵石净变化 + 丹药/材料增减），mergeAssets 负责累加与防负
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
      // 功法 / 身法神通 / 法宝 走"追加并去重"
      ...(cu.add_techniques?.length ? { techniques: cu.add_techniques } : {}),
      ...(cu.add_movement_arts?.length ? { movement_arts: cu.add_movement_arts } : {}),
      ...(cu.add_artifacts?.length ? { artifacts: cu.add_artifacts } : {}),
      ...(hasAsset ? { assets: {
        spirit_stones: cu.spirit_stones_delta ?? 0,
        pills: cu.add_pills ?? [], materials: cu.add_materials ?? [], misc: [],
      } } : {}),
    });
  }
  // 位面变更（飞升）-> 更新书的当前位面
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

// 去掉正文开头模型自己写的标题行（如"第12章 暗巷杀机"/"第十二章 …"），统一改由系统拼接
function stripLeadingTitle(t: string): string {
  const lines = t.replace(/\r\n/g, "\n").split("\n");
  let i = 0;
  while (i < lines.length && lines[i].trim() === "") i++;
  if (i < lines.length && /^第\s*[\d〇零一二三四五六七八九十百千两]+\s*章/.test(lines[i].trim())) {
    i++;
  }
  return lines.slice(i).join("\n");
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
