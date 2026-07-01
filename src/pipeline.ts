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
  // 【绝对修复】：用显式字符串拼接代替 `${}`，无论什么不可见字符都不会再报错
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
      const issues: any[] = validateDelta(charMap, delta, fores, {
        chapterNo: ch, planes, currentPlane,
        minBreakthroughGap: c.minBreakthroughGap, assetSurgeFactor: c.assetSurgeFactor,
      }) as any[];

      // =========================================================================
      // 【核心安全墙】：绝对资产防穿透与指数级境界突破拦截
      // =========================================================================
      const heroName = chars.find(c => c.role === 'protagonist')?.name;
      for (const cu of delta.characters) {
        if (!cu.name) continue;
        const prev = charMap.get(cu.name);
        if (prev) {
          // 1. 灵石防穿透：LLM算错账扣成负数，直接算致命错误(Fatal)打回重写
          if (typeof cu.spirit_stones_delta === 'number') {
            const newBalance = (prev.assets?.spirit_stones || 0) + cu.spirit_stones_delta;
            if (newBalance < 0) {
              issues.push({ level: 'error', rule: '资产穿透', detail: `${cu.name} 灵石变动 ${cu.spirit_stones_delta} 会导致余额为负 (${newBalance})，绝不允许。` });
            }
          }
          // 2. 指数级境界防崩：替换原有的死板线性限制
          if (cu.breakthrough || (cu.realm_index && cu.realm_index > prev.realm_index)) {
            const baseGap = c.minBreakthroughGap;
            const dynamicGap = Math.floor(baseGap * Math.pow(1.5, prev.realm_index || 0));
            const chaptersSince = ch - (prev.last_breakthrough_ch || 0);
            
            // 如果是主角，严格执行指数级门槛拦截
            if (cu.name === heroName && chaptersSince < dynamicGap) {
              issues.push({ level: 'error', rule: '节奏过快', detail: `主角突破至下一大境界需沉淀 ${dynamicGap} 章，当前仅过 ${chaptersSince} 章，强制拦截！` });
            }
          }
        }
      }
      // =========================================================================

      const issuesText = issues.map((x) => `[${x.level}] ${x.rule}: ${x.detail}`);
      const hasFatal = issues.some(x => x.level === 'error'); // 捕捉我们自建的红线拦截

      if (!st.isRewrite && (hasFatal || hasBlocking(issues)) && st.attempt < c.maxRewrite - 1) {
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
  // 【核心修改】：原先的 slice(0, 2000) 极其致命，会把精心编译的世界状态、角色列表、甚至是“上一章结尾原文”全被腰斩！
  // 大幅放宽至 15000 字符，大模型上下文现在完全装得下，杜绝剧情跳跃。
  memorySlim = memorySlim.slice(0, 15000);

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