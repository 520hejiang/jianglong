// ============================================================================
// 多 Agent 流水线：读取记忆 -> 提取焦点 -> 细纲 -> 审核 -> 正文 -> 润色质检 -> 更新记忆
// 一次 generateChapter 完整产出并落库一章。
// ============================================================================
import type { Env, Book, ChapterOutline, StateDelta, Plane, PowerRank } from "./types";
import { cfg, DEFAULT_PLANES, DEFAULT_POWER_RANKS } from "./config";
import { chat, parseJson, chatJSON } from "./llm";
import * as M from "./memory";
import { validateDelta, hasBlocking, formatIssues, detectSlop, detectLedgerLeaks, detectRealmMisnaming } from "./validators";
import {
  PROMPT_EXTRACT, PROMPT_OUTLINE, PROMPT_REVIEW, PROMPT_DRAFT, PROMPT_POLISH, PROMPT_EDITOR, PROMPT_UPDATE, PROMPT_DIGEST,
  PROMPT_JUDGE, PROMPT_DELTA_AUDIT, PROMPT_CONSISTENCY,
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
type Stage = "extract" | "outline" | "review" | "draft" | "draft2" | "judge" | "polish" | "editor" | "update" | "finalize" | "rewrite" | "complete";

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
  editorScore?: number;   // AI 主编终审评分
  editorNotes?: string[]; // 主编意见（存入质检报告）
  draftB?: string;        // 双稿择优的第二候选
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
  // 剧情坐标：告诉模型"现在写到全书哪一格"，配合卷界锁防止跳卷/抢跑
  const volText = vol
    ? `【当前剧情坐标】第${vol.vol}卷《${vol.title}》(第${vol.start_ch}-${vol.end_ch}章)｜本章是卷内第 ${ch - vol.start_ch + 1}/${vol.end_ch - vol.start_ch + 1} 章｜卷内进度约 ${Math.round(((ch - vol.start_ch + 1) / Math.max(1, vol.end_ch - vol.start_ch + 1)) * 100)}%\n${JSON.stringify(vol)}`
    : (book.master_outline || "（无卷纲，依据总纲推进）");
  const stylePrefix = book.style_prompt_override
    ? `【本书特别文风/设定要求（优先级最高，与下列通用铁律冲突时以此为准）】\n${book.style_prompt_override}\n\n`
    : "";
  const chars = await M.loadCharacters(env, bookId);
  const charMap = new Map(chars.map((x) => [x.name, x]));
  const fores = await M.openForeshadowing(env, bookId);
  const planes: Plane[] = book.planes ? safeParse<Plane[]>(book.planes, []) : DEFAULT_PLANES;
  const currentPlane = book.current_plane || planes[0]?.name || null;
  const powerRanks: PowerRank[] = book.power_system ? safeParse<PowerRank[]>(book.power_system, DEFAULT_POWER_RANKS) : DEFAULT_POWER_RANKS;

  switch (st.stage) {
    case "extract": {
      const mainNode = await M.getPlot(env, bookId, "main_node");
      const exploredMap: string[] = (await M.getPlot(env, bookId, "explored_map")) || [];
      const storyDigest: string = (await M.getPlot(env, bookId, "story_digest")) || "";
      const last = await M.lastChapter(env, bookId);
      const recentSums = await M.recentSummaries(env, bookId, 10);
      const events = await M.recentEvents(env, bookId, 8);
      const settlement: string = (await M.getPlot(env, bookId, "last_settlement")) || "";
      // 健康监控指令：上一章体检发现的问题（战斗过密/境界停滞/女主缺席…），注入本章后即清空
      const directives: string[] = (await M.getPlot(env, bookId, "health_todo")) || [];
      if (directives.length) {
        await M.setPlot(env, bookId, "health_todo", null);
        await M.log(env, { bookId, chapterNo: ch, stage: "extract", message: `注入健康监控指令 ${directives.length} 条`, meta: directives });
      }
      const baseMem = M.compileMemoryContext({
        chars, fores, mainNode, exploredMap, relevant: [], currentPlane, storyDigest,
        events, recentSums, powerRanks, settlement, directives,
        lastSummary: last?.summary || "", lastTail: last?.ending_tail || "",
      });
      let focus: any = {};
      try {
        focus = await chatJSON<any>(env, [
          { role: "system", content: stylePrefix + fill(await tpl(env, bookId, "extract", PROMPT_EXTRACT), { CH: ch }) },
          { role: "user", content: fill("【本卷大纲】\n{{VOLUME}}\n\n【当前世界状态】\n{{MEMORY}}", { VOLUME: volText, MEMORY: baseMem }) },
        ], { temperature: 0.4, maxTokens: 800 });
      } catch { focus = { must_use_entities: [] }; }
      focus.must_use_entities ??= [];
      await M.log(env, { bookId, chapterNo: ch, stage: "extract", message: `focus: ${focus.focus || "-"}`, meta: focus });
      // RAG：拿着本章焦点实体，先查倒排索引召回历史章节、再查设定卡与关系图谱，
      // 只喂"最相关的几 KB"而不是整本书——写第 1827 章时混沌剑的所有旧设定都在
      const entities: string[] = (focus.must_use_entities || []).filter((x: any) => typeof x === "string");
      const relevant = await M.retrieveRelevant(env, bookId, entities, 5);
      const lore = await M.relevantLore(env, bookId, entities, 12);
      const edges = await M.edgesFor(env, bookId, entities, 20);
      const memory = M.compileMemoryContext({
        chars, fores, mainNode, exploredMap, relevant, currentPlane, storyDigest,
        lore, edges, events, recentSums, powerRanks, settlement, directives,
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
        ], { temperature: 0.3, maxTokens: 2800, json: true }); // revised_outline 是完整细纲，上限要够
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
      const draft = await genDraft(env, bookId, ch, outline, st.memory!, st.lastTail || "", c, stylePrefix, st.openings || "", 0.85);
      // 双稿择优：重写回炉时不再双稿（回炉稿已带针对性意见），首written走 best-of-2
      return { ...st, stage: c.bestOf >= 2 && st.attempt === 0 ? "draft2" : "polish", draft };
    }
    // 第二候选稿：更高温度写一版风格更放开的，交给评委二选一
    case "draft2": {
      const outline = JSON.parse(st.outlineJson!) as ChapterOutline;
      const draftB = await genDraft(env, bookId, ch, outline, st.memory!, st.lastTail || "", c, stylePrefix, st.openings || "", 0.95);
      return { ...st, stage: "judge", draftB };
    }
    // AI 评委：两份候选按六维度硬性二选一，胜者进润色。评委故障→保守用A稿。
    case "judge": {
      try {
        const r = await chatJSON<any>(env, [
          { role: "system", content: fill(await tpl(env, bookId, "judge", PROMPT_JUDGE), { CH: ch }) },
          { role: "user", content: fill("【本章细纲】\n{{OUTLINE}}\n\n【候选A】\n{{A}}\n\n【候选B】\n{{B}}",
              { OUTLINE: st.outlineJson!, A: st.draft!, B: st.draftB || "" }) },
        ], { temperature: 0.2, maxTokens: 400 });
        const winner = r?.winner === "B" ? "B" : "A";
        await M.log(env, { bookId, chapterNo: ch, stage: "judge", message: `双稿择优: ${winner}胜｜${String(r?.reason || "").slice(0, 80)}` });
        return { ...st, stage: "polish", draft: winner === "B" ? st.draftB! : st.draft!, draftB: undefined };
      } catch (e) {
        await M.log(env, { bookId, chapterNo: ch, level: "warn", stage: "judge", message: `评委故障，保守采用A稿: ${String(e).slice(0, 100)}` });
        return { ...st, stage: "polish", draftB: undefined };
      }
    }
    case "polish": {
      const slop = detectSlop(st.draft!);
      const ledger = detectLedgerLeaks(st.draft!);
      const realmNaming = detectRealmMisnaming(st.draft!, powerRanks);
      const needPolish = c.polishMode === "always" || (c.polishMode === "auto" && (slop.hit || ledger.hit || realmNaming.hit || st.attempt > 0));
      let finalText = st.draft!;
      if (needPolish) {
        const reasons = [...slop.reasons, ...ledger.reasons, ...realmNaming.reasons];
        if (reasons.length) await M.log(env, { bookId, chapterNo: ch, stage: "polish", message: `触发润色: ${reasons.join("；")}` });
        finalText = await polish(env, bookId, ch, st.draft!, st.memory!, c, stylePrefix);
        // 润色后复检账本泄漏：仍有总余额表述则代码兜底改写成模糊表达，绝不让错误总数上架
        const recheck = detectLedgerLeaks(finalText);
        if (recheck.hit) {
          finalText = finalText.replace(
            /(还剩|只剩|仅剩|尚余|共有|一共|总共|全部家当)[^。！？\n]{0,12}?[\d一二两三四五六七八九十百千]+\s*[块枚颗粒]\s*[下中上极品]{0,2}\s*灵[石晶]/g,
            "摸了摸干瘪的钱袋");
          await M.log(env, { bookId, chapterNo: ch, level: "warn", stage: "polish", message: "润色后仍报灵石总余额，已代码兜底改写为模糊表述" });
        }
      }
      return { ...st, stage: "editor", finalText };
    }
    // AI 主编终审：评分+硬伤扫描。硬伤或低于及格线→带着主编意见回炉重写；
    // 通过→意见与评分随质检报告归档。主编自身故障不阻塞主流程（降级跳过）。
    case "editor": {
      if (c.editorMode === "off") return { ...st, stage: "update" };
      try {
        const r = await chatJSON<any>(env, [
          { role: "system", content: stylePrefix + fill(await tpl(env, bookId, "editor", PROMPT_EDITOR), { CH: ch, BAR: c.qualityBar }) },
          { role: "user", content: fill("【本章定稿】\n{{TEXT}}\n\n【本章细纲】\n{{OUTLINE}}\n\n【当前世界状态（对照查矛盾）】\n{{MEMORY}}",
              { TEXT: st.finalText!, OUTLINE: st.outlineJson!, MEMORY: st.memory! }) },
        ], { temperature: 0.2, maxTokens: 1800 });
        const score = typeof r.score === "number" && Number.isFinite(r.score) ? Math.round(r.score) : 80;
        const fatal: string[] = Array.isArray(r.fatal_issues) ? r.fatal_issues.map((x: any) => String(x)) : [];
        const advice: string[] = Array.isArray(r.advice) ? r.advice.map((x: any) => String(x)) : [];
        await M.log(env, { bookId, chapterNo: ch, stage: "editor", message: `主编评分 ${score}分${fatal.length ? `｜硬伤${fatal.length}条` : ""}`, meta: { score, fatal, advice } });
        const needRewrite = (fatal.length > 0 || score < c.qualityBar) && !st.isRewrite && st.attempt < c.maxRewrite - 1;
        if (needRewrite) {
          const fb = [...fatal.map((x) => `[硬伤] ${x}`), ...advice].slice(0, 8).map((x) => `- ${x}`).join("\n");
          await M.log(env, { bookId, chapterNo: ch, level: "warn", stage: "editor", message: `主编打回(评分${score})，第${st.attempt + 1}次回炉` });
          return { ...st, stage: "draft", attempt: st.attempt + 1, memory: st.memory! + `\n\n【主编终审打回意见（本次重写必须逐条执行）】\n${fb}` };
        }
        return { ...st, stage: "update", editorScore: score, editorNotes: [...fatal, ...advice].slice(0, 6) };
      } catch (e) {
        await M.log(env, { bookId, chapterNo: ch, level: "warn", stage: "editor", message: `主编审稿失败已跳过: ${String(e).slice(0, 150)}` });
        return { ...st, stage: "update" };
      }
    }
    case "update": {
      let delta = await extractDelta(env, bookId, ch, st.finalText!, st.memory!, stylePrefix);

      // 【抽取二次审计】AI 对照正文复核账目/道具/境界字段：漏记的消耗补上、
      // 幽灵登记删掉、凭空流水剔除。审计故障→用原始抽取结果，不阻塞。
      if (c.deltaAudit === "on") {
        try {
          const audited = await chatJSON<StateDelta>(env, [
            { role: "system", content: fill(await tpl(env, bookId, "audit", PROMPT_DELTA_AUDIT), { CH: ch }) },
            { role: "user", content: fill("【本章定稿】\n{{TEXT}}\n\n【待审状态增量】\n{{DELTA}}\n\n【当前世界状态（面板对照）】\n{{MEMORY}}",
                { TEXT: st.finalText!, DELTA: JSON.stringify(delta), MEMORY: st.memory! }) },
          ], { temperature: 0.1, maxTokens: 3200 });
          if (audited && Array.isArray(audited.characters)) {
            audited.characters ??= []; audited.foreshadow_new ??= []; audited.foreshadow_update ??= [];
            audited.lore ??= []; audited.edges ??= []; audited.plot ??= {}; audited.tags ??= []; audited.summary ??= delta.summary;
            for (const cu of audited.characters) {
              if (Array.isArray(cu.stone_moves) && cu.stone_moves.length) {
                cu.spirit_stones_delta = cu.stone_moves.reduce(
                  (acc, m) => acc + (typeof m?.amount === "number" && Number.isFinite(m.amount) ? Math.trunc(m.amount) : 0), 0);
              }
            }
            delta = audited;
            await M.log(env, { bookId, chapterNo: ch, stage: "audit", message: "状态增量已通过二次审计" });
          }
        } catch (e) {
          await M.log(env, { bookId, chapterNo: ch, level: "warn", stage: "audit", message: `增量审计故障，采用原始抽取: ${String(e).slice(0, 100)}` });
        }
      }

      // 【境界序号权没收】realm_index 由代码按境界名推导，模型报错也无效：
      // 模型常把"练气一层→二层"误报成大境界+1，触发误拦截。规则：
      //   - 给了境界名 → 序号=境界体系表里该名的序号（模型给的序号作废）
      //   - 没给境界名 → 大境界序号一律保持不变（升层只动 realm_sub）
      //   - breakthrough 标记只在大境界真正提升时才生效
      const coerced: string[] = [];
      for (const cu of delta.characters) {
        const prev = charMap.get(cu.name);
        if (cu.realm_name) {
          const rk = powerRanks.find((r) => r.name === cu.realm_name)
            || powerRanks.find((r) => cu.realm_name!.includes(r.name));
          if (rk) {
            if (typeof cu.realm_index === "number" && cu.realm_index !== rk.index) {
              coerced.push(`${cu.name}: 境界名「${cu.realm_name}」→序号${rk.index}(模型误报${cu.realm_index})`);
            }
            cu.realm_index = rk.index;
            cu.realm_name = rk.name;
          }
        } else if (prev && typeof cu.realm_index === "number" && cu.realm_index !== prev.realm_index) {
          coerced.push(`${cu.name}: 未给境界名，序号${cu.realm_index}作废，保持${prev.realm_index}`);
          cu.realm_index = prev.realm_index;
        }
        if (cu.breakthrough && prev && !(typeof cu.realm_index === "number" && cu.realm_index > prev.realm_index)) {
          cu.breakthrough = false; // 升小层不是大境界突破
        }
      }
      if (coerced.length) {
        await M.log(env, { bookId, chapterNo: ch, level: "warn", stage: "update", message: `境界序号已由代码矫正: ${coerced.join("；")}` });
      }

      const issues: any[] = validateDelta(charMap, delta, fores, {
        chapterNo: ch, planes, currentPlane,
        minBreakthroughGap: c.minBreakthroughGap, assetSurgeFactor: c.assetSurgeFactor,
      }) as any[];

      // =========================================================================
      // 【核心安全墙】：绝对资产防穿透 + 境界突破"随剧情"拦截
      // =========================================================================
      const outlineForCheck = JSON.parse(st.outlineJson!) as ChapterOutline;
      const heroName = chars.find(x => x.role === 'protagonist')?.name;
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
          // 2. 境界突破随剧情走：细纲统筹安排(breakthrough_due)或正文有明确契机铺垫的突破放行；
          //    未经细纲规划的"顿悟白给"才按指数级门槛拦截。首次突破(尚无记录)不误杀。
          if (cu.breakthrough || (cu.realm_index && cu.realm_index > prev.realm_index)) {
            const plannedByOutline = !!outlineForCheck.breakthrough_due
              || /突破|晋阶|晋升|进阶|结丹|筑基|凝婴|破境/.test(outlineForCheck.goal || "")
              || (outlineForCheck.foreshadow_resolve || []).some(t => /突破|瓶颈|晋阶|契机/.test(t));
            const baseGap = c.minBreakthroughGap;
            const dynamicGap = Math.floor(baseGap * Math.pow(1.5, prev.realm_index || 0));
            const chaptersSince = ch - (prev.last_breakthrough_ch || 0);

            if (cu.name === heroName && prev.last_breakthrough_ch > 0 && !plannedByOutline && chaptersSince < dynamicGap) {
              issues.push({ level: 'error', rule: '节奏过快', detail: `主角突破未经细纲规划且距上次仅 ${chaptersSince} 章（参考沉淀 ${dynamicGap} 章），疑似廉价顿悟，强制拦截！若剧情确需突破，应先在细纲 breakthrough_due 中统筹。` });
            } else if (cu.name === heroName && plannedByOutline && chaptersSince < Math.max(3, Math.floor(baseGap / 4))) {
              // 剧情规划的突破也不能背靠背：距上次突破不足 baseGap/4 章仍视为膨胀
              issues.push({ level: 'error', rule: '节奏过快', detail: `主角距上次突破仅 ${chaptersSince} 章又要突破，哪怕剧情安排也过密，强制拦截。` });
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
      // 先 normalize 剥掉 Markdown 井号/围栏，再剥标题行（此前顺序反了，"## 第N章"逃过剥离导致正文标题重复），最后整章去重
      const body = dedupeChapter(stripLeadingTitle(normalizeText(st.finalText!)), ch);
      const cleaned = `第${ch}章 ${title}\n\n${body}`;
      const wc = body.replace(/\s/g, "").length;
      const issuesText = [...(st.issues || [])];
      if (wc < Math.floor(c.charsMin * 0.7)) issuesText.push(`[warn] LENGTH: 本章仅 ${wc} 字，短于目标下限 ${c.charsMin}`);
      else if (wc > Math.ceil(c.charsMax * 1.6)) issuesText.push(`[warn] LENGTH: 本章 ${wc} 字，明显超出目标上限 ${c.charsMax}`);

      await M.saveChapter(env, bookId, {
        chapter_no: ch, title, outline: JSON.stringify(outline), content: cleaned,
        summary: delta.summary || "", ending_tail: body.slice(-320), tags: delta.tags || [],
        word_count: wc, version: st.version, qc_report: JSON.stringify({ issues: issuesText, editor_score: st.editorScore ?? null, editor_notes: st.editorNotes ?? [] }),
      });

      if (st.isRewrite) {
        await M.log(env, { bookId, chapterNo: ch, stage: "update", message: `第${ch}章已重写(v${st.version})，${wc}字`, meta: { wc, issues: issuesText } });
        return { ...st, stage: "complete", title, wc, issues: issuesText };
      }

      // 记账幂等标记：finalize 被掐断重跑时，绝不把同一章的灵石/物品增量应用两遍
      const appliedKey = `${ch}:v${st.version}`;
      const alreadyApplied = (await M.getPlot(env, bookId, "__applied")) === appliedKey;
      if (!alreadyApplied) {
        await applyDelta(env, bookId, ch, delta, charMap);
        await M.setPlot(env, bookId, "__applied", appliedKey);
      }
      if (ch === book.next_chapter) {
        await env.DB.prepare(
          "UPDATE books SET next_chapter=?, total_chars=total_chars+?, cursor_volume=?, updated_at=? WHERE id=?"
        ).bind(ch + 1, wc, vol?.vol ?? book.cursor_volume, Date.now(), bookId).run();
      }
      if (book.target_chapters && ch >= book.target_chapters) await M.setBookStatus(env, bookId, "finished");
      await M.log(env, { bookId, chapterNo: ch, stage: "update", message: `第${ch}章完成，${wc}字`, meta: { wc, issues: issuesText } });

      await M.pruneDeadThreads(env, bookId, ch);
      const patchDirectives: string[] = [];
      if (ch % 10 === 0) {
        await M.updateStoryDigest(env, bookId, ch, async (oldDigest, recent) => {
          const r = await chat(env, [
            { role: "system", content: fill(await tpl(env, bookId, "digest", PROMPT_DIGEST), {}) },
            { role: "user", content: `【已有前情提要】\n${oldDigest || "（无）"}\n\n【最近章节摘要】\n${recent}` },
          ], { temperature: 0.3, maxTokens: 900 });
          return r.text;
        });
        // 连贯性巡检：AI 通读近10章摘要+面板揪矛盾，生成"找补指令"喂给下一章自动圆回来
        try {
          const sums = await M.recentSummaries(env, bookId, 10);
          const sumText = sums.map((x) => `第${x.chapter_no}章：${x.summary}`).join("\n");
          const sweep = await chatJSON<any>(env, [
            { role: "system", content: await tpl(env, bookId, "consistency", PROMPT_CONSISTENCY) },
            { role: "user", content: `【最近章节摘要】\n${sumText}\n\n【当前世界状态】\n${(st.memory || "").slice(0, 8000)}` },
          ], { temperature: 0.1, maxTokens: 900 });
          const issues: string[] = Array.isArray(sweep?.issues) ? sweep.issues.map(String) : [];
          const patches: string[] = Array.isArray(sweep?.patch_directives) ? sweep.patch_directives.map(String) : [];
          if (issues.length) await M.log(env, { bookId, chapterNo: ch, level: "warn", stage: "consistency", message: `巡检发现 ${issues.length} 处矛盾`, meta: { issues, patches } });
          else await M.log(env, { bookId, chapterNo: ch, stage: "consistency", message: "连贯性巡检通过" });
          patchDirectives.push(...patches.slice(0, 4).map((x) => `找补：${x}`));
        } catch (e) {
          await M.log(env, { bookId, chapterNo: ch, level: "warn", stage: "consistency", message: `巡检故障已跳过: ${String(e).slice(0, 100)}` });
        }
      }
      const hero = (await M.loadCharacters(env, bookId)).find((x) => x.role === "protagonist");
      const heroLine = hero ? `${hero.name} ${hero.realm_name}${M.formatRealmSub(powerRanks, hero.realm_index, hero.realm_sub)}｜灵石${hero.assets?.spirit_stones ?? 0}` : "—";

      // 章末结算单（代码生成的系统账）：存档喂给下一章当账目锚点，也发通知供人工核对
      const settlement = settlementText(delta, hero, ch, outline.location);
      await M.setPlot(env, bookId, "last_settlement", settlement);

      // —— 长篇健康监控（闭环，移植自 main_engine2.py 的 health_monitor）——
      // 每章体检四项：战斗/文戏占比、境界停滞、场景停滞、盟友(女主)长期缺席。
      // 发现问题生成写作指令存入 health_todo，下一章 extract 时注入主笔提示，用完即清。
      const health: any = (await M.getPlot(env, bookId, "__health")) || {};
      const directives: string[] = [...patchDirectives];
      const combatKw = ["灵力", "剑", "杀", "血", "阵", "符", "轰", "斩", "偷袭", "毒", "护体", "厮杀", "爆"];
      const combatHits = combatKw.reduce((a, k) => a + (body.includes(k) ? 1 : 0), 0);
      health.combat = [...(health.combat || []), combatHits >= 6 ? 1 : 0].slice(-10);
      if (health.combat.length >= 8) {
        const ratio = health.combat.reduce((a: number, b: number) => a + b, 0) / health.combat.length;
        if (ratio >= 0.8) directives.push("节奏：近10章战斗占比过高，读者会疲劳。本章放缓——写谋划、人情、经营或修炼沉淀，不要再开打。");
        else if (ratio <= 0.1) directives.push("节奏：近10章几乎无冲突，张力散了。本章须引入一次真实威胁、对抗或危机。");
      }
      // 主编评分趋势（移植 main_engine2 的质量监控）：连续走低→给下一章下打磨指令
      if (typeof st.editorScore === "number") {
        health.scores = [...(health.scores || []), st.editorScore].slice(-30);
        const last5: number[] = health.scores.slice(-5);
        if (last5.length === 5) {
          const avg = last5.reduce((a: number, b: number) => a + b, 0) / 5;
          if (avg < 70) directives.push(`质量：最近5章主编平均分仅 ${Math.round(avg)}，质量在滑坡。本章放慢节奏，把冲突、对话、感官细节写扎实，宁可少推进也不写水。`);
        }
      }
      const realmKey = hero ? `${hero.realm_name}·${hero.realm_sub}` : "";
      if (realmKey && realmKey === health.realm) {
        const stall = ch - (health.realm_since ?? ch);
        if (stall >= 20 && stall % 5 === 0) directives.push(`推进：主角境界已 ${stall} 章无寸进（连小层都没升）。近几章内给一次实打实的修为进展，给读者进度感——凡人流可以慢，但不能原地不动。`);
      } else { health.realm = realmKey; health.realm_since = ch; }
      const loc = outline.location || "";
      if (loc && health.loc && (loc === health.loc || loc.includes(health.loc) || health.loc.includes(loc))) {
        const stall = ch - (health.loc_since ?? ch);
        if (stall >= 8 && stall % 4 === 0) directives.push(`推进：剧情已在「${loc}」附近停留 ${stall} 章。尽快转场，或让这个地点积压的矛盾总爆发。`);
      } else { health.loc = loc; health.loc_since = ch; }
      for (const ally of chars.filter((x) => x.role === "ally" && x.alive && x.last_seen_ch > 0)) {
        const gap = ch - ally.last_seen_ch;
        if (gap >= 40 && gap % 10 === 0) directives.push(`角色：「${ally.name}」已 ${gap} 章未出场，读者会忘。近几章找个自然的方式让其回归或至少被提及。`);
      }
      await M.setPlot(env, bookId, "__health", health);
      if (directives.length) await M.setPlot(env, bookId, "health_todo", directives);

      const rewrites = st.attempt || 0;
      const qc = issuesText.length ? `\n质检: ${issuesText.join("；").slice(0, 300)}` : "";
      const scoreLine = typeof st.editorScore === "number" ? `｜主编评分 ${st.editorScore}` : "";
      await tg(env, `📖 <b>${book.title}</b> 第${ch}章 ${title}（${wc}字｜重写${rewrites}次${scoreLine}）\n摘要: ${delta.summary || "—"}\n主角: ${heroLine}\n${settlement}${qc}`);

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
  // 锁有效期须大于最长单步耗时(写正文2-4分钟)：过短会让下一个cron误判无人干活、
  // 重复执行同一步，调用量翻倍直接撞爆限速(实测故障)
  const got = await M.acquireLock(env, bookId, 360);
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
  // 基于最新版本重写（老版本作废删除），避免把上一次重写的成果又改回去
  const ex = await env.DB.prepare(
    "SELECT id, title, content FROM chapters WHERE book_id=? AND chapter_no=? AND status='done' ORDER BY version DESC LIMIT 1"
  ).bind(bookId, st.chapterNo).first<any>();
  if (!ex) {
    await M.log(env, { bookId, chapterNo: st.chapterNo, level: "warn", stage: "rewrite", message: "找不到原章节，无法重写" });
    return { ...st, stage: "complete" };
  }
  
  const humanized = await chat(env, [
    { role: "system", content: `你是一位纯正的人类网文作家。请把【初稿】里的“AI腔、生硬的词汇、模板化的套路”全部磨掉，换成中文人类的口语化表达、真实的动作细节和内心戏。
【关键底线】严禁使用：仿佛、不禁、瞬间、竟然、居然、与此同时、不仅...而且、首先/其次。禁止替换原文的专有名词、人物名字、境界等级和灵石数量，只改文笔！` },
    { role: "user", content: `【初稿】\n${ex.content}` }
  ], { temperature: 0.6, maxTokens: 7000 });
  const polished = humanized.text;

  const body = dedupeChapter(stripLeadingTitle(normalizeText(polished)), st.chapterNo);
  const title = ex.title || `第${st.chapterNo}章`;
  const cleaned = `第${st.chapterNo}章 ${title}\n\n${body}`;
  const wc = body.replace(/\s/g, "").length;
  await env.DB.prepare(
    "UPDATE chapters SET content=?, word_count=?, ending_tail=?, qc_report=? WHERE id=?"
  ).bind(cleaned, wc, body.slice(-320), JSON.stringify({ rewrite: true }), ex.id).run();
  await env.DB.prepare(
    "DELETE FROM chapters WHERE book_id=? AND chapter_no=? AND id<>?"
  ).bind(bookId, st.chapterNo, ex.id).run();
  // 重写会改变字数，重算全书总字数
  const sum = await env.DB.prepare(
    "SELECT COALESCE(SUM(word_count),0) w FROM chapters WHERE book_id=? AND status='done'"
  ).bind(bookId).first<{ w: number }>();
  await env.DB.prepare("UPDATE books SET total_chars=?, updated_at=? WHERE id=?")
    .bind(sum?.w ?? 0, Date.now(), bookId).run();
  await M.log(env, { bookId, chapterNo: st.chapterNo, stage: "rewrite", message: `第${st.chapterNo}章已重写覆盖，${wc}字` });
  return { ...st, stage: "complete", title, wc };
}

async function genOutline(env: Env, bookId: string, ch: number, volText: string, memory: string, focus: string, c: ReturnType<typeof cfg>, sp: string): Promise<ChapterOutline> {
  return chatJSON<ChapterOutline>(env, [
    { role: "system", content: sp + fill(await tpl(env, bookId, "outline", PROMPT_OUTLINE), { CH: ch, CMIN: c.charsMin, CMAX: c.charsMax }) },
    { role: "user", content: fill("【本章焦点】\n{{FOCUS}}\n\n【本卷大纲】\n{{VOLUME}}\n\n【当前世界状态】\n{{MEMORY}}",
        { FOCUS: focus, VOLUME: volText, MEMORY: memory }) },
  ], { temperature: 0.7, maxTokens: 2600 }); // 细纲含战斗阶段/支线等新字段，1600 会截断
}

async function genDraft(env: Env, bookId: string, ch: number, outline: ChapterOutline, memory: string, tail: string, c: ReturnType<typeof cfg>, sp: string, openings: string, temperature = 0.85): Promise<string> {
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
  ], { temperature, maxTokens: 7000 });
  return raw.text;
}

async function polish(env: Env, bookId: string, ch: number, draft: string, memory: string, c: ReturnType<typeof cfg>, sp: string): Promise<string> {
  const raw = await chat(env, [
    { role: "system", content: sp + fill(await tpl(env, bookId, "polish", PROMPT_POLISH), { CH: ch, CMIN: c.charsMin, CMAX: c.charsMax }) },
    { role: "user", content: fill("【初稿】\n{{DRAFT}}\n\n【当前世界状态】\n{{MEMORY}}", { DRAFT: draft, MEMORY: memory }) },
  ], { temperature: 0.6, maxTokens: 7000 });
  return raw.text || draft;
}

async function extractDelta(env: Env, bookId: string, ch: number, text: string, memory: string, sp: string): Promise<StateDelta> {
  const d = await chatJSON<StateDelta>(env, [
    { role: "system", content: sp + fill(await tpl(env, bookId, "update", PROMPT_UPDATE), { CH: ch }) },
    { role: "user", content: fill("【本章定稿】\n{{TEXT}}\n\n【当前世界状态】\n{{MEMORY}}", { TEXT: text, MEMORY: memory }) },
  ], { temperature: 0.2, maxTokens: 3000 }); // 状态增量含设定卡/图谱/人物演化，2000 会截断
  d.characters ??= []; d.foreshadow_new ??= []; d.foreshadow_update ??= [];
  d.lore ??= []; d.edges ??= [];
  d.plot ??= {}; d.tags ??= []; d.summary ??= "";
  // 【代码记账】灵石流水由代码求和，覆盖模型自己合计的净值——AI 不会算数，算数归代码
  for (const cu of d.characters) {
    if (Array.isArray(cu.stone_moves) && cu.stone_moves.length) {
      cu.spirit_stones_delta = cu.stone_moves.reduce(
        (acc, m) => acc + (typeof m?.amount === "number" && Number.isFinite(m.amount) ? Math.trunc(m.amount) : 0), 0);
    }
  }
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
      // 人物性格/口癖/秘密/目标随剧情演化（增量更新，不重新生成）
      ...(cu.personality_traits ? { personality_traits: cu.personality_traits } : {}),
      ...(cu.speech_pattern ? { speech_pattern: cu.speech_pattern } : {}),
      ...(cu.secrets ? { secrets: cu.secrets } : {}),
      ...(cu.goals ? { goals: cu.goals } : {}),
    });
  }
  // 设定卡增量：势力/地点/神器/神通/事件/世界规则，按 (kind,name) upsert
  const LORE_KINDS = new Set(["faction", "location", "artifact", "technique", "event", "worldrule"]);
  for (const l of d.lore || []) {
    if (l?.name && l?.kind && LORE_KINDS.has(l.kind)) await M.upsertLore(env, bookId, l, ch);
  }
  // 知识图谱增量：人物/势力关系边
  if (d.edges?.length) await M.upsertEdges(env, bookId, d.edges, ch);
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

// 章末结算单（游戏存档式）：收获/消耗逐笔 + 期末余额 + 当前坐标 + 主角近况伤势，
// 全部纯代码生成零算术风险。喂给下一章，让模型对"刚刚发生的一切"零猜测。
function settlementText(d: StateDelta, hero: import("./types").CharacterState | undefined, ch: number, location?: string): string {
  const cu = hero ? d.characters.find((x) => x.name === hero.name) : undefined;
  const gains: string[] = [];
  const costs: string[] = [];
  if (cu) {
    const moves = cu.stone_moves?.length
      ? cu.stone_moves
      : (typeof cu.spirit_stones_delta === "number" && cu.spirit_stones_delta !== 0
          ? [{ amount: cu.spirit_stones_delta, note: undefined as string | undefined }] : []);
    for (const m of moves) {
      if (typeof m?.amount !== "number" || m.amount === 0) continue;
      (m.amount > 0 ? gains : costs).push(`灵石${m.amount > 0 ? "+" : ""}${m.amount}${m.note ? `(${m.note})` : ""}`);
    }
    for (const p of cu.add_pills || []) (p.count >= 0 ? gains : costs).push(`${p.name}${p.count >= 0 ? "+" : ""}${p.count}`);
    for (const m of cu.add_materials || []) (m.count >= 0 ? gains : costs).push(`${m.name}${m.count >= 0 ? "+" : ""}${m.count}`);
    for (const a of cu.add_artifacts || []) gains.push(`法宝「${a.name}」`);
    for (const t of cu.add_techniques || []) gains.push(`功法《${t.name}》`);
    for (const mv of cu.add_movement_arts || []) gains.push(`神通/身法「${mv.name}」`);
  }
  const bal = hero ? `期末灵石=${hero.assets?.spirit_stones ?? 0}块` : "";
  const coord = location ? `｜坐标：${location}` : "";
  const status = hero?.status_notes ? `｜主角近况：${hero.status_notes.slice(0, 80)}` : "";
  return `第${ch}章系统结算｜收获：${gains.join("、") || "无"}｜消耗：${costs.join("、") || "无"}｜${bal}${coord}${status}`;
}

// 整章重复检测与截断（移植自 main_engine2.py 的 deduplicate_chapter）：
// 模型长输出时偶发"重启续写"，把写完的正文从头再输出一遍。两重保险：
//   1) 本章标题在正文 15% 之后再次出现 → 从该处截断
//   2) 同一长段落(≥60字)在正文 30% 之后完整复现 → 从第二次出现处截断
export function dedupeChapter(body: string, ch: number): string {
  if (!body || body.length < 500) return body;
  const titleRe = new RegExp(`第\\s*${ch}\\s*章`, "g");
  let m: RegExpExecArray | null;
  while ((m = titleRe.exec(body)) !== null) {
    if (m.index > body.length * 0.15) {
      const trimmed = body.slice(0, m.index).trim();
      if (trimmed.length >= 400) return trimmed;
    }
  }
  const paras = body.split("\n").filter((p) => p.trim().length >= 60);
  const seen = new Set<string>();
  for (const p of paras) {
    const fp = p.slice(0, 60);
    if (seen.has(fp)) {
      const first = body.indexOf(fp);
      const second = body.indexOf(fp, first + fp.length);
      if (second > body.length * 0.3) {
        const trimmed = body.slice(0, second).trim();
        if (trimmed.length >= 400) return trimmed;
      }
    }
    seen.add(fp);
  }
  return body;
}

function stripLeadingTitle(t: string): string {
  const lines = t.replace(/\r\n/g, "\n").split("\n");
  let i = 0;
  // 模型偶尔把标题行写两遍（曾致正文出现重复标题），循环剥掉开头所有标题行
  while (i < lines.length) {
    const s = lines[i].trim();
    if (s === "" || /^第\s*[\d〇零一二三四五六七八九十百千两]+\s*章/.test(s)) { i++; continue; }
    break;
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