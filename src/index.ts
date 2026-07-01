// ============================================================================
// Worker 入口：三个触发面
//   1. fetch    -> 控制台 REST API（建书/导入大纲/改 Prompt/看记忆/启停/重写/取章）
//   2. scheduled-> Cron 每 1 分钟巡检 running 的书，推进下一章
//                  （有 Queues 则入队；无 Queues 则后台内联生成——纯免费可用）
//   3. queue    -> 仅在开启 Queues(付费计划) 时消费生成任务
// ============================================================================
import type { Env, GenJob } from "./types";
import * as M from "./memory";
import { tg } from "./telegram";
import { api } from "./api";
import { runChapterJob } from "./jobs";
import { advanceBook } from "./pipeline";

export default {
  // ---------------- HTTP ----------------
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return api(req, env, ctx);
  },

  // ---------------- Cron ----------------
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(cronTick(env, ctx));
  },

  // ---------------- Queue 消费（仅付费计划开启 Queues 时触发）----------------
  async queue(batch: MessageBatch<GenJob>, env: Env, _ctx: ExecutionContext): Promise<void> {
    for (const msg of batch.messages) {
      try {
        await runChapterJob(env, msg.body);
        msg.ack();
      } catch {
        msg.retry(); // 进入重试 / 最终入 DLQ
      }
    }
  },
};

// 巡检：给每本 running 的书"断点续传"推进生成，并做每日报告。
// 免费计划下，单次调用可能被平台掐断；advanceBook 每步存档，故多次巡检接力即可完成整章。
async function cronTick(env: Env, ctx: ExecutionContext): Promise<void> {
  const books = await M.listRunningBooks(env);
  for (const b of books) {
    if (b.target_chapters && b.next_chapter > b.target_chapters) {
      await M.setBookStatus(env, b.id, "finished");
      await tg(env, `✅ <b>${b.title}</b> 已达成目标 ${b.target_chapters} 章，自动停笔。`);
      continue;
    }
    // advanceBook 自带锁与时间预算；被锁(正在生成)会直接返回 idle
    ctx.waitUntil(advanceBook(env, b.id, 18000).catch(async (e) => {
      await M.log(env, { bookId: b.id, level: "error", stage: "cron", message: String(e) });
    }));
  }
  await maybeDailyReport(env, books.length);
}

// 每日一次运行报告（用 KV 记当天是否已发）
async function maybeDailyReport(env: Env, runningCount: number): Promise<void> {
  const day = new Date().toISOString().slice(0, 10);
  const key = `report:${day}`;
  if (await env.KV.get(key)) return;
  // 仅在当天首次 cron（UTC 0 点后）发；简单起见：每天第一次进来就发昨日统计
  const since = Date.now() - 24 * 3600 * 1000;
  const r = await env.DB.prepare(
    "SELECT COUNT(*) c, COALESCE(SUM(word_count),0) w FROM chapters WHERE status='done' AND created_at>?"
  ).bind(since).first<{ c: number; w: number }>();
  const errs = await env.DB.prepare(
    "SELECT COUNT(*) c FROM logs WHERE level='error' AND created_at>?"
  ).bind(since).first<{ c: number }>();
  await tg(env,
    `📊 <b>每日运行报告</b> (${day})\n在写书目：${runningCount}\n过去24h新增章节：${r?.c ?? 0}\n新增字数：${r?.w ?? 0}\n错误数：${errs?.c ?? 0}`);
  await env.KV.put(key, "1", { expirationTtl: 36 * 3600 });
}
