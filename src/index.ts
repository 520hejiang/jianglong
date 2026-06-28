// ============================================================================
// Worker 入口：三个触发面
//   1. fetch    -> 控制台 REST API（建书/导入大纲/改 Prompt/看记忆/启停/重写/取章）
//   2. scheduled-> Cron 每 2 分钟巡检 running 的书，入队下一章
//   3. queue    -> 消费生成任务，跑完整 pipeline 落库一章
// ============================================================================
import type { Env, GenJob } from "./types";
import { generateChapter } from "./pipeline";
import * as M from "./memory";
import { tg } from "./telegram";
import { api } from "./api";

export default {
  // ---------------- HTTP ----------------
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return api(req, env, ctx);
  },

  // ---------------- Cron ----------------
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(cronTick(env));
  },

  // ---------------- Queue 消费 ----------------
  async queue(batch: MessageBatch<GenJob>, env: Env, _ctx: ExecutionContext): Promise<void> {
    for (const msg of batch.messages) {
      const job = msg.body;
      const got = await M.acquireLock(env, job.bookId, 600);
      if (!got) { msg.ack(); continue; } // 该书正有一章在跑，跳过
      try {
        const book = await M.getBook(env, job.bookId);
        if (!book || (book.status !== "running" && job.reason !== "manual" && job.reason !== "rewrite")) {
          msg.ack(); await M.releaseLock(env, job.bookId); continue;
        }
        const version = job.reason === "rewrite" ? await nextVersion(env, job.bookId, job.chapterNo) : 1;
        const res = await generateChapter(env, job.bookId, job.chapterNo, version);
        if (res.issues.length) {
          await tg(env, `⚠️ <b>${book.title}</b> 第${res.chapterNo}章已生成但有质检提示：\n${res.issues.join("\n")}`);
        }
        msg.ack();
      } catch (e) {
        const m = String(e);
        await M.log(env, { bookId: job.bookId, chapterNo: job.chapterNo, level: "error", stage: "queue", message: m });
        await M.setBookStatus(env, job.bookId, "error", m);
        await tg(env, `❌ <b>生成失败</b> book=${job.bookId} 第${job.chapterNo}章\n${m}`);
        msg.retry(); // 进入重试 / 最终入 DLQ
      } finally {
        await M.releaseLock(env, job.bookId);
      }
    }
  },
};

// 巡检：给每本 running 的书入队"下一章"，并做每日报告
async function cronTick(env: Env): Promise<void> {
  const books = await M.listRunningBooks(env);
  for (const b of books) {
    // 已写到目标章数则停
    if (b.target_chapters && b.next_chapter > b.target_chapters) {
      await M.setBookStatus(env, b.id, "finished");
      await tg(env, `✅ <b>${b.title}</b> 已达成目标 ${b.target_chapters} 章，自动停笔。`);
      continue;
    }
    // 该书若有锁说明正在生成，跳过（避免堆积）
    const locked = await env.KV.get(`lock:${b.id}`);
    if (locked) continue;
    await env.GEN_QUEUE.send({ bookId: b.id, chapterNo: b.next_chapter, reason: "cron" });
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

async function nextVersion(env: Env, bookId: string, ch: number): Promise<number> {
  const r = await env.DB.prepare(
    "SELECT COALESCE(MAX(version),0) v FROM chapters WHERE book_id=? AND chapter_no=?"
  ).bind(bookId, ch).first<{ v: number }>();
  return (r?.v ?? 0) + 1;
}
