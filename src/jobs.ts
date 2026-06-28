// ============================================================================
// 任务分发：兼容"有 Queues(付费计划)"与"无 Queues(纯免费, Cron 内联生成)"两种模式
//   - 有 GEN_QUEUE 绑定 -> 入队，由 queue 消费者处理（吞吐高，需付费 Workers 计划）
//   - 无 GEN_QUEUE     -> 直接在后台(ctx.waitUntil)生成，Cron 每 2 分钟推进一章（全免费）
// 两种模式共用 runChapterJob，保证行为一致。
// ============================================================================
import type { Env, GenJob } from "./types";
import { generateChapter } from "./pipeline";
import * as M from "./memory";
import { tg } from "./telegram";

// 决定一个 job 怎么跑：能入队就入队，否则后台内联生成。
export async function dispatchChapter(env: Env, ctx: ExecutionContext, job: GenJob): Promise<void> {
  if (env.GEN_QUEUE) {
    await env.GEN_QUEUE.send(job);
  } else {
    ctx.waitUntil(runChapterJob(env, job).catch(() => {})); // 错误已在内部记录
  }
}

// 实际执行一个章节任务：加锁 -> 生成 -> 通知 -> 解锁。失败时置书为 error 并抛出（供队列重试）。
export async function runChapterJob(env: Env, job: GenJob): Promise<void> {
  const got = await M.acquireLock(env, job.bookId, 1500); // 25min，覆盖慢章，配合幂等防重复
  if (!got) return; // 该书已有一章在生成，跳过
  try {
    const book = await M.getBook(env, job.bookId);
    if (!book) return;
    if (book.status !== "running" && job.reason === "cron") return; // 已暂停则不再自动推进
    const version = job.reason === "rewrite" ? await nextVersion(env, job.bookId, job.chapterNo) : 1;
    const res = await generateChapter(env, job.bookId, job.chapterNo, version);
    if (res.issues.length) {
      await tg(env, `⚠️ <b>${book.title}</b> 第${res.chapterNo}章已生成但有质检提示：\n${res.issues.join("\n")}`);
    }
  } catch (e) {
    const m = String(e);
    await M.log(env, { bookId: job.bookId, chapterNo: job.chapterNo, level: "error", stage: "job", message: m });
    await M.setBookStatus(env, job.bookId, "error", m);
    await tg(env, `❌ <b>生成失败</b> book=${job.bookId} 第${job.chapterNo}章\n${m}`);
    throw e;
  } finally {
    await M.releaseLock(env, job.bookId);
  }
}

export async function nextVersion(env: Env, bookId: string, ch: number): Promise<number> {
  const r = await env.DB.prepare(
    "SELECT COALESCE(MAX(version),0) v FROM chapters WHERE book_id=? AND chapter_no=?"
  ).bind(bookId, ch).first<{ v: number }>();
  return (r?.v ?? 0) + 1;
}
