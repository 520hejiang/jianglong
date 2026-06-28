// ============================================================================
// 控制台 REST API
//   鉴权：请求头 Authorization: Bearer <ADMIN_TOKEN>
//   书：建/列/导入大纲设定/启停
//   记忆：查看与手动修改角色（防崩）、伏笔、剧情
//   章节：列出 / 取正文（供一键复制或推送到前端网站）
//   Prompt：查看/覆盖模板
//   生成：手动触发一章 / 重写某章
// ============================================================================
import type { Env } from "./types";

const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", ...cors() } });
const err = (msg: string, status = 400) => json({ error: msg }, status);
const cors = () => ({
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Authorization,Content-Type",
});
const now = () => Date.now();
const uid = () => crypto.randomUUID();

export async function api(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  if (req.method === "OPTIONS") return new Response(null, { headers: cors() });
  const url = new URL(req.url);
  const p = url.pathname.replace(/\/+$/, "");

  // 公开只读：供前端小说网站拉取已发布章节（按需可去掉鉴权）
  if (req.method === "GET" && p.startsWith("/public/")) return publicRoutes(p, env);

  // 其余需要鉴权
  const auth = req.headers.get("Authorization") || "";
  if (auth !== `Bearer ${env.ADMIN_TOKEN}`) return err("unauthorized", 401);

  try {
    // ---- books ----
    if (p === "/api/books" && req.method === "GET") {
      const r = await env.DB.prepare("SELECT id,title,status,next_chapter,target_chapters,total_chars,cursor_volume,last_error,updated_at FROM books ORDER BY updated_at DESC").all();
      return json(r.results ?? []);
    }
    if (p === "/api/books" && req.method === "POST") {
      const b = await req.json<any>();
      const id = uid();
      await env.DB.prepare(
        `INSERT INTO books (id,title,status,master_outline,volume_outline,core_settings,power_system,
         next_chapter,target_chapters,total_chars,cursor_volume,created_at,updated_at)
         VALUES (?,?,?,?,?,?,?,?,?,0,0,?,?)`
      ).bind(id, b.title || "未命名", "paused", b.master_outline ?? "", b.volume_outline ?? "[]",
        b.core_settings ?? "", b.power_system ?? "", b.start_chapter ?? 1, b.target_chapters ?? 800, now(), now()).run();
      return json({ id });
    }
    const mBook = p.match(/^\/api\/books\/([^/]+)$/);
    if (mBook) {
      const id = mBook[1];
      if (req.method === "GET") {
        const b = await env.DB.prepare("SELECT * FROM books WHERE id=?").bind(id).first();
        return b ? json(b) : err("not found", 404);
      }
      if (req.method === "PUT") {
        const b = await req.json<any>();
        const fields = ["title", "master_outline", "volume_outline", "core_settings", "power_system", "style_prompt_override", "target_chapters", "next_chapter"];
        const sets: string[] = []; const vals: any[] = [];
        for (const f of fields) if (f in b) { sets.push(`${f}=?`); vals.push(b[f]); }
        if (!sets.length) return err("nothing to update");
        vals.push(now(), id);
        await env.DB.prepare(`UPDATE books SET ${sets.join(",")}, updated_at=? WHERE id=?`).bind(...vals).run();
        return json({ ok: true });
      }
    }

    // 启停
    const mStatus = p.match(/^\/api\/books\/([^/]+)\/(start|stop)$/);
    if (mStatus && req.method === "POST") {
      const [, id, act] = mStatus;
      await env.DB.prepare("UPDATE books SET status=?, last_error=NULL, updated_at=? WHERE id=?")
        .bind(act === "start" ? "running" : "paused", now(), id).run();
      // start 时立即入队一章，不必等下一次 cron
      if (act === "start") {
        const b = await env.DB.prepare("SELECT next_chapter FROM books WHERE id=?").bind(id).first<{ next_chapter: number }>();
        if (b) await env.GEN_QUEUE.send({ bookId: id, chapterNo: b.next_chapter, reason: "manual" });
      }
      return json({ ok: true });
    }

    // 手动生成一章 / 重写某章
    const mGen = p.match(/^\/api\/books\/([^/]+)\/generate$/);
    if (mGen && req.method === "POST") {
      const id = mGen[1];
      const body = await req.json<any>().catch(() => ({}));
      const b = await env.DB.prepare("SELECT next_chapter FROM books WHERE id=?").bind(id).first<{ next_chapter: number }>();
      if (!b) return err("not found", 404);
      const ch = body.chapter ?? b.next_chapter;
      await env.GEN_QUEUE.send({ bookId: id, chapterNo: ch, reason: body.rewrite ? "rewrite" : "manual" });
      return json({ ok: true, queued: ch });
    }

    // ---- 记忆：角色 ----
    const mChars = p.match(/^\/api\/books\/([^/]+)\/characters$/);
    if (mChars && req.method === "GET") {
      const r = await env.DB.prepare("SELECT * FROM characters WHERE book_id=? ORDER BY role, name").bind(mChars[1]).all();
      return json(r.results ?? []);
    }
    // 批量 seed 角色/法宝设定（解析脚本 & 新书向导用）。按 name upsert。
    if (mChars && req.method === "POST") {
      const bookId = mChars[1];
      const body = await req.json<any>();
      const list: any[] = Array.isArray(body) ? body : (body.characters || []);
      for (const c of list) {
        if (!c?.name) continue;
        await env.DB.prepare(
          `INSERT INTO characters (id,book_id,name,aliases,role,alive,realm_index,realm_name,realm_sub,
           techniques,artifacts,relations,status_notes,last_seen_ch,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,0,?)
           ON CONFLICT(book_id,name) DO UPDATE SET aliases=excluded.aliases, role=excluded.role,
             alive=excluded.alive, realm_index=excluded.realm_index, realm_name=excluded.realm_name,
             realm_sub=excluded.realm_sub, techniques=excluded.techniques, artifacts=excluded.artifacts,
             relations=excluded.relations, status_notes=excluded.status_notes, updated_at=excluded.updated_at`
        ).bind(
          uid(), bookId, c.name, JSON.stringify(c.aliases ?? []), c.role ?? "npc",
          c.alive === false ? 0 : 1, c.realm_index ?? 0, c.realm_name ?? "", c.realm_sub ?? 0,
          JSON.stringify(c.techniques ?? []), JSON.stringify(c.artifacts ?? []),
          JSON.stringify(c.relations ?? []), c.status_notes ?? "", now()
        ).run();
      }
      return json({ ok: true, count: list.length });
    }
    const mChar = p.match(/^\/api\/characters\/([^/]+)$/);
    if (mChar && req.method === "PUT") {
      // 手动改角色（生死/境界等，用于防崩）
      const b = await req.json<any>();
      const allow = ["alive", "realm_index", "realm_name", "realm_sub", "techniques", "artifacts", "relations", "status_notes", "role"];
      const sets: string[] = []; const vals: any[] = [];
      for (const f of allow) if (f in b) {
        sets.push(`${f}=?`);
        vals.push(typeof b[f] === "object" ? JSON.stringify(b[f]) : (f === "alive" ? (b[f] ? 1 : 0) : b[f]));
      }
      if (!sets.length) return err("nothing to update");
      vals.push(now(), mChar[1]);
      await env.DB.prepare(`UPDATE characters SET ${sets.join(",")}, updated_at=? WHERE id=?`).bind(...vals).run();
      return json({ ok: true });
    }

    // ---- 记忆：伏笔 / 剧情 ----
    const mFore = p.match(/^\/api\/books\/([^/]+)\/foreshadowing$/);
    if (mFore && req.method === "GET") {
      const r = await env.DB.prepare("SELECT * FROM foreshadowing WHERE book_id=? ORDER BY status,importance DESC").bind(mFore[1]).all();
      return json(r.results ?? []);
    }
    const mPlot = p.match(/^\/api\/books\/([^/]+)\/plot$/);
    if (mPlot && req.method === "GET") {
      const r = await env.DB.prepare("SELECT key,value,updated_at FROM plot_state WHERE book_id=?").bind(mPlot[1]).all();
      return json(r.results ?? []);
    }

    // ---- 章节 ----
    const mChaps = p.match(/^\/api\/books\/([^/]+)\/chapters$/);
    if (mChaps && req.method === "GET") {
      const r = await env.DB.prepare(
        "SELECT chapter_no,title,word_count,version,status,created_at FROM chapters WHERE book_id=? AND status='done' ORDER BY chapter_no DESC LIMIT 500"
      ).bind(mChaps[1]).all();
      return json(r.results ?? []);
    }
    const mChap = p.match(/^\/api\/books\/([^/]+)\/chapters\/(\d+)$/);
    if (mChap && req.method === "GET") {
      const r = await env.DB.prepare(
        "SELECT * FROM chapters WHERE book_id=? AND chapter_no=? AND status='done' ORDER BY version DESC LIMIT 1"
      ).bind(mChap[1], parseInt(mChap[2], 10)).first();
      return r ? json(r) : err("not found", 404);
    }

    // ---- 日志 ----
    const mLogs = p.match(/^\/api\/books\/([^/]+)\/logs$/);
    if (mLogs && req.method === "GET") {
      const r = await env.DB.prepare("SELECT * FROM logs WHERE book_id=? ORDER BY created_at DESC LIMIT 200").bind(mLogs[1]).all();
      return json(r.results ?? []);
    }

    // ---- Prompt 模板 ----
    if (p === "/api/prompts" && req.method === "GET") {
      const r = await env.DB.prepare("SELECT * FROM prompts ORDER BY scope,name").all();
      return json(r.results ?? []);
    }
    if (p === "/api/prompts" && req.method === "POST") {
      const b = await req.json<any>(); // {scope, book_id?, name, template}
      const id = b.scope === "book" ? `${b.book_id}:${b.name}` : `global:${b.name}`;
      await env.DB.prepare(
        `INSERT INTO prompts (id,scope,book_id,name,template,updated_at) VALUES (?,?,?,?,?,?)
         ON CONFLICT(id) DO UPDATE SET template=excluded.template, updated_at=excluded.updated_at`
      ).bind(id, b.scope, b.book_id ?? null, b.name, b.template, now()).run();
      return json({ id });
    }

    return err("not found", 404);
  } catch (e) {
    return err(String(e), 500);
  }
}

// 公开只读：你的前端小说网站可直接调这些拉取章节
async function publicRoutes(p: string, env: Env): Promise<Response> {
  const mList = p.match(/^\/public\/books\/([^/]+)\/chapters$/);
  if (mList) {
    const r = await env.DB.prepare(
      "SELECT chapter_no,title,word_count FROM chapters WHERE book_id=? AND status='done' ORDER BY chapter_no ASC"
    ).bind(mList[1]).all();
    return json(r.results ?? []);
  }
  const mGet = p.match(/^\/public\/books\/([^/]+)\/chapters\/(\d+)$/);
  if (mGet) {
    const r = await env.DB.prepare(
      "SELECT chapter_no,title,content,word_count FROM chapters WHERE book_id=? AND chapter_no=? AND status='done' ORDER BY version DESC LIMIT 1"
    ).bind(mGet[1], parseInt(mGet[2], 10)).first();
    return r ? json(r) : err("not found", 404);
  }
  return err("not found", 404);
}
