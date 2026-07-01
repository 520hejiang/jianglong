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
import { advanceBook, startRewrite } from "./pipeline";
import { ensureSchema } from "./schema";
import { backfillChapterTags } from "./memory";

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

// 【新增】修复 D1 绑定对象的辅助函数：如果是数组或对象，自动转为 JSON 字符串
const safeDbValue = (v: any, defaultVal: string = ''): any => {
  if (v === null || v === undefined) return defaultVal;
  // 数组或普通对象，必须序列化为字符串
  if (Array.isArray(v) || (typeof v === 'object' && v !== null)) {
    return JSON.stringify(v);
  }
  // 数字、字符串、布尔值原样返回
  return v;
};

export async function api(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  if (req.method === "OPTIONS") return new Response(null, { headers: cors() });
  const url = new URL(req.url);
  const p = url.pathname.replace(/\/+$/, "");

  // 健康检查（公开，无需鉴权）：手机上打开 <后台网址>/health 即可一眼看出哪里没配好
  if (req.method === "GET" && (p === "" || p === "/health" || p === "/api/health")) {
    let d1 = "ok";
    try { await env.DB.prepare("SELECT 1 AS x").first(); }
    catch (e) { d1 = "FAIL(数据库未绑定或未建表): " + String(e); }
    return json({
      ok: true,
      service: "novel-engine",
      时间: new Date().toISOString(),
      数据库D1: env.DB ? d1 : "FAIL(未绑定 DB)",
      KV存储: env.KV ? "ok" : "FAIL(未绑定 KV)",
      模型: env.DEEPSEEK_MODEL || "(未设置)",
      DeepSeek密钥: env.DEEPSEEK_API_KEY ? "已配置" : "FAIL(未配置 DEEPSEEK_API_KEY)",
      登录口令: env.ADMIN_TOKEN ? "已配置" : "FAIL(未配置 ADMIN_TOKEN)",
      提示: "全部显示 ok/已配置 才算就绪；任何 FAIL 都要按教程补上",
    });
  }

  // 公开只读：供前端小说网站拉取已发布章节（按需可去掉鉴权）
  if (req.method === "GET" && p.startsWith("/public/")) return publicRoutes(p, env);

  // 其余需要鉴权
  const auth = req.headers.get("Authorization") || "";
  if (auth !== `Bearer ${env.ADMIN_TOKEN}`) return err("unauthorized", 401);

  try {
    await ensureSchema(env); // 首次自动建表，手机用户无需手动跑 SQL
    // ---- books ----
    if (p === "/api/books" && req.method === "GET") {
      const r = await env.DB.prepare("SELECT id,title,status,next_chapter,target_chapters,total_chars,cursor_volume,last_error,updated_at FROM books ORDER BY updated_at DESC").all();
      return json(r.results ?? []);
    }
    if (p === "/api/books" && req.method === "POST") {
      const b = await req.json<any>();
      const id = uid();
      // 【已修复】使用 safeDbValue 包裹所有可能传对象的字段
      await env.DB.prepare(
        `INSERT INTO books (id,title,status,master_outline,volume_outline,core_settings,power_system,
         planes,current_plane,style_prompt_override,next_chapter,target_chapters,total_chars,cursor_volume,created_at,updated_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0,0,?,?)`
      ).bind(id, safeDbValue(b.title, "未命名"), "paused", safeDbValue(b.master_outline),
        safeDbValue(b.volume_outline, "[]"), safeDbValue(b.core_settings),
        safeDbValue(b.power_system), safeDbValue(b.planes), safeDbValue(b.current_plane),
        safeDbValue(b.style_prompt_override), b.start_chapter ?? 1, b.target_chapters ?? 800, now(), now()).run();
      return json({ id });
    }
    const mBook = p.match(/^\/api\/books\/([^/]+)$/);
    if (mBook) {
      const id = mBook[1];
      if (req.method === "GET") {
        const b = await env.DB.prepare("SELECT * FROM books WHERE id=?").bind(id).first();
        return b ? json(b) : err("not found", 404);
      }
      // 彻底删书：本书的一切（章节/角色/伏笔/剧情/设定卡/图谱/索引/日志/单书Prompt/锁/书本身）全部删光，
      // 数据库里不留一行。开新书（玄幻/恐怖多本并行）前清场用。前端三次确认。
      if (req.method === "DELETE") {
        const b = await env.DB.prepare("SELECT title FROM books WHERE id=?").bind(id).first<{ title: string }>();
        if (!b) return err("not found", 404);
        for (const t of ["chapters", "foreshadowing", "characters", "plot_state", "lore", "graph_edges", "chapter_tags", "logs"]) {
          await env.DB.prepare(`DELETE FROM ${t} WHERE book_id=?`).bind(id).run();
        }
        await env.DB.prepare("DELETE FROM prompts WHERE book_id=?").bind(id).run();
        await env.DB.prepare("DELETE FROM books WHERE id=?").bind(id).run();
        await env.KV.delete(`genlock:${id}`);
        return json({ ok: true, deleted: b.title, note: "本书及全部关联数据已彻底删除" });
      }
      if (req.method === "PUT") {
        const b = await req.json<any>();
        const fields = ["title", "master_outline", "volume_outline", "core_settings", "power_system", "planes", "current_plane", "style_prompt_override", "target_chapters", "next_chapter"];
        const sets: string[] = []; const vals: any[] = [];
        for (const f of fields) if (f in b) { 
          sets.push(`${f}=?`); 
          // 【已修复】更新时也可能传入对象/数组，必须序列化
          vals.push(safeDbValue(b[f])); 
        }
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
      // start 时立刻推进一步（断点续传），不必等下一次 cron
      if (act === "start") ctx.waitUntil(advanceBook(env, id, 18000).catch(() => {}));
      return json({ ok: true });
    }

    // 重置生成：清掉卡住的生成/重写存档与锁，恢复正常推进（解卡用）
    const mReset = p.match(/^\/api\/books\/([^/]+)\/reset$/);
    if (mReset && req.method === "POST") {
      const id = mReset[1];
      await env.DB.prepare("DELETE FROM plot_state WHERE book_id=? AND key IN ('__genjob','__rewritejob')").bind(id).run();
      await env.KV.delete(`genlock:${id}`);
      // 重置=彻底恢复：清存档/锁，并把书设回 running，否则 cron 不会推进
      await env.DB.prepare("UPDATE books SET status='running', last_error=NULL, updated_at=? WHERE id=?").bind(now(), id).run();
      await env.DB.prepare("INSERT INTO logs (id,book_id,level,stage,message,meta,created_at) VALUES (?,?,?,?,?,?,?)")
        .bind(uid(), id, "warn", "manual", "手动重置生成（清掉卡住的存档与锁）", null, now()).run();
      ctx.waitUntil(advanceBook(env, id, 18000).catch(() => {}));
      return json({ ok: true, note: "已重置并重新推进" });
    }

    // 清空重置：删除本书全部章节/角色/伏笔/剧情/日志/存档，回到第1章（前端三次确认）
    const mWipe = p.match(/^\/api\/books\/([^/]+)\/wipe$/);
    if (mWipe && req.method === "POST") {
      const id = mWipe[1];
      const book = await env.DB.prepare("SELECT planes FROM books WHERE id=?").bind(id).first<{ planes: string }>();
      if (!book) return err("not found", 404);
      // 取出初始角色快照，清空后重新植入
      const seedRow = await env.DB.prepare("SELECT value FROM plot_state WHERE book_id=? AND key='__char_seed'").bind(id).first<{ value: string }>();
      const seed: any[] = seedRow ? (JSON.parse(seedRow.value) || []) : [];
      for (const t of ["chapters", "foreshadowing", "characters", "plot_state", "lore", "graph_edges", "chapter_tags", "logs"]) {
        await env.DB.prepare(`DELETE FROM ${t} WHERE book_id=?`).bind(id).run();
      }
      await env.KV.delete(`genlock:${id}`);
      for (const c of seed) {
        if (!c?.name) continue;
        await env.DB.prepare(
          `INSERT INTO characters (id,book_id,name,aliases,role,alive,realm_index,realm_name,realm_sub,
           techniques,movement_arts,artifacts,assets,relations,status_notes,last_seen_ch,last_breakthrough_ch,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,0,?)`
        ).bind(uid(), id, c.name, JSON.stringify(c.aliases ?? []), c.role ?? "npc",
          c.alive === false ? 0 : 1, c.realm_index ?? 0, c.realm_name ?? "", c.realm_sub ?? 0,
          JSON.stringify(c.techniques ?? []), JSON.stringify(c.movement_arts ?? []),
          JSON.stringify(c.artifacts ?? []), JSON.stringify(c.assets ?? { spirit_stones: 0, pills: [], materials: [], misc: [] }),
          JSON.stringify(c.relations ?? []), c.status_notes ?? "", now()).run();
      }
      if (seed.length) {
        await env.DB.prepare(`INSERT INTO plot_state (book_id,key,value,updated_at) VALUES (?,?,?,?)`)
          .bind(id, "__char_seed", JSON.stringify(seed), now()).run();
      }
      const planes = book.planes ? (JSON.parse(book.planes) || []) : [];
      await env.DB.prepare("UPDATE books SET next_chapter=1, total_chars=0, cursor_volume=0, current_plane=?, status='paused', last_error=NULL, updated_at=? WHERE id=?")
        .bind(planes[0]?.name ?? "", now(), id).run();
      await env.DB.prepare("INSERT INTO logs (id,book_id,level,stage,message,meta,created_at) VALUES (?,?,?,?,?,?,?)")
        .bind(uid(), id, "warn", "manual", `🧨 已清空本书全部内容，重置到第1章（恢复 ${seed.length} 个初始角色）`, null, now()).run();
      return json({ ok: true, reseeded: seed.length, note: "已清空并重置到第1章，点开始即从头生成" });
    }

    // 手动生成一章 / 重写某章
    const mGen = p.match(/^\/api\/books\/([^/]+)\/generate$/);
    if (mGen && req.method === "POST") {
      const id = mGen[1];
      const body = await req.json<any>().catch(() => ({}));
      if (body.rewrite && body.chapter) {
        // 重写指定章：断点续传式，优先跑完；只换正文不重复应用状态
        const v = await startRewrite(env, id, body.chapter);
        ctx.waitUntil(advanceBook(env, id, 18000).catch(() => {}));
        return json({ ok: true, rewriting: body.chapter, version: v, note: "重写已排期，后台逐步生成，约数分钟后刷新该章即可看到新版" });
      }
      // 向前生成：点"立即生成"即视为要它跑，顺手设为 running（否则 cron 不推进）
      const b = await env.DB.prepare("SELECT next_chapter FROM books WHERE id=?").bind(id).first<{ next_chapter: number }>();
      if (!b) return err("not found", 404);
      await env.DB.prepare("UPDATE books SET status='running', last_error=NULL, updated_at=? WHERE id=?").bind(now(), id).run();
      ctx.waitUntil(advanceBook(env, id, 18000).catch(() => {}));
      return json({ ok: true, generating: b.next_chapter, note: "已开始，章节会在后台逐步生成，约数分钟内出章" });
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
           techniques,movement_arts,artifacts,assets,relations,status_notes,last_seen_ch,last_breakthrough_ch,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,0,?)
           ON CONFLICT(book_id,name) DO UPDATE SET aliases=excluded.aliases, role=excluded.role,
             alive=excluded.alive, realm_index=excluded.realm_index, realm_name=excluded.realm_name,
             realm_sub=excluded.realm_sub, techniques=excluded.techniques, movement_arts=excluded.movement_arts,
             artifacts=excluded.artifacts, assets=excluded.assets, relations=excluded.relations,
             status_notes=excluded.status_notes, updated_at=excluded.updated_at`
        ).bind(
          uid(), bookId, c.name, JSON.stringify(c.aliases ?? []), c.role ?? "npc",
          c.alive === false ? 0 : 1, c.realm_index ?? 0, c.realm_name ?? "", c.realm_sub ?? 0,
          JSON.stringify(c.techniques ?? []), JSON.stringify(c.movement_arts ?? []),
          JSON.stringify(c.artifacts ?? []), JSON.stringify(c.assets ?? { spirit_stones: 0, pills: [], materials: [], misc: [] }),
          JSON.stringify(c.relations ?? []), c.status_notes ?? "", now()
        ).run();
      }
      // 存一份"初始角色快照"，供"清空重置"后从头恢复
      await env.DB.prepare(
        `INSERT INTO plot_state (book_id,key,value,updated_at) VALUES (?,?,?,?)
         ON CONFLICT(book_id,key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`
      ).bind(bookId, "__char_seed", JSON.stringify(list), now()).run();
      return json({ ok: true, count: list.length });
    }
    const mChar = p.match(/^\/api\/characters\/([^/]+)$/);
    if (mChar && req.method === "PUT") {
      // 手动改角色（生死/境界等，用于防崩）
      const b = await req.json<any>();
      const allow = ["alive", "realm_index", "realm_name", "realm_sub", "techniques", "movement_arts", "artifacts", "assets", "relations", "status_notes", "role", "last_breakthrough_ch"];
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

    // ---- 记忆：设定卡 / 知识图谱 ----
    const mLore = p.match(/^\/api\/books\/([^/]+)\/lore$/);
    if (mLore && req.method === "GET") {
      const r = await env.DB.prepare(
        "SELECT * FROM lore WHERE book_id=? ORDER BY kind, importance DESC, last_ch DESC LIMIT 500"
      ).bind(mLore[1]).all();
      return json(r.results ?? []);
    }
    const mEdges = p.match(/^\/api\/books\/([^/]+)\/graph$/);
    if (mEdges && req.method === "GET") {
      const r = await env.DB.prepare(
        "SELECT * FROM graph_edges WHERE book_id=? ORDER BY updated_ch DESC LIMIT 500"
      ).bind(mEdges[1]).all();
      return json(r.results ?? []);
    }

    // 老书升级用：把已有章节的 tags 回填进倒排索引（新章节写入时自动索引，无需再跑）
    const mReindex = p.match(/^\/api\/books\/([^/]+)\/reindex$/);
    if (mReindex && req.method === "POST") {
      const n = await backfillChapterTags(env, mReindex[1]);
      return json({ ok: true, indexed_chapters: n, note: "标签倒排索引已回填，历史章节可被RAG精准检索" });
    }

    // ---- 章节 ----
    const mChaps = p.match(/^\/api\/books\/([^/]+)\/chapters$/);
    if (mChaps && req.method === "GET") {
      // 每个 chapter_no 只取最新版本，避免历史重复版本造成目录重复
      const r = await env.DB.prepare(
        `SELECT chapter_no,title,word_count,version,status,created_at FROM chapters c
         WHERE book_id=? AND status='done'
           AND version=(SELECT MAX(version) FROM chapters WHERE book_id=c.book_id AND chapter_no=c.chapter_no AND status='done')
         ORDER BY chapter_no DESC LIMIT 500`
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
    // 删除某章（所有版本），并重算总字数
    if (mChap && req.method === "DELETE") {
      const bookId = mChap[1]; const no = parseInt(mChap[2], 10);
      await env.DB.prepare("DELETE FROM chapters WHERE book_id=? AND chapter_no=?").bind(bookId, no).run();
      await env.DB.prepare("DELETE FROM chapter_tags WHERE book_id=? AND chapter_no=?").bind(bookId, no).run();
      const sum = await env.DB.prepare("SELECT COALESCE(SUM(word_count),0) w FROM chapters WHERE book_id=? AND status='done'").bind(bookId).first<{ w: number }>();
      await env.DB.prepare("UPDATE books SET total_chars=?, updated_at=? WHERE id=?").bind(sum?.w ?? 0, now(), bookId).run();
      await env.DB.prepare("INSERT INTO logs (id,book_id,chapter_no,level,stage,message,meta,created_at) VALUES (?,?,?,?,?,?,?,?)")
        .bind(uid(), bookId, no, "warn", "manual", `手动删除第${no}章`, null, now()).run();
      return json({ ok: true, deleted: no });
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
      // 【已修复】确保 template 内容如果是对象或数组也能安全存入
      await env.DB.prepare(
        `INSERT INTO prompts (id,scope,book_id,name,template,updated_at) VALUES (?,?,?,?,?,?)
         ON CONFLICT(id) DO UPDATE SET template=excluded.template, updated_at=excluded.updated_at`
      ).bind(id, b.scope, b.book_id ?? null, b.name, safeDbValue(b.template), now()).run();
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