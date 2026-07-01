// ============================================================================
// 内嵌建表 DDL + 自动建表
//   作用：手机/一键 Git 部署的用户无需手动在 D1 控制台跑 schema.sql——
//   后端首次收到请求时会自动建好所有表（CREATE TABLE IF NOT EXISTS，幂等安全）。
//   ⚠️ 本文件需与 schema.sql 保持一致（字段有改动两处都要改）。
// ============================================================================
import type { Env } from "./types";

const DDL: string[] = [
  `CREATE TABLE IF NOT EXISTS books (
    id TEXT PRIMARY KEY, title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'paused',
    master_outline TEXT, volume_outline TEXT, core_settings TEXT, power_system TEXT,
    planes TEXT, current_plane TEXT, style_prompt_override TEXT,
    next_chapter INTEGER NOT NULL DEFAULT 1, target_chapters INTEGER DEFAULT 800,
    total_chars INTEGER NOT NULL DEFAULT 0, cursor_volume INTEGER NOT NULL DEFAULT 0,
    last_error TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS chapters (
    id TEXT PRIMARY KEY, book_id TEXT NOT NULL, chapter_no INTEGER NOT NULL, title TEXT,
    outline TEXT, content TEXT, summary TEXT, ending_tail TEXT, tags TEXT,
    word_count INTEGER DEFAULT 0, status TEXT NOT NULL DEFAULT 'draft', version INTEGER NOT NULL DEFAULT 1,
    qc_report TEXT, created_at INTEGER NOT NULL, UNIQUE(book_id, chapter_no, version))`,
  `CREATE INDEX IF NOT EXISTS idx_chapters_book ON chapters(book_id, chapter_no)`,
  `CREATE TABLE IF NOT EXISTS characters (
    id TEXT PRIMARY KEY, book_id TEXT NOT NULL, name TEXT NOT NULL, aliases TEXT, role TEXT,
    alive INTEGER NOT NULL DEFAULT 1, realm_index INTEGER NOT NULL DEFAULT 0, realm_name TEXT,
    realm_sub INTEGER DEFAULT 0, techniques TEXT, movement_arts TEXT, artifacts TEXT, assets TEXT,
    relations TEXT, status_notes TEXT, personality_traits TEXT, speech_pattern TEXT,
    secrets TEXT, goals TEXT, last_seen_ch INTEGER DEFAULT 0,
    last_breakthrough_ch INTEGER DEFAULT 0, updated_at INTEGER NOT NULL, UNIQUE(book_id, name))`,
  `CREATE INDEX IF NOT EXISTS idx_char_book ON characters(book_id)`,
  `CREATE TABLE IF NOT EXISTS lore (
    id TEXT PRIMARY KEY, book_id TEXT NOT NULL, kind TEXT NOT NULL, name TEXT NOT NULL,
    detail TEXT, tags TEXT, first_ch INTEGER DEFAULT 0, last_ch INTEGER DEFAULT 0,
    importance INTEGER DEFAULT 2, status TEXT DEFAULT '', updated_at INTEGER NOT NULL,
    UNIQUE(book_id, kind, name))`,
  `CREATE INDEX IF NOT EXISTS idx_lore_book ON lore(book_id, kind)`,
  `CREATE TABLE IF NOT EXISTS graph_edges (
    book_id TEXT NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL, rel TEXT NOT NULL,
    note TEXT, updated_ch INTEGER DEFAULT 0, updated_at INTEGER NOT NULL,
    PRIMARY KEY (book_id, src, dst, rel))`,
  `CREATE INDEX IF NOT EXISTS idx_edges_dst ON graph_edges(book_id, dst)`,
  `CREATE TABLE IF NOT EXISTS chapter_tags (
    book_id TEXT NOT NULL, tag TEXT NOT NULL, chapter_no INTEGER NOT NULL,
    PRIMARY KEY (book_id, tag, chapter_no))`,
  `CREATE TABLE IF NOT EXISTS plot_state (
    book_id TEXT NOT NULL, key TEXT NOT NULL, value TEXT, updated_at INTEGER NOT NULL,
    PRIMARY KEY (book_id, key))`,
  `CREATE TABLE IF NOT EXISTS foreshadowing (
    id TEXT PRIMARY KEY, book_id TEXT NOT NULL, title TEXT NOT NULL, detail TEXT,
    status TEXT NOT NULL DEFAULT 'planted', planted_ch INTEGER, due_ch INTEGER, resolved_ch INTEGER,
    importance INTEGER DEFAULT 2, updated_at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_fore_book ON foreshadowing(book_id, status)`,
  `CREATE TABLE IF NOT EXISTS logs (
    id TEXT PRIMARY KEY, book_id TEXT, chapter_no INTEGER, level TEXT NOT NULL DEFAULT 'info',
    stage TEXT, message TEXT, meta TEXT, created_at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_logs_book ON logs(book_id, created_at)`,
  `CREATE TABLE IF NOT EXISTS prompts (
    id TEXT PRIMARY KEY, scope TEXT NOT NULL, book_id TEXT, name TEXT NOT NULL,
    template TEXT NOT NULL, updated_at INTEGER NOT NULL)`,
];

// 老库增量升级：SQLite 不支持 ADD COLUMN IF NOT EXISTS，逐条尝试、已存在则静默跳过
const SOFT_ALTERS: string[] = [
  `ALTER TABLE characters ADD COLUMN personality_traits TEXT`,
  `ALTER TABLE characters ADD COLUMN speech_pattern TEXT`,
  `ALTER TABLE characters ADD COLUMN secrets TEXT`,
  `ALTER TABLE characters ADD COLUMN goals TEXT`,
];

let ensured = false; // 每个 isolate 只建一次

export async function ensureSchema(env: Env): Promise<void> {
  if (ensured) return;
  for (const stmt of DDL) await env.DB.prepare(stmt).run();
  for (const stmt of SOFT_ALTERS) {
    try { await env.DB.prepare(stmt).run(); } catch { /* 列已存在 */ }
  }
  ensured = true;
}
