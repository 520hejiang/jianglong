-- 增量迁移：五层记忆升级（设定卡 / 知识图谱 / 标签倒排索引 / 人物性格口癖）
-- 说明：后端 ensureSchema 会自动执行等价升级，一般无需手动跑本文件。
-- 已初始化过的库如需手动升级可执行本文件（重复执行 ALTER 会报"列已存在"属正常）。
ALTER TABLE characters ADD COLUMN personality_traits TEXT;
ALTER TABLE characters ADD COLUMN speech_pattern TEXT;
ALTER TABLE characters ADD COLUMN secrets TEXT;
ALTER TABLE characters ADD COLUMN goals TEXT;

CREATE TABLE IF NOT EXISTS lore (
  id          TEXT PRIMARY KEY,
  book_id     TEXT NOT NULL,
  kind        TEXT NOT NULL,
  name        TEXT NOT NULL,
  detail      TEXT,
  tags        TEXT,
  first_ch    INTEGER DEFAULT 0,
  last_ch     INTEGER DEFAULT 0,
  importance  INTEGER DEFAULT 2,
  status      TEXT DEFAULT '',
  updated_at  INTEGER NOT NULL,
  UNIQUE(book_id, kind, name)
);
CREATE INDEX IF NOT EXISTS idx_lore_book ON lore(book_id, kind);

CREATE TABLE IF NOT EXISTS graph_edges (
  book_id     TEXT NOT NULL,
  src         TEXT NOT NULL,
  dst         TEXT NOT NULL,
  rel         TEXT NOT NULL,
  note        TEXT,
  updated_ch  INTEGER DEFAULT 0,
  updated_at  INTEGER NOT NULL,
  PRIMARY KEY (book_id, src, dst, rel)
);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON graph_edges(book_id, dst);

CREATE TABLE IF NOT EXISTS chapter_tags (
  book_id     TEXT NOT NULL,
  tag         TEXT NOT NULL,
  chapter_no  INTEGER NOT NULL,
  PRIMARY KEY (book_id, tag, chapter_no)
);
