-- ============================================================================
-- D1 数据库结构：全自动修仙小说生成系统（优化版）
-- 设计原则：
--   1. 结构化战力体系（境界/功法/法宝做成可被代码校验的字段），防数值膨胀。
--   2. 伏笔有完整生命周期状态机，防忘填坑。
--   3. 章节带 summary + tags，用 tag 匹配实现"记忆检索"，无需付费 Vectorize。
--   4. 一切可手动修改（控制台直接改 D1），用于人工防崩。
--   5. 增加必要索引，优化查询性能。
-- ============================================================================

-- 启用外键支持（建议在连接时设置 PRAGMA foreign_keys = ON）
-- 注意：D1 默认可能不启用，但可执行。本脚本不包含外键约束，但保留了兼容性。

-- ---------- 书 ----------
CREATE TABLE IF NOT EXISTS books (
  id            TEXT PRIMARY KEY,              -- uuid
  title         TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'paused',-- running | paused | finished | error
  -- 大纲与设定（导入时填）
  master_outline TEXT,                         -- 总纲
  volume_outline TEXT,                         -- 分卷大纲（JSON 数组，见下方说明）
  core_settings  TEXT,                         -- 核心设定集（世界观/势力/地理/历法等，长文本）
  power_system   TEXT,                         -- 境界体系定义（JSON，见 power_ranks 说明）
  planes         TEXT,                         -- 位面定义（JSON：[{name,min_realm,max_realm}]），用于位面-境界一致性校验
  current_plane  TEXT,                         -- 当前所处位面名（随飞升剧情推进，校验器据此判断越界）
  style_prompt_override TEXT,                  -- 可选：覆盖默认文风 system prompt
  -- 进度
  next_chapter   INTEGER NOT NULL DEFAULT 1,   -- 下一个要生成的章号
  target_chapters INTEGER DEFAULT 800,         -- 目标章节数（200万字 / ~2700字 ≈ 740 章）
  total_chars    INTEGER NOT NULL DEFAULT 0,
  -- 运行控制
  cursor_volume  INTEGER NOT NULL DEFAULT 0,   -- 当前在第几卷（volume_outline 下标）
  last_error     TEXT,
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL
);

-- 索引：快速查询运行中的书籍，及按状态排序
CREATE INDEX IF NOT EXISTS idx_books_status ON books(status);
CREATE INDEX IF NOT EXISTS idx_books_next ON books(next_chapter);

-- volume_outline JSON 示例：
-- [
--   { "vol": 1, "title": "山村少年", "start_ch": 1, "end_ch": 60,
--     "summary": "韩立入七玄门...", "key_events": ["拜入七玄门","得神秘小瓶","..."] },
--   ...
-- ]

-- ---------- 章节 ----------
CREATE TABLE IF NOT EXISTS chapters (
  id          TEXT PRIMARY KEY,
  book_id     TEXT NOT NULL,
  chapter_no  INTEGER NOT NULL,
  title       TEXT,
  outline     TEXT,                            -- 本章细纲（JSON）
  content     TEXT,                            -- 正文（已排版）
  summary     TEXT,                            -- 200字内的剧情摘要（喂给下一章）
  ending_tail TEXT,                            -- 结尾原文(末300字)，用于无缝衔接
  tags        TEXT,                            -- JSON 数组：本章涉及的实体/地点/事件标签
  word_count  INTEGER DEFAULT 0,
  status      TEXT NOT NULL DEFAULT 'draft',   -- draft | done | failed
  version     INTEGER NOT NULL DEFAULT 1,      -- 重写次数，支持回滚
  qc_report   TEXT,                            -- 质检报告（JSON）
  created_at  INTEGER NOT NULL,
  UNIQUE(book_id, chapter_no, version)
);
-- 索引：按书和章节号查询，以及按状态过滤已完成章节
CREATE INDEX IF NOT EXISTS idx_chapters_book ON chapters(book_id, chapter_no);
CREATE INDEX IF NOT EXISTS idx_chapters_status ON chapters(book_id, status);

-- ---------- 角色状态（结构化，防战力崩坏） ----------
CREATE TABLE IF NOT EXISTS characters (
  id          TEXT PRIMARY KEY,
  book_id     TEXT NOT NULL,
  name        TEXT NOT NULL,
  aliases     TEXT,                            -- JSON 数组：别名/道号
  role        TEXT,                            -- protagonist | ally | enemy | npc
  alive       INTEGER NOT NULL DEFAULT 1,      -- 1 活 / 0 死（手动可改）
  -- 战力（结构化，校验器据此判断"是否跨大境界杀敌"）
  realm_index INTEGER NOT NULL DEFAULT 0,      -- 境界序号，对应 power_ranks 下标，只增不无故减
  realm_name  TEXT,                            -- 境界名（炼气/筑基/结丹...）
  realm_sub   INTEGER DEFAULT 0,               -- 小层数（如炼气几层）
  techniques  TEXT,                            -- JSON：功法列表 [{name,layer,maxLayer}]
  movement_arts TEXT,                          -- JSON：身法/神通/秘术 [{name,kind,grade,note}]，须随剧情习得方可用
  artifacts   TEXT,                            -- JSON：法宝列表 [{name,grade,durability,note}]
  assets      TEXT,                            -- JSON：家底 {spirit_stones, pills:[{name,count}], materials:[{name,count}], misc:[]}
  relations   TEXT,                            -- JSON：人脉 [{name,type,attitude}]
  status_notes TEXT,                           -- 当前处境/伤势/秘密
  last_seen_ch INTEGER DEFAULT 0,
  last_breakthrough_ch INTEGER DEFAULT 0,      -- 上次大境界突破章，用于突破节奏校验
  updated_at  INTEGER NOT NULL,
  UNIQUE(book_id, name)
);
-- 索引：按书查询所有角色，以及按角色类型/存活状态筛选
CREATE INDEX IF NOT EXISTS idx_char_book ON characters(book_id);
CREATE INDEX IF NOT EXISTS idx_char_role ON characters(role);
CREATE INDEX IF NOT EXISTS idx_char_alive ON characters(alive);

-- ---------- 剧情状态（全局单行/少行，按 key 存） ----------
CREATE TABLE IF NOT EXISTS plot_state (
  book_id     TEXT NOT NULL,
  key         TEXT NOT NULL,                   -- main_node | explored_map | factions | timeline | open_threads
  value       TEXT,                            -- JSON
  updated_at  INTEGER NOT NULL,
  PRIMARY KEY (book_id, key)
);
-- 注意：plot_state 本身按主键查询，无需额外索引

-- ---------- 伏笔（带生命周期状态机，防忘填坑） ----------
CREATE TABLE IF NOT EXISTS foreshadowing (
  id          TEXT PRIMARY KEY,
  book_id     TEXT NOT NULL,
  title       TEXT NOT NULL,                   -- 伏笔简述
  detail      TEXT,
  status      TEXT NOT NULL DEFAULT 'planted', -- planted | developing | resolved | dropped
  planted_ch  INTEGER,                         -- 埋下章
  due_ch      INTEGER,                         -- 建议回收章（超期会在审核时强提醒）
  resolved_ch INTEGER,
  importance  INTEGER DEFAULT 2,               -- 1 低 2 中 3 主线级
  updated_at  INTEGER NOT NULL
);
-- 索引：按书和状态查询活跃伏笔，以及按重要性排序
CREATE INDEX IF NOT EXISTS idx_fore_book ON foreshadowing(book_id, status);
CREATE INDEX IF NOT EXISTS idx_fore_importance ON foreshadowing(importance);

-- ---------- 运行日志 ----------
CREATE TABLE IF NOT EXISTS logs (
  id          TEXT PRIMARY KEY,
  book_id     TEXT,
  chapter_no  INTEGER,
  level       TEXT NOT NULL DEFAULT 'info',    -- info | warn | error
  stage       TEXT,                            -- extract|outline|review|draft|polish|update|cron|queue
  message     TEXT,
  meta        TEXT,                            -- JSON（如 token 用量、耗时）
  created_at  INTEGER NOT NULL
);
-- 索引：按书和时间检索日志，以及按级别筛选
CREATE INDEX IF NOT EXISTS idx_logs_book ON logs(book_id, created_at);
CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(level);

-- ---------- 可编辑的全局 / 单书 Prompt 模板 ----------
CREATE TABLE IF NOT EXISTS prompts (
  id          TEXT PRIMARY KEY,               -- 形如 "global:outline" 或 "<bookId>:draft"
  scope       TEXT NOT NULL,                  -- global | book
  book_id     TEXT,
  name        TEXT NOT NULL,                  -- outline | review | draft | polish | extract | update
  template    TEXT NOT NULL,
  updated_at  INTEGER NOT NULL
);
-- 索引：加速按 scope 和 book_id 查找模板
CREATE INDEX IF NOT EXISTS idx_prompts_scope ON prompts(scope, book_id);