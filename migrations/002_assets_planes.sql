-- 增量迁移：家底 / 身法 / 突破节奏 / 位面字段
-- 若是全新数据库，直接跑 schema.sql 即可，无需本文件。
-- 已初始化过的库执行本文件升级（SQLite 不支持 IF NOT EXISTS 列，重复执行会报错属正常）。
ALTER TABLE characters ADD COLUMN movement_arts TEXT;
ALTER TABLE characters ADD COLUMN assets TEXT;
ALTER TABLE characters ADD COLUMN last_breakthrough_ch INTEGER DEFAULT 0;
ALTER TABLE books ADD COLUMN planes TEXT;
ALTER TABLE books ADD COLUMN current_plane TEXT;
