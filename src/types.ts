// ============================================================================
// 类型定义 —— Cloudflare 绑定与领域模型
// ============================================================================

export interface Env {
  DB: D1Database;
  KV: KVNamespace;
  GEN_QUEUE: Queue<GenJob>;
  // vars
  DEEPSEEK_MODEL: string;
  DEEPSEEK_BASE_URL: string;
  TARGET_CHARS_MIN: string;
  TARGET_CHARS_MAX: string;
  MAX_CONTEXT_TOKENS: string;
  MIN_BREAKTHROUGH_GAP?: string;
  // secrets
  DEEPSEEK_API_KEY: string;
  TELEGRAM_BOT_TOKEN?: string;
  TELEGRAM_CHAT_ID?: string;
  ADMIN_TOKEN: string;
}

// 队列任务：生成某本书的某一章
export interface GenJob {
  bookId: string;
  chapterNo: number;
  reason: "cron" | "manual" | "rewrite";
  // rewrite 时携带：要重写的版本会 +1
}

// ---- 领域模型（与 D1 表对应） ----
export interface Book {
  id: string;
  title: string;
  status: "running" | "paused" | "finished" | "error";
  master_outline: string | null;
  volume_outline: string | null; // JSON Volume[]
  core_settings: string | null;
  power_system: string | null; // JSON PowerRank[]
  planes: string | null; // JSON Plane[]
  current_plane: string | null;
  style_prompt_override: string | null;
  next_chapter: number;
  target_chapters: number | null;
  total_chars: number;
  cursor_volume: number;
  last_error: string | null;
  created_at: number;
  updated_at: number;
}

export interface Volume {
  vol: number;
  title: string;
  start_ch: number;
  end_ch: number;
  summary: string;
  key_events: string[];
}

// 境界体系：下标即 realm_index，越大越强。校验器据此判断跨境界。
export interface PowerRank {
  index: number;
  name: string;      // 炼气 / 筑基 / 结丹 / 元婴 ...
  subLayers: number; // 该大境界包含的小层数，如炼气 13 层
}

export interface CharacterState {
  id: string;
  book_id: string;
  name: string;
  aliases: string[];
  role: "protagonist" | "ally" | "enemy" | "npc";
  alive: boolean;
  realm_index: number;
  realm_name: string;
  realm_sub: number;
  techniques: { name: string; layer: number; maxLayer: number }[];
  movement_arts: { name: string; kind: string; grade?: string; note?: string }[];
  artifacts: { name: string; grade: string; durability: number; note?: string }[];
  assets: Assets;
  relations: { name: string; type: string; attitude: string }[];
  status_notes: string;
  last_seen_ch: number;
  last_breakthrough_ch: number;
}

// 家底：灵石 + 丹药 + 材料 + 杂项，net worth 追踪，防凭空暴涨/为负
export interface Assets {
  spirit_stones: number;
  pills: { name: string; count: number }[];
  materials: { name: string; count: number }[];
  misc: string[];
}

export const emptyAssets = (): Assets => ({ spirit_stones: 0, pills: [], materials: [], misc: [] });

// 位面：min/max 为境界序号区间，用于"位面-境界一致性"校验
export interface Plane {
  name: string;
  min_realm: number;
  max_realm: number;
}

export interface Foreshadow {
  id: string;
  title: string;
  detail: string;
  status: "planted" | "developing" | "resolved" | "dropped";
  planted_ch: number | null;
  due_ch: number | null;
  resolved_ch: number | null;
  importance: number;
}

// 单章细纲（outline 阶段产出）
export interface ChapterOutline {
  title: string;
  goal: string;                 // 本章在主线中的作用
  beats: string[];              // 3-6 个情节节拍
  characters: string[];         // 出场角色
  location: string;
  conflicts: string;            // 核心冲突/危机
  protagonist_cards: string[];  // 主角本章可动用的底牌/筹谋
  foreshadow_plant: string[];   // 本章拟埋伏笔
  foreshadow_resolve: string[]; // 本章拟回收伏笔
  power_notes: string;          // 战力边界提醒（谁能打过谁）
  hook: string;                 // 章末钩子
}

// 记忆更新增量（update 阶段由 LLM 抽取）
export interface StateDelta {
  characters: Array<{
    name: string;
    realm_index?: number;
    realm_name?: string;
    realm_sub?: number;
    alive?: boolean;
    breakthrough?: boolean; // 本章是否发生"大境界"突破（realm_index 提升）
    add_techniques?: { name: string; layer: number; maxLayer: number }[];
    add_movement_arts?: { name: string; kind: string; grade?: string; note?: string }[]; // 本章新习得的身法/神通/秘术
    add_artifacts?: { name: string; grade: string; durability: number; note?: string }[];
    // 家底增量：灵石净变化（正得负耗），丹药/材料的增减
    spirit_stones_delta?: number;
    add_pills?: { name: string; count: number }[];
    add_materials?: { name: string; count: number }[];
    relations?: { name: string; type: string; attitude: string }[];
    status_notes?: string;
  }>;
  plane_change?: string; // 本章主角飞升/转换到的新位面名（如「灵界」），无则省略
  foreshadow_new: Array<{ title: string; detail: string; importance: number; due_ch?: number }>;
  foreshadow_update: Array<{ title: string; status: "developing" | "resolved" | "dropped" }>;
  plot: {
    main_node?: string;
    explored_map_add?: string[];
    open_threads?: string[];
  };
  summary: string;     // 本章 200 字内摘要
  tags: string[];      // 实体/地点/事件标签
}
