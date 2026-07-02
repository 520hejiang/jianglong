// ============================================================================
// 类型定义 —— Cloudflare 绑定与领域模型
// ============================================================================

export interface Env {
  DB: D1Database;
  KV: KVNamespace;
  GEN_QUEUE?: Queue<GenJob>; // 可选：仅在付费计划开启 Queues 时绑定；无则走 Cron 内联生成
  // vars
  DEEPSEEK_MODEL: string;
  DEEPSEEK_BASE_URL: string;
  TARGET_CHARS_MIN: string;
  TARGET_CHARS_MAX: string;
  MAX_CONTEXT_TOKENS: string;
  MIN_BREAKTHROUGH_GAP?: string;
  POLISH_MODE?: string; // always | auto | off，默认 auto（仅在检出AI味/超限/重写时润色，省钱）
  EDITOR_MODE?: string;  // on | off，默认 on：每章过一遍 AI 主编终审（评分+硬伤扫描，不合格打回重写）
  QUALITY_BAR?: string;  // 主编评分及格线，默认 75，低于此分打回重写
  MAX_REWRITE?: string;  // 单章最多回炉次数（质检+主编共享额度），默认 3
  DRAFT_BEST_OF?: string; // 每章写N版正文由AI评委择优，默认 2
  DELTA_AUDIT?: string;   // on | off，记忆抽取二次审计，默认 on
  LLM_CALL_GAP_MS?: string; // 两次LLM调用最小间隔毫秒，默认3000，防网关限速
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
  personality_traits: string; // 性格底色（如"谨慎多疑、睚眦必报"），随剧情缓慢演化
  speech_pattern: string;     // 口癖/说话方式（如"惜字如金，爱用反问"），保证台词区分度
  secrets: string;            // 隐藏身份/不能忘的秘密（如"实为魔宗遗孤，左臂封印"）
  goals: string;              // 当前目标（如"三年内筑基，查清灭门真凶"）
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

// ============================================================================
// 设定卡（五层记忆的"数据库层"）：势力/地点/神器/神通/事件/世界规则，
// 一张卡一个实体，按 tags 检索，写到 2000 章也能精准捞回第 1 章的设定。
// ============================================================================
export type LoreKind = "faction" | "location" | "artifact" | "technique" | "event" | "worldrule";

export interface LoreEntry {
  id: string;
  book_id: string;
  kind: LoreKind;
  name: string;           // 实体名（如"天玄宗""混沌剑""叶辰被废"）
  detail: string;         // 设定正文：外观/规则/克制关系/事件经过与影响
  tags: string[];         // 检索标签（相关人物/地点/物品名）
  first_ch: number;       // 首次出现章
  last_ch: number;        // 最近提及章
  importance: number;     // 1-3，3=核心设定永不淘汰
  status: string;         // 事件用：ongoing/settled；物品用：intact/damaged/lost 等，自由文本
}

// 知识图谱边：人物-人物 / 人物-势力 / 势力-势力 的关系网
export interface GraphEdge {
  book_id: string;
  src: string;   // 起点实体名
  dst: string;   // 终点实体名
  rel: string;   // 关系（师徒/仇敌/隶属/盟友/暗恋/血亲…）
  note: string;  // 补充（因何结仇、恩情大小）
  updated_ch: number;
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
  subplot: string;              // 本章推进的支线（人情线/暗线/日常线），与主线并行
  breakthrough_due: boolean;    // 本章是否安排主角境界突破（须有契机铺垫，由细纲统筹）
  battle_scale: "none" | "skirmish" | "major"; // 本章战斗规模：无/遭遇战/大战
  battle_stages: string[];      // major 时必填：按七阶段拆解的战斗节拍（试探→神通→底牌→反转→生死一线→顿悟→绝杀，可裁剪但≥5段）
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
    // 家底增量：灵石逐笔流水（收入正/支出负，代码求和记账——绝不让模型自己合计）
    stone_moves?: { amount: number; note?: string }[];
    // 兼容字段：模型若只给净变化也接受（旧格式），有 stone_moves 时以流水求和为准
    spirit_stones_delta?: number;
    add_pills?: { name: string; count: number }[];
    add_materials?: { name: string; count: number }[];
    relations?: { name: string; type: string; attitude: string }[];
    status_notes?: string;
    personality_traits?: string; // 性格有演化时更新（如经历大变后"多了狠戾"）
    speech_pattern?: string;     // 口癖变化（一般不变）
    secrets?: string;            // 隐藏身份/秘密有变化时更新
    goals?: string;              // 当前目标有变化时更新
  }>;
  plane_change?: string; // 本章主角飞升/转换到的新位面名（如「灵界」），无则省略
  foreshadow_new: Array<{ title: string; detail: string; importance: number; due_ch?: number }>;
  foreshadow_update: Array<{ title: string; status: "developing" | "resolved" | "dropped" }>;
  // 设定卡增量：本章新出现/有变化的势力/地点/神器/神通/事件/世界规则
  lore: Array<{ kind: LoreKind; name: string; detail: string; tags?: string[]; importance?: number; status?: string }>;
  // 关系图谱增量：本章确立或变化的实体关系
  edges: Array<{ src: string; dst: string; rel: string; note?: string }>;
  plot: {
    main_node?: string;
    explored_map_add?: string[];
    open_threads?: string[];
  };
  summary: string;     // 本章 200 字内摘要
  tags: string[];      // 实体/地点/事件标签
}
