// ============================================================================
// 运行参数 & 默认境界体系
// ============================================================================
import type { Env, PowerRank, Plane } from "./types";

export const cfg = (env: Env) => ({
  model: env.DEEPSEEK_MODEL || "deepseek-v4-flash",
  baseUrl: (env.DEEPSEEK_BASE_URL || "https://api.deepseek.com").replace(/\/$/, ""),
  charsMin: parseInt(env.TARGET_CHARS_MIN || "2000", 10),
  charsMax: parseInt(env.TARGET_CHARS_MAX || "2400", 10),
  maxContextTokens: parseInt(env.MAX_CONTEXT_TOKENS || "60000", 10),
  maxRewrite: parseInt(env.MAX_REWRITE || "3", 10),  // 单章最多回炉次数（代码质检+AI主编共享额度）
  maxReviewLoop: 2,     // 细纲审核最多打回次数

  // AI 主编终审：每章定稿后过一遍主编（评分+硬伤扫描），不合格打回重写。
  // 追求极致质量时开启（默认 on）；qualityBar 为及格线。
  editorMode: (env.EDITOR_MODE || "on") as "on" | "off",
  qualityBar: parseInt(env.QUALITY_BAR || "75", 10),

  // 极致质量三件套（不差钱模式，全部默认开启）：
  bestOf: parseInt(env.DRAFT_BEST_OF || "2", 10),          // 每章写N版正文，AI评委择优（1=关闭）
  deltaAudit: (env.DELTA_AUDIT || "on") as "on" | "off",   // 记忆抽取二次审计：AI对照正文复核账目/道具/境界
  consistencyEvery: 10,                                     // 每N章一次全书连贯性巡检，矛盾自动生成找补指令
  
  // 【核心修改】：主角"大境界"突破的最小章节间隔基数。
  // 防突破节奏过快。后期此值会在管线（pipeline/validators）校验中进行指数级放大：
  // 实际间隔 = minBreakthroughGap * (1.5 ^ realm_index)
  // 效果：炼气(20章) -> 筑基(30章) -> 金丹(45章) -> 元婴(67章)... 保障500万字战力不崩
  minBreakthroughGap: parseInt(env.MIN_BREAKTHROUGH_GAP || "20", 10),
  
  // 单章灵石净增幅超过此倍数（相对此前家底）且无重大事件，视为数值膨胀告警
  assetSurgeFactor: 50,
  
  // 润色策略：always=每章都润色；auto=仅在检出AI味/篇幅超限/重写时润色(默认,省钱)；off=从不润色
  polishMode: (env.POLISH_MODE || "auto") as "always" | "auto" | "off",
});

// 默认境界体系（对标凡人流，可在控制台按书覆盖 books.power_system）
export const DEFAULT_POWER_RANKS: PowerRank[] = [
  { index: 0, name: "炼气", subLayers: 13 },
  { index: 1, name: "筑基", subLayers: 12 },
  { index: 2, name: "结丹", subLayers: 9 },
  { index: 3, name: "元婴", subLayers: 9 },
  { index: 4, name: "化神", subLayers: 9 },
  { index: 5, name: "炼虚", subLayers: 9 },
  { index: 6, name: "合体", subLayers: 9 },
  { index: 7, name: "大乘", subLayers: 9 },
  { index: 8, name: "渡劫", subLayers: 9 },
];

// 默认位面划分（按默认凡人流 9 阶境界；多位面书如《玄天鼎尊》应在 books.planes 自定义）
export const DEFAULT_PLANES: Plane[] = [
  { name: "凡界", min_realm: 0, max_realm: 8 },
];

// 粗略 token 估算（中文约 1.5 字/token，留余量按 1 字 ≈ 0.6 token 估）
export const estTokens = (s: string) => Math.ceil(s.length * 0.6);