// ============================================================================
// 运行参数 & 默认境界体系
// ============================================================================
import type { Env, PowerRank, Plane } from "./types";

export const cfg = (env: Env) => ({
  model: env.DEEPSEEK_MODEL || "deepseek-v4-flash",
  baseUrl: (env.DEEPSEEK_BASE_URL || "https://api.deepseek.com").replace(/\/$/, ""),
  charsMin: parseInt(env.TARGET_CHARS_MIN || "2500", 10),
  charsMax: parseInt(env.TARGET_CHARS_MAX || "3000", 10),
  maxContextTokens: parseInt(env.MAX_CONTEXT_TOKENS || "60000", 10),
  maxRewrite: 2,        // 正文质检不过最多重写次数
  maxReviewLoop: 2,     // 细纲审核最多打回次数
  // 主角"大境界"突破的最小章节间隔：防突破节奏过快（写着写着崩）。
  // 默认 20 章；非主角可放宽一半。控制台/单书可按需调整。
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
