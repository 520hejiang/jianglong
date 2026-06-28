// ============================================================================
// 运行参数 & 默认境界体系
// ============================================================================
import type { Env, PowerRank } from "./types";

export const cfg = (env: Env) => ({
  model: env.DEEPSEEK_MODEL || "deepseek-v4-flash",
  baseUrl: (env.DEEPSEEK_BASE_URL || "https://api.deepseek.com").replace(/\/$/, ""),
  charsMin: parseInt(env.TARGET_CHARS_MIN || "2500", 10),
  charsMax: parseInt(env.TARGET_CHARS_MAX || "3000", 10),
  maxContextTokens: parseInt(env.MAX_CONTEXT_TOKENS || "60000", 10),
  maxRewrite: 2,        // 正文质检不过最多重写次数
  maxReviewLoop: 2,     // 细纲审核最多打回次数
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

// 粗略 token 估算（中文约 1.5 字/token，留余量按 1 字 ≈ 0.6 token 估）
export const estTokens = (s: string) => Math.ceil(s.length * 0.6);
