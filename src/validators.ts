// ============================================================================
// 硬规则校验器 —— 不依赖 AI 自觉，用代码守住"战力/逻辑"红线。
// 在更新记忆库前对 StateDelta 做断言；违规则打回重写。
// ============================================================================
import type { CharacterState, StateDelta, Foreshadow } from "./types";

export interface ValidationIssue {
  level: "block" | "warn";
  rule: string;
  detail: string;
}

/**
 * 校验本章产出的状态增量是否违反硬规则。
 * @param before  本章生成前的角色快照（name -> state）
 * @param delta   本章抽取出的状态变更
 * @param fores   当前未回收的伏笔
 * @param chapterNo 当前章号
 */
export function validateDelta(
  before: Map<string, CharacterState>,
  delta: StateDelta,
  fores: Foreshadow[],
  chapterNo: number
): ValidationIssue[] {
  const issues: ValidationIssue[] = [];

  for (const cu of delta.characters) {
    const prev = before.get(cu.name);

    // 规则1：死人不能复活（除非手动在控制台改 alive）
    if (prev && !prev.alive && cu.alive === true) {
      issues.push({
        level: "block",
        rule: "REVIVE_DEAD",
        detail: `角色「${cu.name}」此前已死亡，正文让其复活——需人工确认。`,
      });
    }

    // 规则2：境界不能无故倒退（被废修为属剧情，需在 status_notes 标注"被废/自废"）
    if (prev && typeof cu.realm_index === "number" && cu.realm_index < prev.realm_index) {
      const justified = (cu.status_notes || "").match(/废|散功|跌境|重伤|封印/);
      issues.push({
        level: justified ? "warn" : "block",
        rule: "REALM_REGRESS",
        detail: `角色「${cu.name}」境界从 ${prev.realm_index} 降到 ${cu.realm_index}${
          justified ? "（已注明原因，放行但请核对）" : "——无正当理由，疑似设定崩坏。"
        }`,
      });
    }

    // 规则3：单章境界暴涨（跨大境界）。炼气→筑基这种属正常突破；一次跳 ≥2 大境界异常。
    if (prev && typeof cu.realm_index === "number" && cu.realm_index - prev.realm_index >= 2) {
      issues.push({
        level: "block",
        rule: "REALM_LEAP",
        detail: `角色「${cu.name}」单章跨 ${cu.realm_index - prev.realm_index} 大境界，数值膨胀，必须放缓。`,
      });
    }

    // 规则4：功法层数不能超过其上限
    for (const t of cu.add_techniques || []) {
      if (t.maxLayer && t.layer > t.maxLayer) {
        issues.push({
          level: "block",
          rule: "TECH_OVERLAYER",
          detail: `「${cu.name}」功法《${t.name}》层数 ${t.layer} 超过上限 ${t.maxLayer}。`,
        });
      }
    }
  }

  // 规则5：伏笔超期未回收（不阻断，仅提醒审核阶段优先安排回收）
  for (const f of fores) {
    if (f.status !== "resolved" && f.due_ch && chapterNo > f.due_ch) {
      issues.push({
        level: "warn",
        rule: "FORESHADOW_OVERDUE",
        detail: `伏笔「${f.title}」已超过建议回收章(${f.due_ch})，当前第 ${chapterNo} 章仍未了结。`,
      });
    }
  }

  return issues;
}

export const hasBlocking = (issues: ValidationIssue[]) =>
  issues.some((i) => i.level === "block");

export const formatIssues = (issues: ValidationIssue[]) =>
  issues.map((i) => `[${i.level}] ${i.rule}: ${i.detail}`).join("\n");
