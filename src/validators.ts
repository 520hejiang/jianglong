// ============================================================================
// 硬规则校验器 —— 不依赖 AI 自觉，用代码守住"战力/逻辑"红线。
// 在更新记忆库前对 StateDelta 做断言；违规则打回重写。
// ============================================================================
import type { CharacterState, StateDelta, Foreshadow, Plane } from "./types";

export interface ValidationIssue {
  level: "block" | "warn";
  rule: string;
  detail: string;
}

export interface ValidateOpts {
  chapterNo: number;
  planes: Plane[];           // 本书位面定义（空数组则跳过位面校验）
  currentPlane: string | null;
  minBreakthroughGap: number;
  assetSurgeFactor: number;
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
  opts: ValidateOpts
): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  const { chapterNo } = opts;
  // 位面允许的境界上限（当前位面 max_realm）；多位面书飞升前不得越界
  const plane = opts.planes.find((p) => p.name === opts.currentPlane) || null;

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

    // 规则5：突破节奏。两次"大境界"突破间隔过短 -> 升级过快，写着写着崩。
    const newIdx = typeof cu.realm_index === "number" ? cu.realm_index : prev?.realm_index ?? 0;
    const isBreakthrough = !!cu.breakthrough || (prev && newIdx > prev.realm_index);
    if (prev && isBreakthrough && newIdx > prev.realm_index) {
      const gap = chapterNo - (prev.last_breakthrough_ch || 0);
      const required = prev.role === "protagonist" ? opts.minBreakthroughGap : Math.ceil(opts.minBreakthroughGap / 2);
      if (prev.last_breakthrough_ch > 0 && gap < required) {
        issues.push({
          level: "block",
          rule: "BREAKTHROUGH_TOO_FAST",
          detail: `「${cu.name}」距上次大境界突破仅 ${gap} 章(<${required})，升级过快，需拉长沉淀。`,
        });
      }
    }

    // 规则6：位面-境界一致性。飞升前不得拥有超出本位面上限的境界。
    if (plane && newIdx > plane.max_realm) {
      const ascending = !!delta.plane_change || /飞升|破空|位面|登临|渡入/.test(cu.status_notes || "");
      issues.push({
        level: ascending ? "warn" : "block",
        rule: "PLANE_REALM_MISMATCH",
        detail: `「${cu.name}」境界序 ${newIdx} 超出当前位面「${plane.name}」上限 ${plane.max_realm}${
          ascending ? "（伴随飞升，放行但请核对换算）" : "——未飞升却越位面境界，设定崩坏。"
        }`,
      });
    }

    // 规则7：身家不能凭空暴涨 / 不能为负。
    if (typeof cu.spirit_stones_delta === "number") {
      const before2 = prev?.assets?.spirit_stones ?? 0;
      const after = before2 + cu.spirit_stones_delta;
      if (after < 0) {
        issues.push({
          level: "block",
          rule: "ASSET_NEGATIVE",
          detail: `「${cu.name}」灵石将变为负数(${after})：花销超过家底，账目不自洽。`,
        });
      }
      if (cu.spirit_stones_delta > 0 && before2 > 0 && cu.spirit_stones_delta > before2 * opts.assetSurgeFactor) {
        const justified = /夺取|缴获|宝库|矿脉|献祭|抄家|商会|拍卖|赏赐/.test(cu.status_notes || "");
        issues.push({
          level: justified ? "warn" : "block",
          rule: "ASSET_SURGE",
          detail: `「${cu.name}」单章灵石暴增 ${cu.spirit_stones_delta}(超家底${opts.assetSurgeFactor}倍)${
            justified ? "（已注明来源，放行）" : "——来路不明，疑似数值膨胀。"
          }`,
        });
      }
    }

    // 规则8：身法/神通/秘术须随剧情习得 —— 新增能力必须带类别与出处，杜绝凭空放招。
    for (const m of cu.add_movement_arts || []) {
      if (!m.kind) {
        issues.push({
          level: "warn",
          rule: "SKILL_NO_SOURCE",
          detail: `「${cu.name}」新增身法/神通《${m.name}》缺少类别与出处，疑似凭空获得，请在正文交代来历。`,
        });
      }
    }
  }

  // 规则9：伏笔超期未回收（不阻断，仅提醒审核阶段优先安排回收）
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

// ---------- AI 味 / 烂俗套话检测（纯代码，零成本，用于决定是否需要润色） ----------
// 注意：只收录"足够具体、不会误伤正常行文"的套话。像"的气息""弥漫着""这是一个"
// 这类碎片会命中大量正常句子（如"练气七层的气息"），一律不收，否则润色被无谓触发、白花钱。
const SLOP_PHRASES = [
  "空气仿佛凝固", "空气中仿佛凝固", "安静得可怕", "空气中弥漫着", "时间仿佛静止", "时间仿佛凝固",
  "不知过了多久", "仿佛一道惊雷", "如遭雷击", "五味杂陈", "这一切才刚刚开始", "悄然破碎",
  "嘴角勾起一抹", "嘴角勾起一丝", "眼中闪过一丝", "命运的齿轮", "无法言喻", "难以言喻",
  "心如刀绞", "瞳孔骤缩", "似乎在诉说着", "仿佛在诉说",
];

export interface SlopReport {
  hit: boolean;
  reasons: string[];
}

// 扫描正文，返回是否疑似 AI 腔（命中套话 / 比喻词过密 / 段落过于均匀）。
export function detectSlop(text: string): SlopReport {
  const reasons: string[] = [];
  const hits = SLOP_PHRASES.filter((p) => text.includes(p));
  if (hits.length) reasons.push(`烂俗套话: ${hits.slice(0, 5).join("、")}`);

  // 比喻词密度：仿佛/宛如/犹如/好似/如同 —— 每千字超过 6 次视为过密
  const simile = (text.match(/仿佛|宛如|犹如|好似|如同/g) || []).length;
  const per1k = simile / Math.max(1, text.length / 1000);
  if (per1k > 6) reasons.push(`比喻词过密(${simile}处)`);

  // 段落长度过于均匀（AI 倾向等长段）：变异系数过低
  const paras = text.split(/\n{2,}/).map((p) => p.replace(/\s/g, "").length).filter((n) => n > 0);
  if (paras.length >= 6) {
    const mean = paras.reduce((a, b) => a + b, 0) / paras.length;
    const sd = Math.sqrt(paras.reduce((a, b) => a + (b - mean) ** 2, 0) / paras.length);
    if (mean > 0 && sd / mean < 0.25) reasons.push("段落长度过于均匀(疑似AI节奏)");
  }
  return { hit: reasons.length > 0, reasons };
}

export const hasBlocking = (issues: ValidationIssue[]) =>
  issues.some((i) => i.level === "block");

export const formatIssues = (issues: ValidationIssue[]) =>
  issues.map((i) => `[${i.level}] ${i.rule}: ${i.detail}`).join("\n");
