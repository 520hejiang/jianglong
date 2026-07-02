// ============================================================================
// 硬规则校验器 —— 不依赖 AI 自觉，用代码守住"战力/逻辑"红线。
// 在更新记忆库前对 StateDelta 做断言；违规则打回重写。
// ============================================================================
import type { CharacterState, StateDelta, Foreshadow, Plane, PowerRank } from "./types";

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
 * @param opts    配置选项
 */
export function validateDelta(
  before: Map<string, CharacterState>,
  delta: StateDelta,
  fores: Foreshadow[],
  opts: ValidateOpts
): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  const { chapterNo } = opts;
  // 位面允许的境界上限。增加类型强判，防止配置写成字符串引发误判
  const plane = opts.planes.find((p) => p.name === opts.currentPlane) || null;

  // 提前算出当前已有角色的最高境界，用于第 10 条规则（新角色凭空出世校验）
  let maxExistingRealm = 0;
  for (const c of before.values()) {
    if ((c.realm_index || 0) > maxExistingRealm) maxExistingRealm = c.realm_index || 0;
  }

  for (const cu of delta.characters) {
    const prev = before.get(cu.name);

    // --- 规则1：死人不能复活 ---
    if (prev && !prev.alive && cu.alive === true) {
      issues.push({
        level: "block",
        rule: "REVIVE_DEAD",
        detail: `角色「${cu.name}」此前已死亡，正文让其复活——需人工确认。`,
      });
    }

    // --- 规则2：境界不能无故倒退 ---
    if (prev && typeof cu.realm_index === "number" && cu.realm_index < prev.realm_index) {
      const justified = (cu.status_notes || "").match(/废|散功|跌境|重伤|封印|飞升|破空|转世|重修/);
      issues.push({
        level: justified ? "warn" : "block",
        rule: "REALM_REGRESS",
        detail: `角色「${cu.name}」境界从 ${prev.realm_index} 降到 ${cu.realm_index}${
          justified ? "（已注明原因，放行但请核对）" : "——无正当理由，疑似设定崩坏。"
        }`,
      });
    }

    // --- 规则3：单章境界跨度过大 ---
    if (prev && typeof cu.realm_index === "number" && cu.realm_index - prev.realm_index >= 2) {
      issues.push({
        level: "block",
        rule: "REALM_LEAP",
        detail: `角色「${cu.name}」单章跨 ${cu.realm_index - prev.realm_index} 大境界，数值膨胀，必须放缓。`,
      });
    }

    // --- 规则4：功法层数不能超过其上限 ---
    for (const t of cu.add_techniques || []) {
      if (t.maxLayer && t.layer > t.maxLayer) {
        issues.push({
          level: "block",
          rule: "TECH_OVERLAYER",
          detail: `「${cu.name}」功法《${t.name}》层数 ${t.layer} 超过上限 ${t.maxLayer}。`,
        });
      }
    }

    // --- 规则5：突破节奏过快 ---
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

    // --- 规则6：位面-境界一致性（增加类型强判）---
    if (plane && typeof plane.max_realm === 'number' && newIdx > plane.max_realm) {
      const ascending = !!delta.plane_change || /飞升|破空|位面|登临|渡入/.test(cu.status_notes || "");
      issues.push({
        level: ascending ? "warn" : "block",
        rule: "PLANE_REALM_MISMATCH",
        detail: `「${cu.name}」境界序 ${newIdx} 超出当前位面「${plane.name}」上限 ${plane.max_realm}${
          ascending ? "（伴随飞升，放行但请核对换算）" : "——未飞升却越位面境界，设定崩坏。"
        }`,
      });
    }

    // --- 规则7：灵石账本自洽 ---
    if (typeof cu.spirit_stones_delta === "number") {
      const before2 = prev?.assets?.spirit_stones ?? 0;
      const after = before2 + cu.spirit_stones_delta;
      // 7.1 不能算成负数
      if (after < 0) {
        issues.push({
          level: "block",
          rule: "ASSET_NEGATIVE",
          detail: `「${cu.name}」灵石将变为负数(${after})：花销超过家底，账目不自洽。`,
        });
      }
      // 7.2 防止灵石暴增（增加基础兜底 100 灵石，避免 0 资产时被误杀）
      if (cu.spirit_stones_delta > 0) {
        // 基数低时允许一定程度的自然小收入，超过 100 灵石才启动拦截
        const threshold = Math.max(before2 * opts.assetSurgeFactor, 100);
        if (cu.spirit_stones_delta > threshold) {
          const justified = /夺取|缴获|宝库|矿脉|献祭|抄家|商会|拍卖|赏赐|交易|出售|买卖/.test(cu.status_notes || "");
          issues.push({
            level: justified ? "warn" : "block",
            rule: "ASSET_SURGE",
            detail: `「${cu.name}」单章灵石暴增 ${cu.spirit_stones_delta} (超家底倍数及兜底线 ${threshold})${
              justified ? "（已注明来源，放行）" : "——来路不明，疑似数值膨胀。"
            }`,
          });
        }
      }
    }

    // --- 规则7.5：物品消耗不得超过库存（面板是唯一事实，AI 不许花不存在的东西）---
    for (const kind of ["add_pills", "add_materials"] as const) {
      for (const item of (cu[kind] || [])) {
        if (typeof item?.count !== "number" || item.count >= 0) continue; // 只查消耗
        const stockList = kind === "add_pills" ? prev?.assets?.pills : prev?.assets?.materials;
        const stock = stockList?.find((x) => x.name === item.name)?.count ?? 0;
        if (-item.count > stock) {
          issues.push({
            level: stock === 0 ? "warn" : "block", // 完全没这东西可能是命名不一致，warn 人工核；有但不够则必错，block
            rule: "ITEM_OVERDRAW",
            detail: `「${cu.name}」消耗${kind === "add_pills" ? "丹药" : "材料"}「${item.name}」${-item.count}份，但面板库存仅 ${stock}——花了不存在的东西，账目不自洽。`,
          });
        }
      }
    }

    // --- 规则8：新增能力必须有交待 ---
    for (const m of cu.add_movement_arts || []) {
      if (!m.kind) {
        issues.push({
          level: "warn",
          rule: "SKILL_NO_SOURCE",
          detail: `「${cu.name}」新增身法/神通《${m.name}》缺少类别与出处，疑似凭空获得，请在正文交代来历。`,
        });
      }
    }

    // --- 规则8.5：新增法宝必须有来历（防"幽灵法宝"污染面板） ---
    for (const a of cu.add_artifacts || []) {
      if (!a.note) {
        issues.push({
          level: "warn",
          rule: "ARTIFACT_NO_SOURCE",
          detail: `「${cu.name}」新增法宝「${a.name}」未注明获得来历（缴获/购买/赠予/炼成），疑似凭空登记，请核对正文。`,
        });
      }
    }

    // --- 规则9：新增角色境界大检视（防凭空出世的高手）---
    if (!prev && cu.name) {
      if (typeof cu.realm_index === "number" && cu.realm_index > maxExistingRealm + 3) {
        issues.push({
          level: "warn",
          rule: "NEW_CHARACTER_GOD",
          detail: `新角色「${cu.name}」首次出场即拥有境界序 ${cu.realm_index}，远超当前最高序 ${maxExistingRealm}。请核对前文是否曾铺垫或暗示过此等高手的存在。`,
        });
      }
    }
  }

  // --- 规则10：伏笔超期未回收（只报最严重的3条，防警告刷屏挤占重写提示） ---
  const overdueList = fores
    .filter((f) => f.status !== "resolved" && f.due_ch && chapterNo > f.due_ch)
    .sort((a, b) => (b.importance - a.importance) || ((chapterNo - (a.due_ch || 0)) - (chapterNo - (b.due_ch || 0))))
    .slice(0, 3);
  for (const f of overdueList) {
    issues.push({
      level: "warn",
      rule: "FORESHADOW_OVERDUE",
      detail: `伏笔「${f.title}」已超过建议回收章(${f.due_ch})，当前第 ${chapterNo} 章仍未了结。`,
    });
  }

  return issues;
}

// ---------- AI 味 / 烂俗套话检测（纯代码，零成本，用于决定是否需要润色） ----------
// 只收录确定性极高、不会被正常描写误伤的套话。补充了极度高频烂俗词汇。
const SLOP_PHRASES = [
  "空气仿佛凝固", "安静得可怕", "时间仿佛静止", "时间仿佛凝固",
  "不知过了多久", "仿佛一道惊雷", "如遭雷击", "五味杂陈", "这一切才刚刚开始", "悄然破碎",
  "嘴角勾起一抹", "嘴角勾起一丝", "眼中闪过一丝", "命运的齿轮", "无法言喻", "难以言喻",
  "心如刀绞", "瞳孔骤缩", "似乎在诉说着", "仿佛在诉说",
  "如坠冰窟", "脊背发凉", "冷汗直冒", "面色大变", "心头一紧", "脸色苍白", // 🔥 新增高频恶俗套话
  "汗毛根根", "心脏猛地一缩", "心脏漏跳", "不是错觉", // 实测11章连读发现的复读指纹
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

  // 段首单调（移植自 main_engine2 的 first-word monotony）：过多段落以"他/她/这/那/陆"等起头
  const lines = text.split(/\n+/).map((p) => p.trim()).filter((p) => p.length > 10);
  if (lines.length >= 8) {
    const boring = lines.filter((p) => /^[他她这那]/.test(p)).length;
    if (boring / lines.length > 0.45) reasons.push(`段首单调(${boring}/${lines.length}段以他/她/这/那起头，超45%)`);
  }

  // 章内高频短语复读：同一生理反应单章刷3次以上（实测"眼前发黑"一章能出现四五次）
  const OVERUSED = ["眼前发黑", "眼前一黑", "腥甜", "冷汗", "铁锈味", "咬紧牙关"];
  for (const p of OVERUSED) {
    const n = text.split(p).length - 1;
    if (n >= 3) reasons.push(`「${p}」单章出现${n}次(上限2次，换写法)`);
  }
  return { hit: reasons.length > 0, reasons };
}

// ---------- 账本泄漏检测（纯代码） ----------
// 正文里严禁出现总余额表述——总账归系统面板管，AI 报总数必错。
// 三类泄漏模式：①"还剩/只剩/共X块"；②"怀里/身上/袋中…X块灵石"式盘点；③"所有/全部灵石…X块"。
// 带交易动词(摸出/掏出/花/付/缴获…)的单笔流水不算泄漏。
const LEDGER_PATTERNS = [
  /(还剩|只剩|仅剩|尚余|共有|一共|总共|全部家当)[^。！？\n]{0,12}?[\d一二两三四五六七八九十百千]+\s*[块枚颗粒]\s*[下中上极品]{0,2}\s*灵[石晶]/g,
  /(怀里|怀中|袋里|袋中|身上|囊中|口袋)[^。！？\n]{0,10}?[\d一二两三四五六七八九十百千]+\s*[块枚颗粒]\s*[下中上极品]{0,2}\s*灵[石晶]/g,
  /(所有|全部)[^。！？\n]{0,6}灵[石晶][^。！？\n]{0,8}?[\d一二两三四五六七八九十百千]+\s*[块枚颗粒]/g,
  // 盘点式跨句报数："摸了摸灵石袋。十六块下品灵石" —— 袋后紧跟计数句
  /灵[石晶]袋[^\n]{0,8}[\d一二两三四五六七八九十百千]+\s*[块枚颗粒]/g,
  // 清点式收尾："十六块下品灵石，全在/还在/没动"
  /[\d一二两三四五六七八九十百千]+\s*[块枚颗粒]\s*[下中上极品]{0,2}\s*灵[石晶][^。！？\n]{0,6}(全在|还在|尚在|没动|未动|分文未少)/g,
  // 倒装盘点："灵石只剩两块"
  /灵[石晶][^。！？\n]{0,4}(只剩|还剩|仅剩|剩下)[^。！？\n]{0,4}[\d一二两三四五六七八九十百千]+\s*[块枚颗粒]/g,
];
const TXN_VERBS = /摸出|掏出|取出|拿出|递|拍在|扔|抛|付|花了|花去|买|换|缴获|得了|收下|塞|数出|甩/;

export function detectLedgerLeaks(text: string): SlopReport {
  const hits: string[] = [];
  for (const re of LEDGER_PATTERNS) {
    for (const m of text.match(re) || []) {
      if (!TXN_VERBS.test(m)) hits.push(m);
    }
  }
  return {
    hit: hits.length > 0,
    reasons: hits.length ? [`正文报了灵石总余额(违反系统结算铁律): ${hits.slice(0, 3).join("、")}`] : [],
  };
}

// ---------- 境界叫法校验（纯代码，按本书境界体系动态生成规则） ----------
// 层制境界(如练气1-9层)严禁叫"初期/中期/后期/巅峰"；四档制境界(筑基及以上)严禁叫"X层"。
// 检出即触发润色修正，杜绝"练气初期"这类口径漂移。
export function detectRealmMisnaming(text: string, ranks: PowerRank[]): SlopReport {
  const reasons: string[] = [];
  for (const r of ranks || []) {
    if (!r?.name || r.subLayers === 1) continue;
    if (r.subLayers === 4) {
      const hits = text.match(new RegExp(`${r.name}\\s*[一二两三四五六七八九十\\d]+\\s*层`, "g"));
      if (hits?.length) reasons.push(`「${r.name}」只分初期/中期/后期/巅峰，正文误用层数叫法: ${[...new Set(hits)].slice(0, 3).join("、")}`);
    } else {
      const hits = text.match(new RegExp(`${r.name}\\s*(?:期)?(?:初期|中期|后期|末期|巅峰)`, "g"));
      if (hits?.length) reasons.push(`「${r.name}」只按层数称呼(一层到${r.subLayers}层)，正文误用: ${[...new Set(hits)].slice(0, 3).join("、")}`);
    }
  }
  return { hit: reasons.length > 0, reasons };
}

export const hasBlocking = (issues: ValidationIssue[]) =>
  issues.some((i) => i.level === "block");

export const formatIssues = (issues: ValidationIssue[]) =>
  issues.map((i) => `[${i.level}] ${i.rule}: ${i.detail}`).join("\n");