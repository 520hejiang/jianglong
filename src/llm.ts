// ============================================================================
// DeepSeek 官方 API 客户端
//   - 关键：fetch 等待属于 I/O，不计入 Worker CPU 时间，长文本生成不会触发
//     Free Plan 的 CPU 上限；一次生成一整章正文也安全。
//   - 内置重试 + 超时 + JSON 解析容错。
// ============================================================================
import type { Env } from "./types";
import { cfg } from "./config";

export interface ChatMsg {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface LLMResult {
  text: string;
  usage?: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
}

export async function chat(
  env: Env,
  messages: ChatMsg[],
  opts: { temperature?: number; maxTokens?: number; json?: boolean } = {}
): Promise<LLMResult> {
  const c = cfg(env);
  const body: Record<string, unknown> = {
    model: c.model,
    messages,
    temperature: opts.temperature ?? 0.8,
    max_tokens: opts.maxTokens ?? 9192,
    stream: false,
  };
// if (opts.json) body.response_format = { type: "json_object" };

  let lastErr: unknown;
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      await throttle(c.llmCallGapMs); // 调用间强制间隔，压平突发速率防 429
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 999_000); // 单次最长 999s
      const res = await fetch(`${c.baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${env.DEEPSEEK_API_KEY}`,
        },
        body: JSON.stringify(body),
        signal: ctrl.signal,
      });
      clearTimeout(timer);

      if (res.status === 429 || res.status >= 500) {
        lastErr = new Error(`LLM ${res.status}: ${await safeText(res)}`);
        // 429 用长退避(5s,10s,20s,40s,60s)等限速窗口过去；5xx 用短退避
        await sleep(res.status === 429
          ? Math.min(60_000, 5000 * Math.pow(2, attempt))
          : 1000 * Math.pow(2, attempt));
        continue;
      }
      if (!res.ok) {
        // 4xx（密钥无效/参数错误）重试也不会好，直接失败，不空耗退避时间
        const e: any = new Error(`LLM ${res.status}: ${await safeText(res)}`);
        e.fatal = true;
        throw e;
      }

// ★★★ 核心升级：先读纯文本，防止空内容直接崩掉 ★★★
const rawText = await res.text();

// 如果返回的是完全空的字符串
if (!rawText || rawText.trim() === "") {
  throw new Error(`API 返回了空内容 (状态码: ${res.status})。可能是 Cloudflare 超时、Token 失效或请求被拦截。`);
}

let data: any;
try {
  data = JSON.parse(rawText);
} catch (e) {
  // ★★★ 杀手锏：把 API 返回的真实内容截取一段，直接塞进报错信息里 ★★★
  const snippet = rawText.length > 300 ? rawText.substring(0, 300) + "..." : rawText;
  throw new Error(`响应不是有效的 JSON。API 返回的原始内容: ${snippet}`);
}
// --- 插入这段诊断逻辑 ---
    if (data?.error) {
      throw new Error(`🚨 API 隐性错误: ${JSON.stringify(data.error)}`);
    }
    if (data?.result?.response) {
      return { text: data.result.response, usage: data?.result?.usage };
    }
    if (!data?.choices?.[0]?.message) {
      throw new Error(`🚨 接口回包格式异常，找不到 choices！真实回包是: ${rawText}`);
    }
    // --- 插入结束 ---
const text: string = data?.choices?.[0]?.message?.content ?? "";
return { text, usage: data?.usage };
    } catch (e: any) {
      lastErr = e;
      if (e?.fatal) break; // 4xx 类错误重试无意义，立刻报出去
      // 空回包多半是网关被限速后的软失败，与 429 同等对待用长退避
      const rateish = String(e?.message || e).includes("空内容");
      await sleep(rateish ? Math.min(60_000, 5000 * Math.pow(2, attempt)) : 1000 * Math.pow(2, attempt));
    }
  }
  throw new Error(`DeepSeek 调用失败: ${String(lastErr)}`);
}

// 要求模型返回 JSON 时的稳健解析（容忍 ```json 包裹、前后噪声、尾逗号、智能引号等常见瑕疵）
export function parseJson<T>(raw: string): T {
  // 🚨 第一步就判空，防止 API 返回空白导致直接崩溃
  if (!raw || raw.trim() === "") {
    throw new Error(`[parseJson 判空] API 返回的内容是空白的 (长度: ${raw.length})，无法解析。可能是 OpenCode 额度用尽或回包出错。`);
  }

  let s = raw.trim();
  const fence = s.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) s = fence[1].trim();
  const start = s.indexOf("{");
  const end = s.lastIndexOf("}");
  if (start >= 0 && end > start) s = s.slice(start, end + 1);
  try {
    return JSON.parse(s) as T;
  } catch {
    // 容错二次尝试：去尾逗号、全角引号转半角、补缺失的数组/对象间逗号
    const f = s
      .replace(/,\s*([}\]])/g, "$1")            // 尾逗号
      .replace(/[“”]/g, '"').replace(/[‘’]/g, "'") // 智能引号
      .replace(/"\s*\n\s*"/g, '",\n"')          // 相邻字符串漏逗号（"a"\n"b" -> "a",\n"b"）
      .replace(/"\s+"/g, '", "');               // 同行相邻字符串漏逗号（"a" "b"）
    try {
      return JSON.parse(f) as T;
    } catch {
      // 终极修复：补值后漏逗号 + 转义字符串内部的裸英文双引号（mimo 高频翻车点）
      return JSON.parse(repairJson(f)) as T;
    }
  }
}

// 深度修复常见的 LLM JSON 语法伤：
//   1) 值结尾（"、}、]、数字、true/false/null）换行后直接跟下一个 "key" 却漏了逗号
//   2) 字符串值内部出现未转义的英文双引号（如 detail:"他说"滚""）——用状态机判定该引号
//      是否真的在收尾（后面跟 , } ] : 或换行才算收尾），否则转义之
function repairJson(s: string): string {
  const commaFixed = s.replace(/(["}\]0-9el])[ \t]*\n(\s*")/g, "$1,\n$2");
  let out = "";
  let inStr = false;
  for (let i = 0; i < commaFixed.length; i++) {
    const c = commaFixed[i];
    if (!inStr) {
      if (c === '"') inStr = true;
      out += c;
      continue;
    }
    if (c === "\\") { out += c + (commaFixed[i + 1] ?? ""); i++; continue; }
    if (c === '"') {
      let j = i + 1;
      while (j < commaFixed.length && (commaFixed[j] === " " || commaFixed[j] === "\t" || commaFixed[j] === "\r")) j++;
      const nxt = commaFixed[j];
      if (nxt === undefined || nxt === "," || nxt === "}" || nxt === "]" || nxt === ":" || nxt === "\n") {
        inStr = false; out += c;       // 合法收尾引号
      } else {
        out += '\\"';                  // 字符串内部的裸引号，转义保内容
      }
      continue;
    }
    out += c;
  }
  return out;
}

// 调 LLM 并要求 JSON；解析失败自动重试。重试时：
//   1) 降温提高规范性；2) 把上次的坏输出和报错回喂给模型，让它知道错在哪；
//   3) 每次把 maxTokens 提高 50%——大量解析失败其实是 JSON 写到一半被截断。
export async function chatJSON<T>(
  env: Env,
  messages: ChatMsg[],
  opts: { temperature?: number; maxTokens?: number } = {},
  tries = 3
): Promise<T> {
  let lastErr: unknown;
  let lastRaw = "";
  let maxTokens = opts.maxTokens;
  for (let i = 0; i < tries; i++) {
    const msgs: ChatMsg[] = i === 0 || !lastRaw ? messages : [
      ...messages,
      { role: "assistant", content: lastRaw.slice(0, 6000) },
      { role: "user", content: `你上面输出的 JSON 解析失败：${String(lastErr).slice(0, 200)}。请重新输出一份完整、合法的 JSON，规则：字符串值内部一律用中文引号「」，绝不出现未转义的英文双引号；所有括号必须闭合、逗号必须完整；除 JSON 本身外不要输出任何文字。` },
    ];
    const r = await chat(env, msgs, {
      temperature: i === 0 ? (opts.temperature ?? 0.5) : 0.15,
      maxTokens,
      json: true,
    });
    try { return parseJson<T>(r.text); }
    catch (e) {
      lastErr = e; lastRaw = r.text;
      if (maxTokens) maxTokens = Math.ceil(maxTokens * 1.5); // 防截断：逐次放宽输出上限
    }
  }
  const snippet = lastRaw ? `｜模型原始输出首尾: ${lastRaw.slice(0, 160)} …… ${lastRaw.slice(-160)}` : "";
  throw new Error(`JSON 解析失败(已重试${tries}次): ${String(lastErr)}${snippet}`);
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// 同一次执行内的调用节流：两次 LLM 调用之间至少间隔 minGap 毫秒，
// 把 13 道工序的连环调用压平成匀速流，避免触发网关"每分钟请求数"限速。
let _lastCallAt = 0;
async function throttle(minGap: number) {
  if (!minGap || minGap <= 0) return;
  const wait = _lastCallAt + minGap - Date.now();
  if (wait > 0) await sleep(wait);
  _lastCallAt = Date.now();
}
async function safeText(res: Response) {
  try { return await res.text(); } catch { return "<no body>"; }
}
