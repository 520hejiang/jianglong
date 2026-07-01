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
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
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
        await sleep(1000 * Math.pow(2, attempt)); // 退避 1s,2s,4s
        continue;
      }
      if (!res.ok) {
  throw new Error(`LLM ${res.status}: ${await safeText(res)}`);
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
    } catch (e) {
      lastErr = e;
      await sleep(1000 * Math.pow(2, attempt));
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
    // 容错二次尝试：去尾逗号、全角引号转半角、中文逗号误用、补缺失的数组/对象间逗号
    let f = s
      .replace(/,\s*([}\]])/g, "$1")            // 尾逗号
      .replace(/[“”]/g, '"').replace(/[‘’]/g, "'") // 智能引号
      .replace(/"\s*\n\s*"/g, '",\n"')          // 相邻字符串漏逗号（"a"\n"b" -> "a",\n"b"）
      .replace(/"\s+"/g, '", "');               // 同行相邻字符串漏逗号（"a" "b"）
    return JSON.parse(f) as T;
  }
}

// 调 LLM 并要求 JSON；解析失败自动重试（降温重来），抵御模型偶发的格式不规范。
export async function chatJSON<T>(
  env: Env,
  messages: ChatMsg[],
  opts: { temperature?: number; maxTokens?: number } = {},
  tries = 3
): Promise<T> {
  let lastErr: unknown;
  for (let i = 0; i < tries; i++) {
    const r = await chat(env, messages, {
      temperature: i === 0 ? (opts.temperature ?? 0.5) : 0.15, // 重试时降温，提高 JSON 规范性
      maxTokens: opts.maxTokens,
      json: true,
    });
    try { return parseJson<T>(r.text); }
    catch (e) { lastErr = e; }
  }
  throw new Error(`JSON 解析失败(已重试${tries}次): ${String(lastErr)}`);
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function safeText(res: Response) {
  try { return await res.text(); } catch { return "<no body>"; }
}
