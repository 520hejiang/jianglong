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
    max_tokens: opts.maxTokens ?? 4096,
    stream: false,
  };
  if (opts.json) body.response_format = { type: "json_object" };

  let lastErr: unknown;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 120_000); // 单次最长 120s
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
      const data: any = await res.json();
      const text: string = data?.choices?.[0]?.message?.content ?? "";
      return { text, usage: data?.usage };
    } catch (e) {
      lastErr = e;
      await sleep(1000 * Math.pow(2, attempt));
    }
  }
  throw new Error(`DeepSeek 调用失败: ${String(lastErr)}`);
}

// 要求模型返回 JSON 时的稳健解析（容忍 ```json 包裹、前后噪声）
export function parseJson<T>(raw: string): T {
  let s = raw.trim();
  const fence = s.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) s = fence[1].trim();
  const start = s.indexOf("{");
  const end = s.lastIndexOf("}");
  if (start >= 0 && end > start) s = s.slice(start, end + 1);
  return JSON.parse(s) as T;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function safeText(res: Response) {
  try { return await res.text(); } catch { return "<no body>"; }
}
