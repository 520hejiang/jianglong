# 全自动 AI 修仙小说生成系统

基于 **Cloudflare Workers + D1 + KV + Queues + Cron**，对标《凡人修仙传》硬核修仙文风，从分卷大纲全自动向下拆章、写正文、自检、更新记忆库，目标单本 200 万字以上，支持多本并发。**全部组件走 Cloudflare Free Plan。**

---

## 一、整体架构方案

```
                        ┌─────────────────────────────┐
                        │   Cloudflare Pages (控制台)   │  ← 你在这里管理
                        │  console/  新建书/启停/看记忆/改Prompt │
                        └──────────────┬──────────────┘
                                       │ REST (Bearer ADMIN_TOKEN)
                                       ▼
        ┌──────────────────────────────────────────────────────────┐
        │                Cloudflare Worker  (novel-engine)            │
        │                                                            │
        │  ① fetch     → src/api.ts     控制台 API + 公开取章 API      │
        │  ② scheduled → 每2分钟 Cron    巡检 running 的书 → 入队下一章  │
        │  ③ queue     → src/pipeline.ts 消费任务，跑完整流水线落库一章  │
        └───────┬───────────────┬──────────────┬────────────────────┘
                │               │              │
          ┌─────▼────┐   ┌──────▼─────┐   ┌────▼──────┐    ┌──────────────┐
          │   D1     │   │    KV      │   │  Queues   │    │ DeepSeek API  │
          │ 书/章节/  │   │ 锁/开关/   │   │ chapter-  │    │ deepseek-v4-  │
          │ 角色/伏笔/│   │ 限流/日报  │   │ gen 队列   │    │ flash         │
          │ 剧情/日志 │   └────────────┘   └───────────┘    └──────────────┘
          └──────────┘
                │
                └──→ Telegram Bot（每日报告 / 报错告警）
```

### 为什么这样设计能"不超时、不烧钱、不崩"

1. **避免 Serverless 超时**：写一整章要调用 DeepSeek 5~6 次，耗时数十秒到几分钟。关键点——**Worker 的 CPU 时间限制只计算计算耗时，`await fetch()` 的等待不计入 CPU 时间**。所以长文本生成在 Free Plan 也不会触发 CPU 上限。一章的全部 LLM 调用（约 6 次子请求）远低于 Free Plan 单请求 50 子请求上限。

2. **异步解耦**：Cron 只负责"巡检 + 入队"，真正耗时的生成在 **Queue 消费者**里跑。一条消息 = 一章，处理失败自动重试，最终进死信队列并 Telegram 告警，绝不阻塞其它书。

3. **多本并发**：Queue `max_concurrency=2`，不同书可并行；同一本书用 **KV 锁**（`lock:<bookId>`）保证同一时刻只生成一章，避免章节错乱。

4. **零付费组件**：用 **D1 + tags 关键词匹配**替代付费的 Vectorize 做"相关历史检索"（见下文）。Queues / Cron / KV / D1 均在 Free Plan 额度内。

### 一章的生命周期（多 Agent Pipeline）

```
读取记忆(D1) → ①焦点提取 → 检索相关历史(tag匹配) → ②单章细纲
   → ③细纲审核(战力/人设/底牌/伏笔, 最多打回2次)
   → ④正文生成(2500-3000字, 衔接上一章结尾)
   → ⑤润色+自洽 → 抽取状态增量 → 【硬规则校验】不过则重写(最多2次)
   → ⑥落库 + 应用增量(角色/伏笔/剧情) + 推进进度
```

每一步都是独立的 LLM 调用，prompt 见 `src/prompts.ts`，可在控制台按全局或单书覆盖。

---

## 二、数据库 / 记忆库设计

完整 DDL 见 [`schema.sql`](./schema.sql)。核心思想：**把战力体系结构化**，让代码（而不是 AI）守住红线。

| 表 | 作用 | 防崩要点 |
|---|---|---|
| `books` | 书 + 大纲 + 设定 + 进度 | `volume_outline` 存分卷 JSON，系统据此自动拆章 |
| `chapters` | 章节正文 + `summary` + `tags` + `ending_tail` + `version` | tags 用于无 Vectorize 检索；ending_tail 用于无缝衔接；version 支持回滚/重写 |
| `characters` | 角色**结构化**状态 | `realm_index`(境界序号,只增不无故减)、`techniques`/`artifacts`/`relations` JSON，校验器据此判断跨境界 |
| `plot_state` | 主线节点 / 已探地图 / 未了线索 | 按 key 存 JSON |
| `foreshadowing` | 伏笔**状态机** | `status: planted→developing→resolved/dropped` + `due_ch` 超期强提醒 |
| `logs` | 各阶段运行日志 | 控制台与日报数据源 |
| `prompts` | 可覆盖的 Prompt 模板 | `global:*` 或 `<bookId>:*` |

**"记忆"如何在每章前后流转**（无 Vectorize 方案）：
- **读**：`compileMemoryContext()` 把"在世角色结构化状态 + 未了伏笔 + 主线节点 + 上一章摘要 + 上一章结尾原文 + 按 tag 检索到的相关历史章节摘要"压成一段紧凑文本喂给 LLM。
- **检索**：`retrieveRelevant()` 用本章焦点实体（标签）在历史章节的 `tags`/`summary` 里打分匹配，取最相关 5 条 —— 纯 D1 查询，零成本替代向量库。
- **写**：`⑥更新` 阶段由 LLM 抽取 `StateDelta`（JSON），经**硬规则校验**后写回 `characters`/`foreshadowing`/`plot_state`。

`volume_outline` JSON 示例：
```json
[
  { "vol": 1, "title": "山村少年", "start_ch": 1, "end_ch": 60,
    "summary": "韩立入七玄门，得神秘小瓶，结识墨大夫……",
    "key_events": ["拜入七玄门", "得神秘小瓶", "墨大夫之死"] }
]
```

---

## 三、核心流转代码

完整实现见 [`src/pipeline.ts`](./src/pipeline.ts)（读取记忆→调用 LLM→更新记忆的完整串联）与 [`src/index.ts`](./src/index.ts)（Cron/Queue/HTTP 三触发面）。核心骨架：

```ts
export async function generateChapter(env, bookId, chapterNo, version = 1) {
  const book  = await M.getBook(env, bookId);
  // 0. 读取记忆，编译上下文
  const chars = await M.loadCharacters(env, bookId);
  const fores = await M.openForeshadowing(env, bookId);
  const last  = await M.lastChapter(env, bookId);

  // 1. 焦点提取 → 用 tags 检索相关历史 → 编译 memory
  const focus    = parseJson(await chat(env, [extractPrompt, ...]));
  const relevant = await M.retrieveRelevant(env, bookId, focus.must_use_entities);
  let memory     = M.compileMemoryContext({ chars, fores, relevant, lastSummary, lastTail });

  // 2~3. 细纲 → 审核（违战力铁律则打回重写）
  let outline = await genOutline(env, ..., memory);
  for (let i = 0; i < maxReviewLoop; i++) {
    const review = parseJson(await chat(env, [reviewPrompt, ...]));
    if (review.approved) break;
    outline = review.revised_outline;
  }

  // 4~5. 正文 → 润色 → 抽取增量 → 硬规则校验，不过则带反馈重写
  let finalText, delta;
  for (let attempt = 0; attempt < maxRewrite; attempt++) {
    const draft = await genDraft(env, ..., outline, memory, last.ending_tail);
    finalText   = await polish(env, ..., draft, memory);
    delta       = await extractDelta(env, ..., finalText, memory);
    const issues = validateDelta(charMap, delta, fores, chapterNo); // ← 代码级红线
    if (!hasBlocking(issues)) break;
    memory += `\n【上次违反硬规则，必须修正】\n${formatIssues(issues)}`;
  }

  // 6. 落库 + 应用增量 + 推进进度
  await M.saveChapter(env, bookId, { ...normalizeText(finalText)... });
  await applyDelta(env, bookId, chapterNo, delta);
}
```

`validateDelta()`（[`src/validators.ts`](./src/validators.ts)）实现的硬红线，靠代码断言、AI 违反就打回重写，是"几百万字不崩"的最后一道防线：

| 规则 | 作用 |
|---|---|
| `REVIVE_DEAD` | 死人不得复活（除非控制台手动改） |
| `REALM_REGRESS` | 境界无故倒退（被废/封印需在 status 注明才放行） |
| `REALM_LEAP` | 单章跨 ≥2 大境界 |
| `TECH_OVERLAYER` | 功法层数超过上限 |
| `BREAKTHROUGH_TOO_FAST` | **突破节奏**：两次大境界突破间隔 < 阈值(主角默认20章)，防升级过快 |
| `PLANE_REALM_MISMATCH` | **位面-境界一致**：未飞升却拥有超出本位面上限的境界 |
| `ASSET_NEGATIVE` / `ASSET_SURGE` | **身家账目**：灵石花成负数，或单章暴增 >家底50倍且无出处 |
| `SKILL_NO_SOURCE` | **身法/神通须随剧情习得**：新增能力无类别/来历，疑似凭空放招 |
| `FORESHADOW_OVERDUE` | 伏笔超期未回收（提醒） |

主角的**家底（灵石/丹药/材料）**、**功法/身法/神通**、**所处位面**全部结构化存于 `characters`/`books`，并在每章生成前编入上下文（`compileMemoryContext` 单列"主角家底与已习得能力"），从源头约束 LLM"只能花已有的、只能用已习得的"。新增字段见 [`migrations/002_assets_planes.sql`](./migrations/002_assets_planes.sql)。

---

## 四、核心 System Prompt 模板

全部模板见 [`src/prompts.ts`](./src/prompts.ts)，均以 `STYLE_CONSTITUTION`（世界观/主角/战力/叙事四类铁律）为前缀。两个最核心的：

- **`PROMPT_OUTLINE`（生成单章细纲）**：强制"只承担本卷大纲中属于本章的一小步""在 `power_notes` 写清谁能打过谁、主角靠什么取胜或脱身""底牌须此前已交代"，输出结构化 JSON 细纲。
- **`PROMPT_DRAFT`（生成正文）**：强制 2500-3000 字、与上一章结尾无缝衔接、冷静克制硬核文风、段间空行排版（便于一键复制）、禁现代词/英文/旁白。

> 想换一本新书 / 换风格：在控制台 Prompt 页用 `scope=book` 覆盖该书模板，或直接改 `src/prompts.ts` 的 `STYLE_CONSTITUTION`。其余逻辑零改动。

---

## 五、部署步骤（Free Plan）

```bash
npm install
npx wrangler login

# 1. 创建资源，把返回的 id 填进 wrangler.toml
npx wrangler d1 create novel_db
npx wrangler kv namespace create KV
npx wrangler queues create chapter-gen
npx wrangler queues create chapter-gen-dlq

# 2. 初始化表结构
npm run db:init:remote

# 3. 注入机密
npx wrangler secret put DEEPSEEK_API_KEY
npx wrangler secret put ADMIN_TOKEN
npx wrangler secret put TELEGRAM_BOT_TOKEN   # 可选
npx wrangler secret put TELEGRAM_CHAT_ID     # 可选

# 4. 部署 Worker（API + Cron + Queue 消费者）
npm run deploy

# 5. 部署控制台到 Pages
npx wrangler pages deploy console --project-name novel-console
```

打开控制台 → 填 Worker 地址与 `ADMIN_TOKEN` → 新建书并粘贴你的总纲/分卷大纲/设定 → 点「开始」即全自动连续生成。前端小说网站可直接调用公开接口取章：
`GET /public/books/<bookId>/chapters` 与 `GET /public/books/<bookId>/chapters/<no>`。

---

## 六、关于 `deepseek-v4-flash` 模型名

模型名通过 `wrangler.toml` 的 `DEEPSEEK_MODEL` 变量配置，默认 `deepseek-v4-flash`。若 DeepSeek 官方实际型号名不同（如 `deepseek-chat`），在 dashboard 改这一个变量即可，代码无需改动。接口走官方 `https://api.deepseek.com/chat/completions`，OpenAI 兼容格式。

---

## 目录结构

```
wrangler.toml         Cloudflare 配置（D1/KV/Queues/Cron/vars）
schema.sql            D1 表结构
src/
  index.ts            入口：fetch / scheduled / queue 三触发面
  api.ts              控制台 REST API + 公开取章 API
  pipeline.ts         多 Agent 流水线（核心）
  memory.ts           记忆库读写 + 上下文编译 + tag 检索
  prompts.ts          System Prompt 模板（凡人流铁律）
  validators.ts       硬规则校验（战力/逻辑红线）
  llm.ts              DeepSeek 客户端（重试/超时/JSON解析）
  telegram.ts         通知
  config.ts / types.ts
console/              Cloudflare Pages 控制台（原生 JS）
```
