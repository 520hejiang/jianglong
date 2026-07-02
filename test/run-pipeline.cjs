/* ============================================================================
 * 本地端到端测试：用 mock 的 DeepSeek（globalThis.fetch）+ 真实 SQLite(node:sqlite)
 * 把整条流水线跑 26 章，验证：存库 / 校验器 / 家底增减 / 突破节奏 / 身法 / 伏笔 / 位面。
 * 不花一分钱 DeepSeek。
 *
 * 运行：  npm run test:pipeline   （先 tsc 编译到 .testbuild，再 node 跑本文件）
 * ==========================================================================*/
'use strict';
const { DatabaseSync } = require('node:sqlite');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const BUILD = path.join(ROOT, '.testbuild');
const memory = require(path.join(BUILD, 'memory.js'));
const pipeline = require(path.join(BUILD, 'pipeline.js'));
const validators = require(path.join(BUILD, 'validators.js'));

// ---------------- D1 / KV mock（节点内置 SQLite，跑真实 SQL）----------------
const coerce = (v) => (typeof v === 'boolean' ? (v ? 1 : 0) : v === undefined ? null : v);
class Stmt {
  constructor(db, sql) { this.db = db; this.sql = sql; this.args = []; }
  bind(...a) { this.args = a.map(coerce); return this; }
  async first(col) {
    const row = this.db.prepare(this.sql).get(...this.args);
    if (row === undefined || row === null) return null;
    return col ? row[col] : row;
  }
  async all() { return { results: this.db.prepare(this.sql).all(...this.args), success: true, meta: {} }; }
  async run() { const i = this.db.prepare(this.sql).run(...this.args); return { success: true, meta: { changes: i.changes } }; }
}
class D1 { constructor(db) { this.db = db; } prepare(sql) { return new Stmt(this.db, sql); } }
class KV {
  constructor() { this.m = new Map(); }
  async get(k) { return this.m.has(k) ? this.m.get(k) : null; }
  async put(k, v) { this.m.set(k, String(v)); }
  async delete(k) { this.m.delete(k); }
}

// ---------------- mock DeepSeek：按 system prompt 判定阶段，返回假数据 ----------------
const calls = { extract: 0, outline: 0, review: 0, draft: 0, polish: 0, editor: 0, update: 0 };

function spiritDelta(ch) {
  if (ch % 5 === 0) return 30;       // 缴获
  if (ch === 6 || ch === 26) return -20; // 突破耗材
  return 6;
}
function makeDraft(ch) {
  // 段落长度刻意不均、规避烂俗套话与高频比喻，确保 detectSlop 不命中 → auto 模式跳过润色
  const paras = [
    `陆长安蹲在墙角，盯着地上那截断指。`,
    `他没急着动。袖中三枚毒粉还剩两枚，够用，但他不想浪费——这年头，连一撮‘化骨散’都要拿命去换。坊市外的暗巷阴冷潮湿，墙缝里渗着不知名的水，滴答，滴答，砸在他破旧的草鞋上，凉意一路爬进脚底。`,
    `“又是个想黑吃黑的。”他心里冷笑，面上却不动声色。`,
    `对面那名散修比他高出一头，练气七层的修为粗豪外放，把他这个面黄肌瘦的杂役当成了案板上的肉。可惜，这块肉里裹着刀。陆长安替他算了笔账：这种人身上多半有十几块下品灵石、一两件趁手的法器，运气好还能摸出半瓶丹药。够喂小鼎一顿了。`,
    `他缓缓退后半步，脚跟在湿滑的青石上轻轻一碾，留下一道几乎看不见的浅痕。四象困煞阵的最后一个阵眼，就埋在那儿。`,
    `要的不是硬拼，是对方一脚踏进死地的那一瞬。`,
    `散修冷哼一声，欺身而上，五指箕张抓向他天灵。`,
    `就是现在。陆长安两指一弹，灰白毒粉无声散开，脚下阵纹骤亮，一股阴冷煞气自地底翻涌，死死缠住对方下盘。那散修脸色剧变，想退，膝盖却像被灌了铅，沉得抬不起来。他张口要骂，喉咙里先涌上一阵腥甜。`,
    `“你他娘的……阴人！”`,
    `“嗯。”陆长安应得平静，像在回应一句天气。他不急，看着毒性一寸寸爬上对方的脖颈，看着那双瞪圆的眼睛里凶光褪去、惊惶涌起，最后只剩下不甘。他见过太多这种眼神，早就麻木了。`,
    `这一行当没有同情。今天他不动手，明天躺在阴沟里的就是自己。`,
    `半炷香后，巷子里只剩他一人。陆长安蹲下身，熟练地翻找尸体，储物袋、玉佩、半瓶丹药，统统揣进怀里，动作快得像做过千百遍。最后，他从对方眉心剜出一缕尚有余温的魂血，珍而重之地收进一只漆黑小瓶。`,
    `识海深处，那口巴掌大的古鼎微微一颤，传来一丝餍足的悸动，紧接着又是一股按捺不住的、贪婪的渴求。`,
    `“就这点东西，还喂不饱你。”陆长安低骂一句，把尸体拖进阴沟，盖好烂草。做完这些，他才靠墙坐下，长长吐出一口浊气，后背早被冷汗浸透，双手也在轻轻发抖——不是怕，是绷得太紧之后的脱力。`,
    `谨慎，再谨慎。他能从那场灭门里爬出来活到今天，靠的从来不是运气，是把每一步都算到死。`,
    `远处传来巡值弟子的脚步声。他不慌不忙拢了拢破旧的灰袍，低着头，像一道再普通不过的影子，融进坊市灰蒙蒙的人流里。`,
  ];
  // 每 8 章注入一次烂俗套话，触发 detectSlop → 验证 auto 润色确实会被触发
  if (ch % 8 === 0) paras.unshift(`空气仿佛凝固，不知过了多久，他嘴角勾起一抹弧度。`);
  return `第${ch}章 测试章节\n\n` + paras.join('\n\n');
}
function makeDelta(ch) {
  const cu = { name: '陆长安', status_notes: `第${ch}章后，蛰伏暗处，警觉异常。` };
  // 混用两种记账格式：偶数章走流水制(代码求和)，奇数章走旧净值制(兼容)；ch=7 拆成两笔验证求和
  if (ch === 7) cu.stone_moves = [{ amount: 10, note: '缴获' }, { amount: -4, note: '买丹' }]; // 净+6=spiritDelta(7)
  else if (ch % 2 === 0) cu.stone_moves = [{ amount: spiritDelta(ch), note: '单笔' }];
  else cu.spirit_stones_delta = spiritDelta(ch);
  if (ch % 5 === 0) cu.status_notes += ' 缴获散修储物袋。';
  if (ch === 6) { Object.assign(cu, { realm_index: 1, realm_name: '筑基', realm_sub: 1, breakthrough: true }); cu.status_notes += ' 强行突破筑基。'; }
  else if (ch === 26) { Object.assign(cu, { realm_index: 2, realm_name: '结丹', realm_sub: 1, breakthrough: true }); cu.status_notes += ' 结成紫金丹。'; }
  else cu.realm_sub = Math.min(13, 1 + (ch % 5));
  if (ch === 10) cu.add_movement_arts = [{ name: '鬼魅步', kind: '身法', note: '夺自暗巷散修' }];
  if (ch === 15) cu.add_movement_arts = [{ name: '血遁', kind: '秘术', note: '血煞炼骨诀衍生' }];
  if (ch === 4) cu.add_pills = [{ name: '疗伤丹', count: 3 }];
  if (ch === 12) cu.add_pills = [{ name: '疗伤丹', count: -1 }];
  const d = { characters: [cu], foreshadow_new: [], foreshadow_update: [], plot: { main_node: `第${ch}章主线推进` },
    summary: `第${ch}章：陆长安在暗巷黑吃黑，斩杀散修，收割精血与灵石。`, tags: ['陆长安', '暗巷', '黑吃黑', '玄元小鼎'] };
  if (ch === 3) d.foreshadow_new = [{ title: '神秘玉简', detail: '死者掉落的古老玉简，暂无法参透', importance: 3, due_ch: 18 }];
  if (ch === 9) {
    d.lore = [{ kind: 'artifact', name: '玄元小鼎', detail: '噬魂养鼎，吞魂血而长，克阴魂类，忌雷法', tags: ['陆长安'], importance: 3, status: 'intact' }];
    d.edges = [{ src: '陆长安', dst: '黑水帮', rel: '仇敌', note: '暗巷黑吃黑结怨' }];
  }
  if (ch === 11) d.lore = [{ kind: 'event', name: '黑水帮堂主暴毙', detail: '陆长安暗杀黑水帮堂主，帮内震怒悬赏，坊市巡查趋严', tags: ['陆长安', '黑水帮'], importance: 2, status: 'ongoing' }];
  if (ch === 18) d.foreshadow_update = [{ title: '神秘玉简', status: 'resolved' }];
  if (ch === 7) d.plot.explored_map_add = ['乱葬岗'];
  if (ch === 24) d.plane_change = '灵界'; // 合成的位面机制测试点
  return JSON.stringify(d);
}
function chMatch(s) { const m = s.match(/第\s*(\d+)\s*章/); return m ? +m[1] : 1; }

globalThis.fetch = async (_url, init) => {
  const body = JSON.parse(init.body);
  const sys = body.messages[0].content;
  const usr = body.messages[body.messages.length - 1].content;
  const ch = chMatch(sys + usr);
  let content;
  if (sys.includes('剧情连贯性助手')) { calls.extract++; content = JSON.stringify({ focus: `第${ch}章焦点`, must_use_entities: ['陆长安', '柳青蝉', '暗巷'], continuity_risks: [], due_foreshadow: [] }); }
  else if (sys.includes('生成一份单章细纲')) { calls.outline++; content = JSON.stringify({ title: `暗巷杀机${ch}`, goal: '推进主线', beats: ['踩点', '伏击', '收割'], characters: ['陆长安'], location: '坊市暗巷', conflicts: '黑吃黑', protagonist_cards: ['毒粉', '四象困煞阵'], foreshadow_plant: [], foreshadow_resolve: [], power_notes: '同阶险胜', hook: '有人在暗处盯着他', subplot: '与柳青蝉的暗中交易推进一步', breakthrough_due: ch === 26, battle_scale: 'skirmish', battle_stages: [] }); }
  else if (sys.includes('严格的设定校验官')) { calls.review++; content = JSON.stringify({ approved: true, issues: [], revised_outline: {} }); }
  else if (sys.includes('根据细纲撰写')) { calls.draft++; content = makeDraft(ch); }
  else if (sys.includes('终审')) { calls.editor++; content = JSON.stringify({ score: 86, verdict: 'pass', fatal_issues: [], advice: ['结尾钩子可以更狠一点'] }); }
  else if (sys.includes('老编辑') || sys.includes('润色')) { calls.polish++; content = makeDraft(ch).replace(/空气仿佛凝固，不知过了多久，他嘴角勾起一抹弧度。\n\n/, ''); }
  else if (sys.includes('抽取本章发生的状态变化')) { calls.update++; content = makeDelta(ch); }
  else content = '{}';
  return new Response(JSON.stringify({ choices: [{ message: { content } }], usage: { prompt_tokens: 50, completion_tokens: 50, total_tokens: 100 } }), { status: 200, headers: { 'content-type': 'application/json' } });
};

// ---------------- 测试主体 ----------------
const C = { g: '\x1b[32m', r: '\x1b[31m', y: '\x1b[33m', d: '\x1b[2m', x: '\x1b[0m' };
let pass = 0, fail = 0;
function ok(cond, label, extra = '') { if (cond) { pass++; console.log(`${C.g}✓${C.x} ${label} ${C.d}${extra}${C.x}`); } else { fail++; console.log(`${C.r}✗ ${label}${C.x} ${extra}`); } }

async function main() {
  const db = new DatabaseSync(':memory:');
  db.exec(fs.readFileSync(path.join(ROOT, 'schema.sql'), 'utf8'));
  const env = {
    DB: new D1(db), KV: new KV(), GEN_QUEUE: { send: async () => {} },
    DEEPSEEK_MODEL: 'mock', DEEPSEEK_BASE_URL: 'http://mock', TARGET_CHARS_MIN: '2500',
    TARGET_CHARS_MAX: '3000', MAX_CONTEXT_TOKENS: '60000', MIN_BREAKTHROUGH_GAP: '20',
    POLISH_MODE: 'auto', DEEPSEEK_API_KEY: 'x', ADMIN_TOKEN: 'x',
  };

  // 用真实大纲 JSON 建书
  const book = JSON.parse(fs.readFileSync(path.join(ROOT, 'outlines', '玄天鼎尊.book.json'), 'utf8'));
  const bookId = 'test-book-1';
  const t = Date.now();
  await env.DB.prepare(
    `INSERT INTO books (id,title,status,master_outline,volume_outline,core_settings,power_system,planes,current_plane,style_prompt_override,next_chapter,target_chapters,total_chars,cursor_volume,created_at,updated_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0,0,?,?)`
  ).bind(bookId, book.title, 'running', ...[book.master_outline, book.volume_outline, book.core_settings,
    book.power_system, book.planes].map((v) => (typeof v === 'string' || v == null) ? v : JSON.stringify(v)),
    book.current_plane, book.style_prompt_override, 1, 1850, t, t).run();
  for (const c of book.characters) await memory.upsertCharacter(env, bookId, c);

  console.log(`\n${C.y}== 用真实《玄天鼎尊》大纲建书，mock LLM 连跑 26 章 ==${C.x}`);
  console.log(`${C.d}初始：主角灵石 ${book.characters.find(c => c.role === 'protagonist').assets.spirit_stones}，位面 ${book.current_plane}${C.x}\n`);

  const N = 26;
  const allIssues = [];
  for (let ch = 1; ch <= N; ch++) {
    const res = await pipeline.generateChapter(env, bookId, ch, 1);
    if (res.issues.length) allIssues.push(`第${ch}章: ${res.issues.join(' | ')}`);
    process.stdout.write(`\r${C.d}已生成 ${ch}/${N} 章…${C.x}`);
  }
  console.log('\n');

  // ---- 断言 ----
  const cnt = await env.DB.prepare("SELECT COUNT(*) c FROM chapters WHERE book_id=? AND status='done'").bind(bookId).first();
  ok(cnt.c === N, '26 章全部入库', `实际 ${cnt.c}`);

  const hero = (await memory.loadCharacters(env, bookId)).find(c => c.role === 'protagonist');
  ok(hero.realm_index === 2 && hero.realm_name === '结丹', '主角境界 练气→筑基→结丹', `序${hero.realm_index} ${hero.realm_name}`);
  ok(hero.last_breakthrough_ch === 26, '突破章号正确记录', `last_breakthrough_ch=${hero.last_breakthrough_ch}`);

  // 灵石账目：起始值 + 各章净变化（混用流水制与净值制，验证代码求和记账）
  const seedStones = book.characters.find(c => c.role === 'protagonist').assets.spirit_stones;
  let expStones = seedStones; for (let ch = 1; ch <= N; ch++) expStones += spiritDelta(ch);
  ok(hero.assets.spirit_stones === expStones, '灵石账目逐章自洽(流水由代码求和)', `账面 ${hero.assets.spirit_stones} / 期望 ${expStones}`);

  // 章末结算单：代码生成、落库、期末余额与面板一致
  const settle = await memory.getPlot(env, bookId, 'last_settlement');
  ok(typeof settle === 'string' && settle.includes(`期末灵石=${expStones}块`), '章末结算单落库且期末余额=面板实数', String(settle).slice(0, 60));

  // 账本泄漏检测：正文报总余额必须被抓，单笔流水不误伤
  const leak1 = validators.detectLedgerLeaks('他数了数，全部家当只剩三块下品灵石，心里发苦。');
  const leak2 = validators.detectLedgerLeaks('他摸出两块灵石拍在案上，又缴获七块下品灵石。');
  ok(leak1.hit === true, '报总余额("只剩三块灵石")被检出', leak1.reasons.join(''));
  ok(leak2.hit === false, '单笔收支表述不误伤');

  // 账本泄漏加宽：盘点式总余额也要抓，交易流水不误伤
  const leak3 = validators.detectLedgerLeaks('他摸了摸怀里的灵石袋。十六块下品灵石，全在。');
  const leak4 = validators.detectLedgerLeaks('他卷起怀中所有灵石——十块下品灵石——拍进鼎里。');
  const leak5 = validators.detectLedgerLeaks('他从怀里摸出三块下品灵石递过去。');
  ok(leak3.hit === true, '盘点式总余额("怀里…十六块灵石")被检出', leak3.reasons.join(''));
  ok(leak4.hit === true, '"所有灵石…十块"式总余额被检出', leak4.reasons.join(''));
  ok(leak5.hit === false, '"怀里摸出三块"交易流水不误伤');

  // 整章去重：标题中段复现 / 长段落复写 均被截断
  const dd1 = pipeline.dedupeChapter('开头正文。'.repeat(150) + '\n第5章 测试标题\n' + '后半重复内容。'.repeat(100), 5);
  ok(!dd1.includes('第5章') , '正文中段重复标题被截断', `长度${dd1.length}`);
  const longPara = '这是一个足够长的段落专门用来做指纹检测字数必须超过六十个字才有效所以这里再补充相当多的内容来凑够长度限制确保通过六十字的段落过滤门槛不出岔子。';
  const dd2 = pipeline.dedupeChapter('前文铺垫。'.repeat(120) + '\n' + longPara + '\n' + '中间过渡。'.repeat(120) + '\n' + longPara + '\n尾部残余', 6);
  ok(!dd2.endsWith('尾部残余') && dd2.includes(longPara), '长段落复写从第二次出现处截断', `长度${dd2.length}`);

  // 境界叫法检测：层制境界(练气9层)禁"初中后巅峰"，四档制(筑基+)禁"X层"
  const ranks = [{ index: 0, name: '练气', subLayers: 9 }, { index: 1, name: '筑基', subLayers: 4 }];
  const rn1 = validators.detectRealmMisnaming('那老者已是练气后期修为，护卫不过练气三层。', ranks);
  const rn2 = validators.detectRealmMisnaming('管事乃筑基三层的高手。', ranks);
  const rn3 = validators.detectRealmMisnaming('他不过练气三层，对面却是筑基中期的老怪。', ranks);
  ok(rn1.hit === true && rn1.reasons.join('').includes('练气'), '层制境界误用"练气后期"被检出', rn1.reasons.join(''));
  ok(rn2.hit === true && rn2.reasons.join('').includes('筑基'), '四档境界误用"筑基三层"被检出', rn2.reasons.join(''));
  ok(rn3.hit === false, '正确叫法(练气三层/筑基中期)不误伤');

  const moveNames = hero.movement_arts.map(m => m.name);
  ok(moveNames.includes('鬼魅步') && moveNames.includes('血遁'), '身法/神通随剧情累加且不丢失', `[${moveNames.join('、')}]`);

  const pill = hero.assets.pills.find(p => p.name === '疗伤丹');
  ok(pill && pill.count === 2, '丹药增减正确(得3用1=2)', `疗伤丹×${pill ? pill.count : 0}`);

  const fores = await env.DB.prepare('SELECT title,status FROM foreshadowing WHERE book_id=?').bind(bookId).all();
  const yu = fores.results.find(f => f.title === '神秘玉简');
  ok(yu && yu.status === 'resolved', '伏笔生命周期 planted→resolved', `神秘玉简: ${yu ? yu.status : '缺失'}`);
  const open = await memory.openForeshadowing(env, bookId);
  ok(!open.find(f => f.title === '神秘玉简'), '已回收伏笔不再出现在"未了结"列表');

  const bk = await memory.getBook(env, bookId);
  ok(bk.current_plane === '灵界', '位面随飞升(plane_change)更新', `current_plane=${bk.current_plane}`);
  ok(bk.next_chapter === 27, '进度推进 next_chapter=27', `=${bk.next_chapter}`);

  // 五层记忆：设定卡 / 事件 / 图谱 / 倒排索引
  const ding = await env.DB.prepare("SELECT * FROM lore WHERE book_id=? AND kind='artifact' AND name='玄元小鼎'").bind(bookId).first();
  ok(ding && ding.first_ch === 9, '设定卡(神器)落库且记录首见章', `first_ch=${ding ? ding.first_ch : '缺失'}`);
  const evt = await env.DB.prepare("SELECT * FROM lore WHERE book_id=? AND kind='event'").bind(bookId).first();
  ok(evt && evt.name === '黑水帮堂主暴毙', '事件系统落库(时间线)', evt ? `第${evt.first_ch}章 ${evt.name}` : '缺失');
  const edge = await env.DB.prepare("SELECT * FROM graph_edges WHERE book_id=? AND src='陆长安' AND dst='黑水帮'").bind(bookId).first();
  ok(edge && edge.rel === '仇敌', '知识图谱关系边落库', edge ? `${edge.src}-[${edge.rel}]->${edge.dst}` : '缺失');
  const tagIdx = await env.DB.prepare("SELECT COUNT(*) c FROM chapter_tags WHERE book_id=? AND tag='玄元小鼎'").bind(bookId).first();
  ok(tagIdx.c >= 20, '章节标签倒排索引已建立', `玄元小鼎 命中 ${tagIdx.c} 章`);
  const rag = await memory.retrieveRelevant(env, bookId, ['黑吃黑'], 3);
  ok(rag.length === 3 && rag.every((r) => r.summary.includes('黑吃黑')), 'RAG 按标签精准召回历史章节', rag.map((r) => `第${r.chapter_no}章`).join('、'));
  const loreHits = await memory.relevantLore(env, bookId, ['玄元小鼎', '黑水帮'], 12);
  ok(loreHits.some((l) => l.name === '玄元小鼎') && loreHits.some((l) => l.kind === 'event'), '设定卡按实体检索召回(含标签模糊命中)', loreHits.map((l) => l.name).join('、'));

  // 篇幅与排版
  const ch5 = await env.DB.prepare('SELECT content,word_count FROM chapters WHERE book_id=? AND chapter_no=5').bind(bookId).first();
  ok(ch5.content.startsWith('第5章 '), '正文自带规范标题行(无重复)', ch5.content.slice(0, 10));
  ok(!/\n{3,}/.test(ch5.content), '排版规整(无多余空行)');
  ok(ch5.word_count > 300, '字数已统计', `${ch5.word_count} 字`);

  // 省钱：auto 模式应跳过大部分润色（仅 ch%8==0 触发）
  const expPolish = Math.floor(N / 8); // 8,16,24
  ok(calls.polish <= expPolish + 1, `auto 润色按需触发省钱`, `draft ${calls.draft} 次 / polish 仅 ${calls.polish} 次(省 ${calls.draft - calls.polish} 次)`);

  // AI 主编终审：每章都过审，评分随质检报告归档
  ok(calls.editor >= N, 'AI 主编终审每章执行', `editor 调用 ${calls.editor} 次`);
  const qcRow = await env.DB.prepare("SELECT qc_report FROM chapters WHERE book_id=? AND chapter_no=10").bind(bookId).first();
  const qcObj = JSON.parse(qcRow.qc_report);
  ok(qcObj.editor_score === 86, '主编评分写入质检报告', `score=${qcObj.editor_score}`);

  // LENGTH 是 warn 级，且 mock 正文刻意偏短(真实 LLM 写满 2500-3000 不会触发)，故剔除后再断言"无其它误报"
  const realIssues = allIssues.map(s => s.replace(/\[warn\] LENGTH:[^;]*?字，短于目标下限 \d+/g, '').replace(/第\d+章:\s*\|?\s*/g, '').trim()).filter(Boolean);
  ok(realIssues.length === 0, '正常推进无误报(LENGTH warn 因 mock 正文偏短属预期, 已剔除)', realIssues.join(' ;; '));
  console.log(`  ${'\x1b[2m'}注: 26 章均有 LENGTH warn —— 这是质检在正确提示"正文偏短"(mock 仅 890 字), 真实生成写满字数即不触发${'\x1b[0m'}`);

  // ---- Part B: 直接单测六条硬规则确实会拦 ----
  console.log(`\n${C.y}== 硬规则拦截单测（构造违规增量，确认每条都触发）==${C.x}`);
  const planes = JSON.parse(book.planes);
  const baseOpts = { chapterNo: 30, planes, currentPlane: '凡界', minBreakthroughGap: 20, assetSurgeFactor: 50 };
  const mkChar = (o) => Object.assign({ id: 'x', book_id: bookId, name: '陆长安', aliases: [], role: 'protagonist', alive: true, realm_index: 1, realm_name: '筑基', realm_sub: 1, techniques: [], movement_arts: [], artifacts: [], assets: { spirit_stones: 10, pills: [], materials: [], misc: [] }, relations: [], status_notes: '', last_seen_ch: 25, last_breakthrough_ch: 5 }, o);
  const fire = (before, delta, opts, rule) => {
    const issues = validators.validateDelta(new Map(before.map(c => [c.name, c])), delta, [], opts || baseOpts);
    return issues.find(i => i.rule === rule);
  };
  ok(fire([mkChar({ alive: false })], { characters: [{ name: '陆长安', alive: true }], foreshadow_new: [], foreshadow_update: [], plot: {} }, baseOpts, 'REVIVE_DEAD'), '规则 REVIVE_DEAD 拦截死人复活');
  ok(fire([mkChar({ realm_index: 1 })], { characters: [{ name: '陆长安', realm_index: 3 }], foreshadow_new: [], foreshadow_update: [], plot: {} }, baseOpts, 'REALM_LEAP'), '规则 REALM_LEAP 拦截单章跨2大境界');
  ok(fire([mkChar({ realm_index: 2, last_breakthrough_ch: 28 })], { characters: [{ name: '陆长安', realm_index: 3, breakthrough: true }], foreshadow_new: [], foreshadow_update: [], plot: {} }, baseOpts, 'BREAKTHROUGH_TOO_FAST'), '规则 BREAKTHROUGH_TOO_FAST 拦截升级过快');
  ok(fire([mkChar({ assets: { spirit_stones: 10, pills: [], materials: [], misc: [] } })], { characters: [{ name: '陆长安', spirit_stones_delta: -50 }], foreshadow_new: [], foreshadow_update: [], plot: {} }, baseOpts, 'ASSET_NEGATIVE'), '规则 ASSET_NEGATIVE 拦截灵石花成负数');
  ok(fire([mkChar({ realm_index: 4 })], { characters: [{ name: '陆长安', realm_index: 6, status_notes: '闭关' }], foreshadow_new: [], foreshadow_update: [], plot: {} }, baseOpts, 'PLANE_REALM_MISMATCH'), '规则 PLANE_REALM_MISMATCH 拦截未飞升越位面境界');
  ok(fire([mkChar({})], { characters: [{ name: '陆长安', add_movement_arts: [{ name: '神秘瞳术', kind: '' }] }], foreshadow_new: [], foreshadow_update: [], plot: {} }, baseOpts, 'SKILL_NO_SOURCE'), '规则 SKILL_NO_SOURCE 提示身法无出处');
  const overdraw = fire([mkChar({ assets: { spirit_stones: 10, pills: [{ name: '疗伤丹', count: 1 }], materials: [], misc: [] } })],
    { characters: [{ name: '陆长安', add_pills: [{ name: '疗伤丹', count: -3 }] }], foreshadow_new: [], foreshadow_update: [], plot: {} }, baseOpts, 'ITEM_OVERDRAW');
  ok(overdraw && overdraw.level === 'block', '规则 ITEM_OVERDRAW 拦截消耗超库存(有1颗吃3颗)');
  const ghostItem = fire([mkChar({})],
    { characters: [{ name: '陆长安', add_pills: [{ name: '九转还魂丹', count: -1 }] }], foreshadow_new: [], foreshadow_update: [], plot: {} }, baseOpts, 'ITEM_OVERDRAW');
  ok(ghostItem && ghostItem.level === 'warn', '规则 ITEM_OVERDRAW 提示消耗不存在的物品(warn防命名误伤)');

  // ---- Part C: 断点续传(advanceBook)——模拟"每走一步就被掐断"，确认仍能接力完成整章 ----
  console.log(`\n${C.y}== 断点续传测试（每次只跑一步，模拟被平台掐断后续传）==${C.x}`);
  const before27 = (await env.DB.prepare("SELECT COUNT(*) c FROM chapters WHERE book_id=?").bind(bookId).first()).c;
  let status = 'progress', steps = 0;
  while (status !== 'completed' && steps < 20) {
    status = await pipeline.advanceBook(env, bookId, 1); // budget=1ms 强制每次只走一步
    steps++;
  }
  const after27 = (await env.DB.prepare("SELECT COUNT(*) c FROM chapters WHERE book_id=?").bind(bookId).first()).c;
  ok(status === 'completed' && after27 === before27 + 1, '断点续传多次接力后成功产出新一章', `用了 ${steps} 步, 章节数 ${before27}→${after27}`);
  const genjob = await env.DB.prepare("SELECT value FROM plot_state WHERE book_id=? AND key='__genjob'").bind(bookId).first();
  ok(!genjob || genjob.value === 'null' || genjob.value === null, '完成后生成存档已清空(不会卡住下一章)');

  // ---- Part D: 重写——就地覆盖(不新增重复行), 不重复应用状态(灵石不变) ----
  console.log(`\n${C.y}== 重写测试（断点续传式重写第5章, 覆盖不新增、不改状态）==${C.x}`);
  const heroBefore = (await memory.loadCharacters(env, bookId)).find(c => c.role === 'protagonist');
  const stonesBefore = heroBefore.assets.spirit_stones;
  const rowsBefore = (await env.DB.prepare("SELECT COUNT(*) c FROM chapters WHERE book_id=? AND chapter_no=5").bind(bookId).first()).c;
  await pipeline.startRewrite(env, bookId, 5);
  let rwStatus = 'progress', rwSteps = 0;
  while (rwStatus !== 'completed' && rwSteps < 20) { rwStatus = await pipeline.advanceBook(env, bookId, 1); rwSteps++; }
  const rowsAfter = (await env.DB.prepare("SELECT COUNT(*) c FROM chapters WHERE book_id=? AND chapter_no=5").bind(bookId).first()).c;
  const heroAfter = (await memory.loadCharacters(env, bookId)).find(c => c.role === 'protagonist');
  ok(rwStatus === 'completed' && rowsAfter === 1 && rowsAfter === rowsBefore, '重写就地覆盖, 不产生重复章行', `第5章行数 ${rowsBefore}→${rowsAfter}`);
  ok(heroAfter.assets.spirit_stones === stonesBefore, '重写未重复应用状态(灵石不变)', `灵石 ${stonesBefore}→${heroAfter.assets.spirit_stones}`);
  const rwjob = await env.DB.prepare("SELECT value FROM plot_state WHERE book_id=? AND key='__rewritejob'").bind(bookId).first();
  ok(!rwjob || rwjob.value === 'null' || rwjob.value === null, '重写存档完成后已清空');

  // ---- Part E: 幂等落库——同一章同版本重复保存不撞 UNIQUE(死循环修复)，只保留一行 ----
  await memory.saveChapter(env, bookId, { chapter_no: 3, title: '重存测试', outline: '{}', content: '第3章 重存测试\n\n覆盖内容', summary: 's', ending_tail: 't', tags: ['重存'], word_count: 4, version: 1, qc_report: '{}' });
  const dupRows = await env.DB.prepare("SELECT COUNT(*) c FROM chapters WHERE book_id=? AND chapter_no=3 AND version=1").bind(bookId).first();
  const dupContent = await env.DB.prepare("SELECT title FROM chapters WHERE book_id=? AND chapter_no=3 AND version=1").bind(bookId).first();
  ok(dupRows.c === 1 && dupContent.title === '重存测试', '章节重复保存幂等覆盖(UNIQUE死循环修复)', `行数${dupRows.c}`);

  // 文本字段消毒：模型把 goals 写成数组也不再抛 D1_TYPE_ERROR，自动压成文本
  await memory.upsertCharacter(env, bookId, { name: '陆长安', goals: ['沿暗河探索', '查明骨坠符号', '活着离开万骨坑'] });
  const heroT = (await memory.loadCharacters(env, bookId)).find(c => c.role === 'protagonist');
  ok(typeof heroT.goals === 'string' && heroT.goals.includes('；') && heroT.goals.includes('活着离开万骨坑'),
    '数组型文本字段自动消毒入库(D1_TYPE_ERROR修复)', heroT.goals);

  // ---- 抽样打印一章正文，肉眼看效果 ----
  console.log(`\n${C.y}== 抽样：第 5 章正文前 400 字（看文风/排版/有无AI味）==${C.x}`);
  console.log(C.d + ch5.content.slice(0, 400) + '…' + C.x);

  console.log(`\n${'─'.repeat(50)}`);
  console.log(`${fail === 0 ? C.g : C.r}测试结果：${pass} 通过 / ${fail} 失败${C.x}`);
  console.log(`${C.d}LLM 调用统计：${JSON.stringify(calls)}${C.x}`);
  process.exit(fail === 0 ? 0 : 1);
}
main().catch((e) => { console.error('测试异常:', e); process.exit(1); });
