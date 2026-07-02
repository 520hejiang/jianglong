import os
import sys
import json
import html
import requests
import xmlrpc.client
import re
import time
import unicodedata

# ================= 1. 多书矩阵传参 =================
if len(sys.argv) > 1:
   NOVEL_ID = sys.argv[1]
else:
   NOVEL_ID = "default_novel"

BASE_DIR = f"/ql/data/scripts/{NOVEL_ID}_data"

CATEGORY_MAP = {
   "book1":         "The Long Road to Immortality",
   "book2":         "Soul Forge: Rise of the Death Sovereign",
   "book3":         "The Supreme Villain: I Plunder Every Protagonist's Destiny",
   "default_novel": "The Heaven-Devouring Sovereign",
}
CATEGORY_NAME = CATEGORY_MAP.get(NOVEL_ID, "Uncategorized")
print(f"📚 当前运行书目: [{NOVEL_ID}] → 数据目录: {BASE_DIR} → 分类: {CATEGORY_NAME}")

# ================= 书目配置中心 =================
# 新增书目时：只需在此处添加一条记录，引擎其余部分自动适配。
# 字段说明：
#   genre_keywords  — lore.txt 关键词匹配列表（用于自动识别类型）
#   combat_rules    — 注入生成prompt的战斗/写作规则
#   protagonist     — 主角性格卡（直接注入写作prompt，决定行文气质）
#   author_notes    — 作者语气池（每本书独立人设，随机15%概率插入章末）
BOOK_CONFIG = {
    "default_novel": {
        "genre_keywords": ["xianxia", "sovereign", "cauldron", "heaven-devouring"],
        "tone_anchor": "TONE: Dark, cold, predatory xianxia. The MC is a calculating apex predator — minimal speech, zero panic, retrospective contempt. Cultivation/cauldron-refinement horror is the core appeal. Never drift into warmth, comedy, or melodrama.",
        "combat_rules": (
            "XIANXIA COMBAT RULES:\n"
            "Rotate methods: FLYING SWORD ARRAYS (御剑/剑阵) | FORMATION TRAPS (阵法) | ALCHEMY POISON (炼丹/毒道)\n"
            "SPIRITUAL CONSCIOUSNESS (神识) | BODY CULTIVATION (炼体) | TALISMAN (符箓) | INSECT/BEAST (御虫)\n"
            "MAJOR FIGHTS span 2-4 chapters. NEVER resolve a significant named-enemy fight in one chapter.\n"
            "COMBAT ROTATION: Every 3 combat chapters must use a DIFFERENT primary method.\n"
            "CAULDRON REFINEMENT: When MC refines an enemy — make it TERRIFYING. 3+ paragraphs minimum."
        ),
        "protagonist": (
            "PROTAGONIST PERSONALITY — Heaven-Devouring Sovereign:\n"
            "Core trait: Predatory patience. He never rushes. He waits until the prey has nowhere left to run.\n"
            "Speech: Minimal. When he speaks, others stop breathing. Sentences under 10 words preferred.\n"
            "Internal state: Always calculating. Fear is information, not an emotion he acts on.\n"
            "Weakness: He underestimates bonds he has never needed. Loyalty genuinely surprises him.\n"
            "FORBIDDEN: Trembling, panic, desperation, begging, warm smiles, casual humor.\n"
            "ALLOWED under extreme duress: Cold anger, retrospective contempt for his own miscalculation."
        ),
        "author_notes": [
            "\n\n---\n*Some chapters write themselves. This wasn't one of them.*",
            "\n\n---\n*The next arc has been planned for a long time. It shows, I think.*",
            "\n\n---\n*If something felt off in this chapter, read it again. It isn't off.*",
            "\n\n---\n*More tomorrow.*",
            "\n\n---\n*Every cultivator in this world believes they understand power. Most of them are wrong.*",
            "\n\n---\n*This story doesn't reward skimming. Just a heads up.*",
            "\n\n---\n*The pacing slows here for a reason. The next ten chapters will make it clear.*",
            "\n\n---\n*Comments open. I read them all, reply to almost none. That's not going to change.*",
        ],
    },
    "book1": {
        "genre_keywords": ["lu chang'an", "chang'an", "jade vial", "turbid-pure", "long road to immortality", "qi condensation"],
        "tone_anchor": "TONE: Serious, grounded, ORTHODOX Eastern xianxia (正宗凡人流修仙). NO system, NO panels, NO LitRPG, NO modern/comedic narration. The MC Lu Chang'an is a cautious, patient, ruthless-when-cornered survivor (韩立式谨慎隐忍). Cultivation is dangerous, resources scarce, breakthroughs hard-won. Power is earned slowly through caution, pills, formations, treasures, and scheming. Never let it become comedic, heroic, or game-like.",
        "mc_name": "Lu Chang'an",
        "protagonist_gender": "male",
        "combat_rules": (
            "ORTHODOX XIANXIA RULES (NO SYSTEM, NO LITRPG, NO GAME UI):\n"
            "Rotate and combine classic methods (all ORIGINAL, never copy existing novels):\n"
            "  Flying-sword & sword-array (御剑/剑阵), formation arrays (阵法), pill refinement (炼丹),\n"
            "  talismans (符箓), spirit beasts (灵兽), body refinement & secret arts (炼体/秘术).\n"
            "Realm gaps are ENORMOUS: a cultivator never easily beats someone a full major-realm above them.\n"
            "Crossing realms to win requires trump cards (talismans, formations, poison, terrain, sacrifice) at heavy cost.\n"
            "MAJOR fights against named enemies span MULTIPLE chapters — never resolve in one.\n"
            "Lu Chang'an prefers to win before the fight starts: poison, ambush, formations, or simply not fighting.\n"
            "His one edge — the Turbid-Pure Jade Vial (浊清玉瓶) — refines resources SLOWLY and is used through\n"
            "patience and cleverness, NEVER as an instant power-up. It grants no combat power and must stay secret."
        ),
        "protagonist": (
            "PROTAGONIST PERSONALITY — Lu Chang'an (陆长安), the cautious-survivor archetype (谨慎隐忍):\n"
            "Core trait: Extreme caution. Assumes everyone may be an enemy; plans escape routes before acting.\n"
            "Patience: Will wait years, even decades, for the right moment. Longevity is the true goal.\n"
            "Speech: Says little. Reveals nothing he doesn't have to. Hides his strength and his treasures.\n"
            "Internal state: Constantly weighing risk and profit, calculating odds of survival.\n"
            "Pragmatism: Cold-blooded about survival — uses poison, traps, deception, retreat; ruthless when cornered.\n"
            "Weakness: Self-reliant to a fault; trusts slowly; quietly loyal to the very few he protects.\n"
            "FORBIDDEN: Righteous speeches, reckless heroism, announcing plans, fighting fair when he could win dirty, "
            "trusting strangers, showing off, acting from pride. He is NOT from Earth and is NEVER comedic.\n"
            "ALLOWED: Feigning weakness, retreating, playing dead, long-term scheming, rare quiet warmth toward "
            "the few he protects (always weighed against risk), quiet satisfaction when a long plan pays off."
        ),
        "author_notes": [
            "\n\n---\n*A patient chapter. On the long road, the ones who can wait are the ones who survive.*",
            "\n\n---\n*The realm gap here is deliberate. Crossing it will cost him. It always does.*",
            "\n\n---\n*Alchemy, formations, hidden strength — Chang'an never fights a battle he isn't sure he can win.*",
            "\n\n---\n*The vial's true origin is still a long way off. It will surface when the time is right.*",
            "\n\n---\n*More tomorrow. The road is long.*",
        ],
    },
    "book2": {
        "genre_keywords": ["kael", "mortis", "soul forge", "necromancer", "undead", "realm merge", "calamity zone", "bone stitching"],
        "tone_anchor": "TONE: Dark, kinetic System-Apocalypse necromancer power-fantasy with loot/craft dopamine and slow-burn harem. A betrayed nobody rebuilds from rock bottom using death itself. The snarky minimal [SYSTEM:] panel MUST appear every chapter. Wins are EARNED through cunning and crafting, never zero-cost curbstomps. Stakes are real. MC Kael is a cold realist forged by betrayal, ruthless with logic, fiercely protective of the loyal. Never edgy gloating, never instant-win.",
        "mc_name": "Kael Mortis",
        "protagonist_gender": "male",
        "requires_system_panel": True,
        "combat_rules": (
            "SYSTEM-APOCALYPSE NECROMANCER RULES (original Soul Forge and Bone Stitching, NOT shadow-extraction):\n"
            "Core loop: reap enemy souls (keep their abilities) then stitch corpses+souls in the Forge into unique undead.\n"
            "[SYSTEM: ...] panel every chapter, dry and minimal, a little mocking, never breaking the dark tone.\n"
            "Loot/craft dopamine: show the satisfaction of building ever-stronger minions from collected materials.\n"
            "LitRPG numeric panel: beings have Level (per color-tier band), attributes STR/AGI/VIT/SP/SEN, attribute\n"
            "  points, and XP. Soul Power (SP) governs Legion Capacity and Forge capacity. The [SYSTEM:] panel shows\n"
            "  the numbers that just changed (e.g. '[SYSTEM: LEVEL UP -> Lv.14. +3 Points. Soul Power 8 -> 9.]').\n"
            "  Never compute new totals in prose; the engine tracks them. Surface only what changed, keep panels tight.\n"
            "STRICT cost: forging needs materials, soul-essence, and time; minion count/quality capped by Kael Panel rank.\n"
            "Powerful reaped souls resist and can rebel if control is weak. Control is a resource.\n"
            "Power scale LOCKED per volume (city, then national, then planar, then divine). No cosmic powers in early volumes.\n"
            "Every win is clever and earned: tactical undead warfare, ambush, terrain, soul-tricks. Never a trivial curbstomp.\n"
            "Numeric totals (soul-essence, materials, minion counts) are tracked by ENGINE CODE; prose never states new totals."
        ),
        "protagonist": (
            "PROTAGONIST PERSONALITY: Kael Mortis (cold realist forged by betrayal, NOT a cackling villain):\n"
            "Core trait: Controlled, calculating, observational. He plans and answers; he never rages or monologues.\n"
            "Ruthlessness: utterly merciless to those who betray or threaten him, but it has LOGIC, not malice.\n"
            "Hidden core: beneath the ice, a fierce protectiveness toward the few genuinely loyal to him\n"
            "  (his undead, his women). He will never trust the world again, but he protects what chooses him.\n"
            "Satisfaction: he finds grim meaning in building order out of ruin; every stitched minion is HIS.\n"
            "Humor: dry, sparse, dark. He narrates his grim competence without melodrama.\n"
            "FORBIDDEN: ranting, gloating, cruelty for its own sake, instant-win with no tension.\n"
            "ALLOWED: clever tactical wins, cold mercy, rare real warmth toward the loyal, hard-earned power."
        ),
        "author_notes": [
            "\n\n---\n*The forge was busy this chapter. Every bone has a purpose.*",
            "\n\n---\n*Kael does not gloat. He just makes sure it never happens again.*",
            "\n\n---\n*The loot-and-craft loop is the whole point. Watch the legion grow.*",
            "\n\n---\n*He trusts no one. But the ones who chose him? He would burn the world for them.*",
            "\n\n---\n*Power has a cost here. Always. That is what makes the climb mean something.*",
            "\n\n---\n*More tomorrow. The dead are patient.*",
        ],
    },
    "book3": {
        "genre_keywords": ["gu tianhao", "tianhao", "supreme villain", "villain system", "villain points", "transmigrat", "chosen one", "face-slap", "fate-line"],
        "tone_anchor": "TONE: Elegant, smug, supremely-in-control villain-protagonist xianxia wish-fulfillment. The appeal is INTELLECTUAL curb-stomps: a flawless mastermind out-thinking arrogant chosen-ones before they realize they have lost. The [SYSTEM:] panel appears every chapter. MC Gu Tianhao is calm, refined, three-moves-ahead, NEVER a bratty shouting young master. CRITICAL SAFETY: every heroine LEAVES a controlling/abusive original protagonist by her own FREE CHOICE, never stolen, never coerced, never non-consensual.",
        "mc_name": "Gu Tianhao",
        "protagonist_gender": "male",
        "requires_system_panel": True,
        "combat_rules": (
            "TRANSMIGRATED VILLAIN-PROTAGONIST XIANXIA RULES (all rivals/heroines ORIGINAL, never copy real novels):\n"
            "Every conflict is an ELEGANT intellectual win. Gu Tianhao reads rivals fate-lines and turns the tables\n"
            "  before they understand the game started. Dominance is intellect first, force second, never shouting.\n"
            "[SYSTEM: ...] Villain-Points panel every chapter (points earned by out-classing the arrogant, not harming innocents).\n"
            "MANDATORY SAFETY RULE: heroines who leave an original protagonist do so by FREE, EMPOWERED CHOICE because\n"
            "  that rival was controlling/abusive/deceitful. Liberation, never theft. NEVER break up a loving couple.\n"
            "  NEVER any coercion or non-consensual content. This applies to EVERY romance beat in every arc.\n"
            "Face-slap reversals are satisfying because the rival genuinely deserved it and was beaten by wits.\n"
            "Power scale LOCKED per volume tier (Lower, Upper, Immortal, Myriad, Dao). No cosmic powers early.\n"
            "Previously-won heroines never vanish: show them briefly beside or aiding Gu Tianhao in later arcs.\n"
            "Numeric totals (Villain Points, spirit stones) tracked by ENGINE CODE; prose never states new totals."
        ),
        "protagonist": (
            "PROTAGONIST PERSONALITY: Gu Tianhao (elegant mastermind, NOT a bratty young master):\n"
            "Core trait: Calm, refined, always three moves ahead. He smiles where others shout. He has already won\n"
            "  before the opponent realizes the game began. Dominance is INTELLECTUAL first, force second.\n"
            "Confidence: supreme but never crude or insecure; he never needs to prove himself loudly.\n"
            "Code: ruthless to the arrogant and abusive, but he targets those who abuse power, never the helpless.\n"
            "  This gives readers a reason to root for him.\n"
            "Romance: beneath the cool control is a guarded, genuine, possessive seriousness toward the women who\n"
            "  choose him, a flicker of real feeling that keeps the harem from feeling hollow.\n"
            "Voice: cool, witty, composed, faintly amused. He enjoys the chess-match, and so does the reader.\n"
            "FORBIDDEN: bratty shouting, insecure gloating, cruelty to the innocent, winning by luck alone.\n"
            "ALLOWED: elegant scheming, intellectual curb-stomps, calm menace, guarded genuine feeling for heroines."
        ),
        "author_notes": [
            "\n\n---\n*He won three moves ago. The rival just has not noticed yet.*",
            "\n\n---\n*Elegance over noise. Always.*",
            "\n\n---\n*She did not get stolen, she got free, and then she chose. That is the whole point.*",
            "\n\n---\n*The best face-slap is the one the rival walks into himself.*",
            "\n\n---\n*Under all that control, he does feel something. He would just never say it first.*",
            "\n\n---\n*Next tier, next world, next arrogant chosen one. The game continues.*",
        ],
    },
    # ── 新增书目模板 ──────────────────────────────────────────────────────────
    # 复制下面注释块，填写字段后取消注释，引擎其余部分自动适配，无需修改任何其他代码。
    # "book4": {
    #     "genre_keywords": ["关键词1", "关键词2"],
    #     "combat_rules": "这本书的战斗/写作规则",
    #     "protagonist": (
    #         "主角性格卡：\n"
    #         "Core trait: ...\n"
    #         "Speech: ...\n"
    #         "FORBIDDEN: ...\n"
    #         "ALLOWED: ..."
    #     ),
    #     "author_notes": [
    #         "\n\n---\n*章末作者语气，写几条备用*",
    #     ],
    # },
}

def get_book_config():
    """根据 NOVEL_ID 返回当前书目配置，找不到则返回 default_novel。"""
    return BOOK_CONFIG.get(NOVEL_ID, BOOK_CONFIG["default_novel"])
# ================================================

# ================= 2. 核心配置（直接填写您的真实凭据） =================
DEEPSEEK_API_KEY     = "s4"# 请替换为您的真实 Key
API_BASE_URL         = "https://api.deepseek.com"   # 注意末尾没有斜杠
MODEL_NAME           = "deepseek-v4-pro"                # 或者 deepseek-v4-flash 等其他模型                             # 新插入（第24行）
SITE_URL             = "https://tomcultivation.com"           # 不要带斜杠
TYPECHO_RPC_URL      = "https://tomcultivation.com/action/xmlrpc"  # 正确 URL
TYPECHO_USER         = "hejianglong"
TYPECHO_PASS         = "2"  # 请替换
TG_BOT_TOKEN         = "8834793388:AAHFNqbHZQa4y59hbrir2Wv3AWdg6-EGqTs"  # 请替换
TG_CHAT_ID           = "6912219476"  # 请替换

# 数据文件路径
FILES = {
   "lore":          os.path.join(BASE_DIR, "lore.txt"),
   "status":        os.path.join(BASE_DIR, "status.json"),
   "characters":    os.path.join(BASE_DIR, "character_bible.json"),
   "quests":        os.path.join(BASE_DIR, "quests.json"),
   "threads":       os.path.join(BASE_DIR, "threads.json"),
   "volumes":       os.path.join(BASE_DIR, "volumes.json"),
   "chapter_index": os.path.join(BASE_DIR, "chapter_index.json"),
   "recent_memory": os.path.join(BASE_DIR, "memory/recent_5_chapters.txt"),
   "arc_current":   os.path.join(BASE_DIR, "memory/arc_current.txt"),
   "chronicles":    os.path.join(BASE_DIR, "chronicles.txt"),
   "perma_facts":   os.path.join(BASE_DIR, "perma_facts.txt"),   # S级永久事实池（境界/生死/永久残疾/誓约）
   "director_todo": os.path.join(BASE_DIR, "director_todo.txt"),  # 主编转交导演的节奏/线程待办
}

ARC_SIZE             = 15
VOLUME_SIZE          = 90     # 必须是 ARC_SIZE 的整数倍(15×6=90)，否则每卷末尾会漏档。改前务必保持整除关系。
MAX_REWRITE_ATTEMPTS = 2      # 精品走查模式：重写最多2次，超过即放行（剩余问题交给巡检引擎回校）
MAX_ACTIVE_THREADS   = 8      # 活跃线程硬上限，超过自动归档最旧的低优先级线程
RELEASE_FLOOR_SCORE  = 72     # 达到MAX重写次数后，分数≥此值直接放行
SLUG_PREFIX_BY_BOOK  = True   # ★ 发布slug带书名前缀(bookN-章号)，确保跨书网址唯一、永不撞车。务必保持True

# 禁用词表（规则扫描 + 专项清洗共用）。这些是AI写作高频"机翻腔/现代词"，在仙侠/奇幻设定里很出戏。
BANNED_WORDS = [
    'testament', 'beacon', 'tapestry', 'pivotal', 'crucial', 'profound',
    'intricate', 'bustling', 'meticulous', 'showcase', 'furthermore',
    'needless to say', "couldn't help but", 'found himself', 'made his way',
    'cognitive dissonance', 'catalogued', 'parameters', 'algorithm',
    'optimize', 'metrics', 'calibrate', 'protocol',
]
# =================================================

def get_target_word_count(chapter_num):
   if chapter_num <= 500:   return 1500
   elif chapter_num <= 2000: return 2000
   else:                     return 2500

# ─────────────────────────────────────────────────
# 工具函数
# ─────────────────────────────────────────────────

def call_deepseek(prompt, temperature=0.75, timeout=600, max_tokens=8000,
                  presence_penalty=0.4, frequency_penalty=0.4):
    """统一的 DeepSeek 调用。
    ★ 关键：'整章改写'类任务（润色/段首改写/禁用词替换）必须用更大的 max_tokens 和更低的惩罚，
      否则输出会被截断或畸形，导致 len<原文*0.7 判定失败、后处理全程瘫痪。
      这类任务请显式传 max_tokens=32000, presence_penalty=0, frequency_penalty=0。"""
    url = f"{API_BASE_URL}/chat/completions"   # 正确端点
    headers = {"Authorization": f"Bearer {DEEPSEEK_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": MODEL_NAME,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens,
        "presence_penalty": presence_penalty,
        "frequency_penalty": frequency_penalty
    }
    for attempt in range(1, 4):
        try:
            r = requests.post(url, json=payload, headers=headers, timeout=timeout)
            r.raise_for_status()
            data = r.json()
            content = data["choices"][0]["message"]["content"]
            # ★ 截断检测：若因 max_tokens 被截断，明确告警（便于排查"润色返回异常"）
            finish = data["choices"][0].get("finish_reason", "")
            if finish == "length":
                print(f"  ⚠️  输出因 max_tokens({max_tokens}) 被截断，建议调高。")
            return content
        except Exception as e:
            print(f"  ⚠️  API 调用异常 (第{attempt}次): {e}")
            if attempt < 3:
                sleep_time = 5 * attempt
                print(f"  ⏳ 退避休眠 {sleep_time} 秒...")
                time.sleep(sleep_time)
            else:
                return None
    return None
  
def extract_json(text):
   """终极 JSON 提取器（增强容错）"""
   if not text: return None
   text = text.strip()
   # 1. 优先提取 Markdown 代码块
   tick3 = "`" * 3
   pattern = tick3 + r"(?:json)?\s*([\s\S]*?)\s*" + tick3
   match = re.search(pattern, text, re.IGNORECASE)
   if match:
       candidate = match.group(1).strip()
       try:
           return json.loads(candidate)
       except:
           pass
   # 2. 退避策略：寻找最外层大括号/中括号
   start_brace = text.find('{')
   end_brace = text.rfind('}')
   start_bracket = text.find('[')
   end_bracket = text.rfind(']')
   candidate = ""
   if start_brace != -1 and end_brace != -1:
       if start_bracket == -1 or (start_brace < start_bracket and end_brace > end_bracket):
           candidate = text[start_brace:end_brace+1]
   if not candidate and start_bracket != -1 and end_bracket != -1:
       candidate = text[start_bracket:end_bracket+1]
   if candidate:
       try:
           return json.loads(candidate)
       except Exception as e:
           # 尝试修复非法逗号、控制字符等
           try:
               repaired = re.sub(r',\s*([\]}])', r'\1', candidate)
               repaired = re.sub(r'[\x00-\x1f\x7f]', '', repaired)  # 移除控制字符
               return json.loads(repaired)
           except:
               pass
           print(f"  ⚠️  [提取 JSON 失败] 解析错误: {e}")
   return None

def safe_read_json(path, default):
   if not os.path.exists(path): return default
   try:
       with open(path, "r", encoding="utf-8") as f: return json.load(f)
   except: return default

def safe_write_json(path, data):
   tmp = path + ".tmp"
   try:
       os.makedirs(os.path.dirname(path), exist_ok=True)
       with open(tmp, "w", encoding="utf-8") as f: json.dump(data, f, indent=4, ensure_ascii=False)
       os.replace(tmp, path)
       return True
   except Exception as e:
       print(f"  ⚠️  写入 {path} 失败: {e}")
       return False

def safe_read_text(path, default=""):
   if not os.path.exists(path): return default
   try:
       with open(path, "r", encoding="utf-8") as f: return f.read()
   except: return default

def safe_write_text(path, text):
   tmp = path + ".tmp"
   try:
       os.makedirs(os.path.dirname(path), exist_ok=True)
       with open(tmp, "w", encoding="utf-8") as f: f.write(text)
       os.replace(tmp, path)   # 原子替换，防止写一半崩溃损坏文件
       return True
   except Exception as e:
       print(f"  ⚠️  写入 {path} 失败: {e}")
       if os.path.exists(tmp):
           try: os.remove(tmp)
           except: pass
       return False

def safe_append_text(path, text):
   try:
       os.makedirs(os.path.dirname(path), exist_ok=True)
       with open(path, "a", encoding="utf-8") as f: f.write(text)
       return True
   except Exception as e:
       print(f"  ⚠️  追加 {path} 失败: {e}")
       return False

# ─────────────────────────────────────────────────
# 自动初始化
# ─────────────────────────────────────────────────

def auto_init_files():
   print("🔧 [初始化检测] 正在扫描数据文件...")
   created_any = False
   for path in FILES.values():
       os.makedirs(os.path.dirname(path), exist_ok=True)

   if not os.path.exists(FILES["status"]):
       safe_write_json(FILES["status"], {
           "chapter": 1, "realm": "Stage 1",
           "location": "Starting location",
           "inventory": []
       })
       print("  ✅ 自动生成 status.json"); created_any = True

   if not os.path.exists(FILES["lore"]):
       safe_write_text(FILES["lore"], "WORLD RULES:\n\n=== ABSOLUTE FACTS - NEVER CONTRADICT ===\nCh.1: Story begins.\n=== END ABSOLUTE FACTS ===\n")
       print("  ✅ 自动生成 lore.txt"); created_any = True
   else:
       lore_content = safe_read_text(FILES["lore"], "")
       if "=== ABSOLUTE FACTS" not in lore_content:
           with open(FILES["lore"], "a", encoding="utf-8") as f:
               f.write("\n\n=== ABSOLUTE FACTS - NEVER CONTRADICT ===\nCh.1: Story begins.\n=== END ABSOLUTE FACTS ===\n")
           print("  ✅ lore.txt 自动追加 ABSOLUTE FACTS 区域"); created_any = True

   if not os.path.exists(FILES["quests"]):
       safe_write_json(FILES["quests"], {
           "macro_goal": "Begin the story.", "immediate_micro_goal": "Ch.1: The story begins.",
           "active_subplots_to_mention": [], "character_interactions_needed": [],
           "villain_status": {"active_villains": []},
           "chapter_budget": {"combat_and_dominance": "60%", "character_moment": "20%", "worldbuilding_or_mystery": "20%"}
       })
       print("  ✅ 自动生成 quests.json"); created_any = True
   else:
       eq = safe_read_json(FILES["quests"], {})
       if "villain_status" not in eq:
           eq["villain_status"] = {"active_villains": []}
           safe_write_json(FILES["quests"], eq)
           print("  ✅ quests.json 自动升级"); created_any = True

   if not os.path.exists(FILES["characters"]):
       safe_write_json(FILES["characters"], {})
       print("  ✅ 自动生成 character_bible.json"); created_any = True
   else:
       ec = safe_read_json(FILES["characters"], {})
       upgraded = False
       for name, data in ec.items():
           for field, default in [("key_events", []), ("character_voice", "undefined"), ("narrative_role", "supporting")]:
               if field not in data:
                   data[field] = default; upgraded = True
       if upgraded:
           safe_write_json(FILES["characters"], ec)
           print("  ✅ character_bible.json 自动升级"); created_any = True

   for key, default in [("threads", {"active_threads": [], "resolved_threads": []}), ("volumes", {}), ("chapter_index", {})]:
       if not os.path.exists(FILES[key]):
           safe_write_json(FILES[key], default)
           print(f"  ✅ 自动生成 {key}"); created_any = True

   for key, default_text in [("recent_memory", "Story begins here."), ("arc_current", ""), ("chronicles", "")]:
       if not os.path.exists(FILES[key]):
           safe_write_text(FILES[key], default_text)
           print(f"  ✅ 自动生成 {key}"); created_any = True

   # 状态快照架构所需的新文件（v5.8+）：永久事实池、导演待办
   for key, default_text in [("perma_facts", "=== S-TIER PERMANENT FACTS (NEVER CONTRADICT, NEVER EXPIRE) ===\n"),
                              ("director_todo", "")]:
       if not os.path.exists(FILES[key]):
           safe_write_text(FILES[key], default_text)
           print(f"  ✅ 自动生成 {key}"); created_any = True

   if not created_any:
       print("  ✅ 所有文件均已存在，无需初始化。")
   else:
       print("  🎉 初始化完成！\n")

# ─────────────────────────────────────────────────
# 数据加载
# ─────────────────────────────────────────────────

def load_database():
   print("📂 正在读取数据库...")
   try:
       lore        = safe_read_text(FILES["lore"], "")
       status      = safe_read_json(FILES["status"], {})
       characters  = safe_read_json(FILES["characters"], {})
       quests      = safe_read_json(FILES["quests"], {})
       threads     = safe_read_json(FILES["threads"], {"active_threads": [], "resolved_threads": []})
       volumes     = safe_read_json(FILES["volumes"], {})
       chap_index  = safe_read_json(FILES["chapter_index"], {})
       recent_mem  = safe_read_text(FILES["recent_memory"], "Story begins here.")
       arc_current = safe_read_text(FILES["arc_current"], "")
       chronicles  = safe_read_text(FILES["chronicles"], "")
       if not status:
           print("❌ status.json 读取异常。"); return None
       print("✅ 数据库读取成功。")
       return lore, status, characters, quests, threads, volumes, chap_index, recent_mem, arc_current, chronicles
   except Exception as e:
       print(f"❌ 读取数据库失败: {e}"); return None

# ─────────────────────────────────────────────────
# 文本清洗处理 (去除 AI 结尾味)
# ─────────────────────────────────────────────────

def clean_ai_endings(text):
   """强制清洗 AI 喜欢在章节末尾加的各种废话、预告和笔记"""
   if not text: return text
   text = strip_placeholder_markers(text)   # 先清理正文任意位置的占位符
   lines = text.strip().split('\n')
   bad_phrases = [
       "to be continued", "next chapter", "the journey continues", "will return", 
       "find out next time", "stay tuned", "what will happen", "the path ahead",
       "chapter end", "end of chapter", "下一章", "未完待续", "敬请期待", "故事继续",
       "author's note", "author note", "note:", "p.s."
   ]
   for _ in range(5):
       if not lines: break
       last_line = lines[-1].strip().lower()
       if any(phrase in last_line for phrase in bad_phrases) or last_line.strip('*- ') == '':
           lines.pop()
       else:
           break
   return '\n'.join(lines)

def strip_placeholder_markers(text):
   """清除主笔残留在正文任意位置的占位符标记（[TBC]、[TODO]、[CONTINUE] 等）。
   这类标记是 AI 生成时的'待续/占位'残留，漏到正文里会让读者一眼看穿是机器生成。"""
   if not text: return text
   # 匹配独立成行或夹在文中的占位符，大小写不敏感
   patterns = [
       r'\[\s*TBC\s*\]', r'\[\s*TO\s*BE\s*CONTINUED\s*\]', r'\[\s*TODO[^\]]*\]',
       r'\[\s*CONTINUE[D]?\s*\]', r'\[\s*CONT\.?\s*\]', r'\[\s*PLACEHOLDER[^\]]*\]',
       r'\[\s*NEXT[^\]]*\]', r'\[\s*INSERT[^\]]*\]', r'\[\s*XXX+\s*\]',
       r'\[\s*未完[^\]]*\]', r'\[\s*待续[^\]]*\]',
   ]
   for pat in patterns:
       text = re.sub(pat, '', text, flags=re.IGNORECASE)
   # 清理因删除占位符产生的空行（连续3+换行压成2个）
   text = re.sub(r'\n{3,}', '\n\n', text)
   return text.strip()

# ─────────────────────────────────────────────────
# 全自动健康检查与修复（每章运行）
# ─────────────────────────────────────────────────

def auto_health_check_and_repair(status, lore, threads, characters, quests, chapter_num, chronicles):
   print(f"🏥 [全自动健康检查] 正在扫描数据库...")
   repairs_made = []

   # ── 修复1：status境界过期 (AI直接裁判法) ─────────
   absolute_facts = _get_absolute_facts(lore)
   if absolute_facts and chapter_num > 2:
       realm_keys    = ["realm","rank","kaelen_rank","seraphina_rank","eli_tier","kane_rank"]
       current_realm = ""
       primary_key   = "realm"
       for k in realm_keys:
           if k in status and status[k]:
               current_realm = str(status[k]); primary_key = k; break
       if not current_realm:
           current_realm = "Unknown"

       extract_prompt = f"""
You are the Continuity Manager. Compare the MC's Current Realm with the latest events in ABSOLUTE FACTS.

[Current Realm in Status]: "{current_realm}"
[ABSOLUTE FACTS]:
{absolute_facts}

Task:
1. Did the MC break through or reach a new stage in recent chapters in ABSOLUTE FACTS?
2. If YES, and it is higher than "{current_realm}", reply ONLY with the EXACT new realm/stage string (e.g. "E-Rank — Middle Stage").
3. If "{current_realm}" is still perfectly accurate and up-to-date, reply EXACTLY: NO_CHANGE
"""
       accurate_realm = call_deepseek(extract_prompt, temperature=0.1, timeout=60)
       if accurate_realm:
           accurate_realm = accurate_realm.strip()
           if "NO_CHANGE" not in accurate_realm.upper() and len(accurate_realm) < 50:
               status[primary_key] = accurate_realm
               safe_write_json(FILES["status"], status)
               repairs_made.append(f"status.{primary_key}: '{current_realm}' → '{accurate_realm}'")
               print(f"  🔧 [自动修复] 境界过期: {current_realm} → {accurate_realm}")

   # ── 修复1b：inventory 自动同步绝对事实 ──────────
   inventory = status.get("inventory", [])
   if inventory and absolute_facts and chapter_num > 3:
       inv_check_prompt = f"""You are a story database manager.
[Inventory]: {json.dumps(inventory, ensure_ascii=False)}
[ABSOLUTE FACTS]: {absolute_facts}

Task: Which inventory items have been consumed, destroyed, used up, or lost according to ABSOLUTE FACTS?
Return EXACTLY: {{"items_to_remove": ["exact item name as it appears in inventory"]}}
If none, return: {{"items_to_remove": []}}"""
       inv_result = extract_json(call_deepseek(inv_check_prompt, temperature=0.1, timeout=60))
       if inv_result and inv_result.get("items_to_remove"):
           to_remove = inv_result["items_to_remove"]
           removed = []
           for item_name in to_remove:
               matches = [i for i in inventory if item_name.lower() in i.lower() or i.lower() in item_name.lower()]
               for m in matches:
                   if m in inventory:
                       inventory.remove(m)
                       removed.append(m)
           if removed:
               status["inventory"] = inventory
               safe_write_json(FILES["status"], status)
               repairs_made.append(f"inventory: 自动删除已消耗道具 {removed}")
               print(f"  🔧 [自动修复] inventory 同步：删除已消耗道具 {removed}")

   # ── 修复2：死线程自动归档 ──────────────────────
   active   = threads.get("active_threads", [])
   resolved = threads.get("resolved_threads", [])
   still_active = []; auto_archived = 0

   for t in active:
       must_by = t.get("must_resolve_by_chapter", chapter_num + 100)
       urgency = t.get("urgency", "medium")
       last_ch = t.get("last_mentioned_chapter", 0)
       overdue = chapter_num - must_by
       dormant = chapter_num - last_ch

       should_archive = False
       reason = ""
       if overdue > 30 and urgency != "high":
           should_archive = True; reason = f"overdue {overdue} chapters"
       elif dormant > 50 and urgency != "high":
           should_archive = True; reason = f"dormant {dormant} chapters"

       if should_archive:
           t["resolved_chapter"] = chapter_num
           t["resolution"]       = f"Auto-archived Ch.{chapter_num}: {reason}."
           resolved.append(t); auto_archived += 1
       else:
           still_active.append(t)

   if chapter_num % 15 == 0 and still_active and chronicles.strip():
       recent_chron = "\n".join(chronicles.strip().splitlines()[-40:])
       threads_text = json.dumps(still_active[:15], ensure_ascii=False)
       scan_prompt  = f"""
You are a story continuity manager. Check which active subplot threads have already been
resolved in the story based on recent history. Look for: enemies killed, items obtained,
mysteries revealed, conflicts concluded.

[Recent Story History]:
{recent_chron}

[Active Threads]:
{threads_text}

Return EXACTLY this JSON:
{{"resolved_in_story": [{{"id": "thread_id", "resolution": "one sentence how it resolved"}}]}}
If none resolved, return: {{"resolved_in_story": []}}
"""
       result = extract_json(call_deepseek(scan_prompt, temperature=0.1, timeout=120))
       if result and result.get("resolved_in_story"):
           resolved_ids = {r["id"]: r["resolution"] for r in result["resolved_in_story"]}
           remaining = []
           for t in still_active:
               if t["id"] in resolved_ids:
                   t["resolved_chapter"] = chapter_num
                   t["resolution"]       = f"Story-detected: {resolved_ids[t['id']]}"
                   resolved.append(t); auto_archived += 1
               else:
                   remaining.append(t)
           still_active = remaining

   if len(still_active) > 25:
       compress_prompt = f"""
There are {len(still_active)} active subplot threads — too many. Maximum should be 20.
Identify resolved, duplicate, or redundant threads. Keep all urgency=high threads.
Merge duplicates. Return max 20 clean threads.

[Active Threads]:
{json.dumps(still_active, ensure_ascii=False)}

Current chapter: {chapter_num}

Return EXACTLY this JSON:
{{"cleaned_active_threads": [{{"id":"","description":"","opened_chapter":0,"urgency":"","must_resolve_by_chapter":0,"last_mentioned_chapter":0}}],
 "archived_thread_ids": [], "cleanup_summary": "one sentence"}}
"""
       result = extract_json(call_deepseek(compress_prompt, temperature=0.1, timeout=180))
       if result and result.get("cleaned_active_threads"):
           archived_ids = result.get("archived_thread_ids", [])
           for t in still_active:
               if t["id"] in archived_ids:
                   t["resolved_chapter"] = chapter_num
                   t["resolution"]       = f"Merged: {result.get('cleanup_summary','')}"
                   resolved.append(t); auto_archived += 1
           still_active = result["cleaned_active_threads"]

   # ── 活跃线程硬上限：超过 MAX_ACTIVE_THREADS 强制归档最旧的低优先级线程 ──
   if len(still_active) > MAX_ACTIVE_THREADS:
       # 高优先级永不强制归档；其余按最后提及章升序（最旧的先归档）
       high = [t for t in still_active if t.get("urgency") == "high"]
       low  = [t for t in still_active if t.get("urgency") != "high"]
       low.sort(key=lambda t: t.get("last_mentioned_chapter", 0))
       allowed_low = MAX_ACTIVE_THREADS - len(high)
       if allowed_low < 0:
           allowed_low = 0   # 高优先级本身就超额时，低优先级全部归档，但保留所有高优先级
       to_keep_low   = low[len(low)-allowed_low:] if allowed_low > 0 else []
       to_archive_low = low[:len(low)-allowed_low] if allowed_low > 0 else low
       for t in to_archive_low:
           t["resolved_chapter"] = chapter_num
           t["resolution"]       = f"Auto-archived Ch.{chapter_num}: active-thread cap ({MAX_ACTIVE_THREADS}) exceeded, oldest low-priority pruned."
           resolved.append(t); auto_archived += 1
       still_active = high + to_keep_low
       if to_archive_low:
           print(f"  🔧 [线程上限] 活跃线程超过 {MAX_ACTIVE_THREADS}，归档 {len(to_archive_low)} 条最旧低优先级线程")

   if auto_archived > 0:
       threads["active_threads"]   = still_active
       threads["resolved_threads"] = resolved
       safe_write_json(FILES["threads"], threads)
       repairs_made.append(f"threads: 自动归档 {auto_archived} 条死线程")
       print(f"  🔧 [自动修复] 归档 {auto_archived} 条线程，活跃剩余 {len(still_active)} 条")

   # ── 修复3：角色档案膨胀（每25章）────────────────
   if chapter_num % 25 == 0:
       compressed_any = False
       for name, data in characters.items():
           events = data.get("key_events", [])
           if len(events) > 20:
               compress_prompt = f"""
Compress character [{name}]'s event history. Keep last 5 events verbatim.
Compress older events into 3-5 summary sentences.
Return EXACTLY: {{"compressed_old_events": ["sentences"], "recent_events": ["last 5 verbatim"]}}

[Events]:
{chr(10).join(events)}
"""
               result = extract_json(call_deepseek(compress_prompt, temperature=0.1, timeout=120))
               if result:
                   data["key_events"] = result.get("compressed_old_events", []) + result.get("recent_events", [])
                   compressed_any = True
       if compressed_any:
           safe_write_json(FILES["characters"], characters)
           repairs_made.append("characters: 角色档案自动压缩")
           print(f"  🔧 [自动修复] 角色档案已压缩")

   # ── 修复4：编年史归档（每100章）─────────────────
   if chapter_num % 100 == 0:
       chron_lines = [l for l in chronicles.splitlines() if l.strip()]
       if len(chron_lines) > 500:
           recent = chron_lines[-100:]; old = chron_lines[:-100]
           vol_num      = chapter_num // 100
           archive_path = os.path.join(BASE_DIR, f"chronicles_archive_vol{vol_num}.txt")
           existing     = safe_read_text(archive_path, "")
           safe_write_text(archive_path, existing + "\n".join(old) + "\n")
           safe_write_text(FILES["chronicles"], "\n".join(recent) + "\n")
           repairs_made.append(f"chronicles: 归档 {len(old)} 行到 vol{vol_num}")
           print(f"  🔧 [自动修复] 编年史归档 {len(old)} 行")

   # ── 修复5：quests缺失villain_status ─────────────
   if "villain_status" not in quests:
       quests["villain_status"] = {"active_villains": []}
       safe_write_json(FILES["quests"], quests)
       repairs_made.append("quests: 补充缺失的villain_status字段")
       print(f"  🔧 [自动修复] quests.json 补充 villain_status 字段")

   # ── 修复6：过期高优先级线程防死锁 ───────────────
   # 如果高优先级线程已过期 5+ 章但仍未被解决（可能AI无法处理），
   # 自动将 must_resolve_by_chapter 延期 10 章，避免每章都触发强制重写导致无限循环。
   # 同时在 lore 里记录一条提醒，让后续章节有机会自然处理。
   threads_updated = False
   for t in threads.get("active_threads", []):
       if t.get("urgency") == "high":
           overdue = chapter_num - t.get("must_resolve_by_chapter", chapter_num)
           stall_count = t.get("_stall_count", 0)
           if overdue >= 5:
               t["_stall_count"] = stall_count + 1
               if stall_count >= 2:  # 连续3次健康检查都在过期状态
                   old_deadline = t["must_resolve_by_chapter"]
                   t["must_resolve_by_chapter"] = chapter_num + 10
                   t["_stall_count"] = 0
                   threads_updated = True
                   repairs_made.append(f"threads: [{t['id']}] 过期死锁，截止章节延期 {old_deadline}→{chapter_num+10}")
                   print(f"  🔧 [防死锁] [{t['id']}] 截止章节自动延期至第 {chapter_num+10} 章")
               else:
                   threads_updated = True  # 更新 stall_count
           else:
               if t.get("_stall_count", 0) > 0:
                   t["_stall_count"] = 0
                   threads_updated = True
   if threads_updated:
       safe_write_json(FILES["threads"], threads)

   if repairs_made:
       print(f"  ✅ 健康检查完成，自动修复了 {len(repairs_made)} 项问题。")
   else:
       print(f"  ✅ 健康检查完成，数据库状态良好。")

   return status, threads, characters, quests

# ─────────────────────────────────────────────────
# 辅助函数
# ─────────────────────────────────────────────────

def _get_absolute_facts(lore):
   if "=== ABSOLUTE FACTS" in lore:
       start = lore.index("=== ABSOLUTE FACTS")
       end   = lore.index("=== END ABSOLUTE FACTS") + len("=== END ABSOLUTE FACTS")
       return lore[start:end]
   return ""

# ── 分级事实系统（状态快照核心）──────────────────────────
# S级永久事实：境界突破、核心角色生死、永久残疾/誓约、系统升级 —— 永久注入，绝不丢
# 普通事实：日常事件 —— 只注入最近 RECENT_FACTS_WINDOW 章，避免 prompt 随章节膨胀
RECENT_FACTS_WINDOW = 20

# 判定 S 级永久事实的关键词（命中即永久保留）
S_TIER_KEYWORDS = [
   "breakthrough", "broke through", "ascend", "realm", "rank up", "advanced to",
   "died", "death", "killed", "slain", "perished", "sacrificed",
   "permanent", "permanently", "forever", "blind", "lost an arm", "lost a leg",
   "severed", "crippled", "oath", "vow", "swore", "bloodline", "awakened",
   "system upgrade", "evolved", "fused", "sealed", "unsealed",
]

def _classify_fact_is_s_tier(fact_line):
   """判断一条事实是否为 S 级永久事实。"""
   low = fact_line.lower()
   return any(kw in low for kw in S_TIER_KEYWORDS)

def _new_fact_conflicts_with_core(new_fact, lore):
   """★ 守门：判断一条'待固化的新绝对事实'是否破坏了金手指/核心力量的既定边界。
   审计AI偶尔会把主笔的过度发挥（如让被动法宝变成主动攻击武器）写成新绝对事实，
   而绝对事实永不推翻——一旦焊死错误设定，金手指就废了，且会滚雪球。
   本函数做轻量启发式拦截：若新事实给一个'被设定为被动/无输出/无战斗'的金手指
   新增了主动攻击/输出/战斗能力，则判定冲突、拒绝固化。"""
   nf = new_fact.lower()
   lore_low = lore.lower()
   # 1. 找出 lore 里是否明确把金手指定义为"被动/无输出/无战斗力"
   passive_markers = [
       "not a system", "no panels", "no combat power", "only slow refinement",
       "only refines", "slowly refines", "no output", "passive", "cannot activate",
       "grants no", "no active", "只能精炼", "无输出", "无战斗", "被动",
   ]
   core_is_passive = any(m in lore_low for m in passive_markers)
   if not core_is_passive:
       return False  # 核心设定本就允许主动能力，不拦
   # 2. 新事实是否给金手指新增了"主动攻击/输出/定向/战斗"语义
   active_combat_markers = [
       "offensive", "attack", "blast", "fire ", "shoot", "expel", "eject", "project",
       "weapon", "directed", "strike enemies", "combat capability", "launch",
       "release energy", "active ability", "drain enemies", "actively", "主动攻击",
       "输出伤害", "攻击敌人", "释放", "喷射",
   ]
   touches_goldfinger = any(g in nf for g in [
       "vial", "system", "treasure", "panel", "soul forge", "villain system",
       "玉瓶", "系统", "法宝",
   ])
   adds_active = any(m in nf for m in active_combat_markers)
   return touches_goldfinger and adds_active

def _get_perma_facts():
   """读取 S 级永久事实池（独立文件）。"""
   return safe_read_text(FILES["perma_facts"], "").strip()

def _append_perma_fact(chapter_num, fact_text):
   """把一条新的 S 级事实追加进永久池。

   ★ 软上限保护（防长篇膨胀）：永久池是上下文里唯一会随卷数累积的组件。
     设上限 PERMA_FACTS_CAP=120 条——足够覆盖一部500万字小说的核心设定。
     超限时把最老的事实归档到 perma_facts_archive（不丢失、可查），池中只保留最近120条，
     从根上封死上下文无限膨胀的可能。"""
   PERMA_FACTS_CAP = 120
   existing = safe_read_text(FILES["perma_facts"], "")
   line = f"Ch.{chapter_num}: {fact_text}".strip()
   if line in existing:   # 去重
       return
   header = "=== S-TIER PERMANENT FACTS (NEVER CONTRADICT, NEVER EXPIRE) ===\n"
   # 拆出已有事实行（排除表头）
   body_lines = [l for l in existing.splitlines() if l.strip() and not l.startswith("===")]
   body_lines.append(line)
   # 超过上限：把最老的移入归档文件，池中只留最近 CAP 条
   if len(body_lines) > PERMA_FACTS_CAP:
       overflow = body_lines[:len(body_lines) - PERMA_FACTS_CAP]
       body_lines = body_lines[-PERMA_FACTS_CAP:]
       archive_path = os.path.join(BASE_DIR, "perma_facts_archive.txt")
       safe_append_text(archive_path, "\n".join(overflow) + "\n")
       print(f"  🗄️  [永久池] 已归档 {len(overflow)} 条最老S级事实到 perma_facts_archive.txt（池保持{PERMA_FACTS_CAP}条上限）。")
   safe_write_text(FILES["perma_facts"], header + "\n".join(body_lines) + "\n")

def _get_windowed_facts(lore, chapter_num, window=RECENT_FACTS_WINDOW):
   """普通事实只取最近 window 章，老的普通事实不再注入（已被 S 级池和卷摘要覆盖）。"""
   facts_block = _get_absolute_facts(lore)
   if not facts_block:
       return ""
   kept = []
   for line in facts_block.splitlines():
       s = line.strip()
       if not s.startswith("Ch."):
           continue
       try:
           ch_num = int(s.split(":")[0].replace("Ch.", "").strip())
       except (ValueError, IndexError):
           continue
       # 最近 window 章内的普通事实保留；更早的若是 S 级也保留（兜底，正常已在永久池）
       if ch_num >= chapter_num - window or _classify_fact_is_s_tier(s):
           kept.append(s)
   if not kept:
       return ""
   return "\n".join(kept)

def _get_constitution(lore, chapter_num):
   """生成注入写作 prompt 的'世界宪法'：S级永久池 + 最近窗口普通事实。
   这是替代'全量 absolute_facts'的状态快照核心，长度不随章节无限增长。"""
   perma = _get_perma_facts()
   windowed = _get_windowed_facts(lore, chapter_num)
   parts = []
   if perma:
       parts.append(perma)
   if windowed:
       parts.append("=== RECENT FACTS (Last 20 Chapters) ===\n" + windowed)
   return "\n\n".join(parts) if parts else "Story just beginning."

def _get_relevant_characters(characters, quests, threads):
   context_text = json.dumps(quests) + json.dumps(threads)
   relevant = {n: d for n, d in characters.items()
               if n in context_text or d.get("narrative_role", "").lower() in ["protagonist", "main"]}
   return relevant if relevant else characters

def _get_volume_summaries(volumes):
   summaries = [f"[{k} Ch.{v.get('chapters','')}]: {v.get('compressed_summary','')}"
                for k, v in volumes.items() if v.get("completed", False)]
   return "\n".join(summaries) if summaries else "No completed volumes yet."

def _get_active_threads_text(threads):
   active = threads.get("active_threads", [])
   if not active: return "No active subplots."
   return "\n".join([f"[{t['id']}] {t['description']} (opened Ch.{t.get('opened_chapter','?')}, must resolve by Ch.{t.get('must_resolve_by_chapter','?')}, urgency: {t.get('urgency','medium')})"
                     for t in active])

def _get_villain_status_text(quests):
   villains = quests.get("villain_status", {}).get("active_villains", [])
   if not villains: return "No tracked villains yet."
   return "\n".join([f"[{v['name']}] {v.get('current_status','active')} | Must survive {max(0,v.get('minimum_arcs_required',2)-v.get('arcs_survived',0))} more Arc(s)."
                     for v in villains])

def _get_recent_hot_facts(lore, chapter_num, lookback=3):
   """提取最近 lookback 章新增的绝对事实，作为热点事实池优先注入写作 prompt。
   格式：lore 里每条绝对事实以 'Ch.N:' 开头。"""
   facts_block = _get_absolute_facts(lore)
   if not facts_block:
       return ""
   hot = []
   for line in facts_block.splitlines():
       line = line.strip()
       if line.startswith("Ch."):
           try:
               ch_num = int(line.split(":")[0].replace("Ch.", "").strip())
               if chapter_num - lookback <= ch_num <= chapter_num:
                   hot.append(line)
           except (ValueError, IndexError):
               pass
   if not hot:
       return ""
   return "=== HOT FACTS (Last 3 Chapters — Highest Priority) ===\n" + "\n".join(hot) + "\n=== END HOT FACTS ==="

# ─────────────────────────────────────────────────
# 步骤 0：预检 + 境界检查（合并调用）
# ─────────────────────────────────────────────────

def precheck_and_pacing(lore, status, threads, quests, chapter_num):
    """合并预检和境界检查，增加强制过期线程解决指令"""
    print(f"🔍 [预检+境界] 正在扫描第 {chapter_num} 章...")
    prompt = f"""
You are a story continuity checker and pacing manager.
[WORLD CONSTITUTION (S-tier + recent)]: {_get_constitution(lore, chapter_num)}
[Status]: {json.dumps(status, ensure_ascii=False)}
[Active Subplots]: {_get_active_threads_text(threads)}
[Villain Status]: {_get_villain_status_text(quests)}
[Chapter {chapter_num} Goal]: {json.dumps(quests, ensure_ascii=False)}

Task:
1. Check if micro_goal contradicts ABSOLUTE FACTS.
2. Check high-urgency threads overdue 10+ chapters.
3. Check MC realm matches combat difficulty.
4. Check if plan permanently defeats villain with arcs left.
5. Check realm pacing: if MC has been at same realm for >15 chapters and no breakthrough imminent, warn.
6. If there is a PACING OVERRIDE in ABSOLUTE FACTS, remind to obey.

Return EXACTLY this JSON:
{{"issues": [], "reminders": [], "pacing_reminders": []}}
"""
    data = extract_json(call_deepseek(prompt, temperature=0.1, timeout=600))
    if data:
        issues = data.get("issues", [])
        if issues:
            print(f"  ⚠️  预检发现问题: {issues}")

            # ★ 自动修正 micro_goal 矛盾：如果目标与绝对事实矛盾，让AI生成新目标并写入 quests.json
            critical_contradictions = [i for i in issues
                                        if isinstance(i, dict) and i.get("severity") == "critical"
                                        or (isinstance(i, str) and "contradict" in i.lower())]
            if critical_contradictions:
                fix_prompt = f"""The current chapter micro_goal contradicts established ABSOLUTE FACTS.
[ABSOLUTE FACTS]: {_get_absolute_facts(lore)}
[Current (Broken) Quests]: {json.dumps(quests, ensure_ascii=False)}
[Contradictions Found]: {json.dumps(critical_contradictions, ensure_ascii=False)}

Generate a corrected immediate_micro_goal that:
1. Does NOT repeat any event already in ABSOLUTE FACTS
2. Logically follows from the current story state
3. Creates genuine forward momentum

Return EXACTLY: {{"immediate_micro_goal": "corrected goal here"}}"""
                fix_result = extract_json(call_deepseek(fix_prompt, temperature=0.3, timeout=120))
                if fix_result and fix_result.get("immediate_micro_goal"):
                    quests["immediate_micro_goal"] = fix_result["immediate_micro_goal"]
                    safe_write_json(FILES["quests"], quests)
                    print(f"  🔧 [自动修正] micro_goal 已更新: {fix_result['immediate_micro_goal'][:80]}...")
        else:
            print("  ✅ 预检通过。")

        reminders = data.get("reminders", []) + data.get("pacing_reminders", [])
        
        # ★★★ 通用过期高优先级线程强制解决指令 ★★★
        if issues:
            for issue in issues:
                issue_str = str(issue).lower()
                if "overdue" in issue_str and ("high" in issue_str or "urgent" in issue_str or "thread_" in issue_str):
                    reminders.append("🔴 CRITICAL: One or more HIGH URGENCY subplot threads are overdue. At least one MUST be explicitly addressed or resolved in THIS chapter. Do not leave overdue high-urgency threads unmentioned.")
                    break
        # ★★★ 健康监控待办注入（战斗节奏/角色回归）：上一章监控发现的问题，转为本章主笔指令 ★★★
        health_todo_path = os.path.join(BASE_DIR, "health_todo.txt")
        health_todo = safe_read_text(health_todo_path, "").strip()
        if health_todo:
            for line in health_todo.splitlines():
                if line.strip():
                    reminders.append("📊 HEALTH-MONITOR DIRECTIVE — " + line.strip())
            safe_write_text(health_todo_path, "")  # 用完即清空，避免重复注入
            print(f"  📊 [健康待办] 已注入 {len(health_todo.splitlines())} 条监控指令到本章主笔。")

        return reminders
    print("  ⚠️  预检AI返回异常，跳过。")
    return []
  
# ─────────────────────────────────────────────────
# 步骤 1：生成章节正文（含上下文长度控制）
# ─────────────────────────────────────────────────

def generate_story(lore, status, characters, quests, threads, volumes,
                  recent_mem, arc_current, chapter_num, reminders, editor_feedback="", temperature=0.8):
   print(f"✍️  [主笔] 正在撰写第 {chapter_num} 章（生成温度: {temperature:.2f}）" + ("（主编打回重写）" if editor_feedback else "") + "...")

   # 提取最近章节标题，用于"标题去雷同"提示（治长篇后期标题套路化，如 "The Weight That..." 刷屏）
   _recent_titles = []
   for _ln in (arc_current or "").splitlines():
       _m = re.search(r'Ch\d+:\s*(.+?)\s+—', _ln)  # 匹配 "Ch12: Some Title — summary"
       if not _m:
           _m = re.search(r'Ch\d+:\s*(.+)', _ln)
       if _m:
           _t = _m.group(1).strip()
           # 去掉前缀 "Chapter N:" 只留标题主体
           _t = re.sub(r'^Chapter\s*\d+\s*[:：]\s*', '', _t).strip()
           if _t:
               _recent_titles.append(_t)
   _recent_titles = _recent_titles[-8:]
   if _recent_titles:
       _titles_block = "\n".join("- " + _t for _t in _recent_titles)
       recent_titles_hint = (
           "\n[RECENT CHAPTER TITLES — DO NOT echo their pattern]:\n" + _titles_block +
           "\nYour new title MUST NOT start with the same word or reuse the same template as these "
           "(e.g. if several begin 'The Weight...', do NOT begin with 'The Weight'). Use a fresh structure, "
           "a concrete image or a noun from THIS chapter's events. Vary sentence shape across titles.\n"
       )
   else:
       recent_titles_hint = ""

   # 对上下文进行智能摘要，防止过长
   relevant_chars = _get_relevant_characters(characters, quests, threads)
   # 只取前10个角色详情，避免过长
   if len(relevant_chars) > 10:
       relevant_chars = dict(list(relevant_chars.items())[:10])
   volume_summaries = _get_volume_summaries(volumes)[:1000]  # 截断
   active_threads = _get_active_threads_text(threads)[:1500]
   villain_text = _get_villain_status_text(quests)[:500]
   target_words = get_target_word_count(chapter_num)
   # 状态快照：S级永久事实池 + 最近20章普通事实（长度不随章节膨胀）
   constitution = _get_constitution(lore, chapter_num)
   hot_facts    = _get_recent_hot_facts(lore, chapter_num, lookback=3)
   lore_rules = lore.split('=== ABSOLUTE FACTS')[0].strip() if '=== ABSOLUTE FACTS' in lore else lore
   # 过期10章以上的高优先级线程 → 生成前就强制注入写作要求（不只靠主编拦截）
   active_threads_list = threads.get("active_threads", [])
   force_thread_blocks = []
   for t in active_threads_list:
       if t.get("urgency") == "high":
           overdue_by = chapter_num - t.get("must_resolve_by_chapter", chapter_num)
           if overdue_by >= 10:
               force_thread_blocks.append(
                   f"🔴 MANDATORY SCENE REQUIRED: Thread [{t['id']}] '{t['description']}' "
                   f"is {overdue_by} chapters overdue. This chapter MUST contain a scene that "
                   f"explicitly advances or resolves this thread. This is not optional."
               )
   if force_thread_blocks:
       reminders = list(reminders) + force_thread_blocks

   reminders_text = "\n".join(str(r) if not isinstance(r, str) else r for r in reminders) if reminders else "None."

   rewrite_block = f"""
=== CHIEF EDITOR REJECTION — MUST FIX ===
{editor_feedback}
=== END EDITOR REJECTION ===
""" if editor_feedback else ""

   # 从书目配置中心获取规则（新增书目只需在 BOOK_CONFIG 里加配置即可）
   cfg = get_book_config()
   lore_lower = lore_rules.lower()
   # 优先用 BOOK_CONFIG 里的规则；若 lore 关键词匹配到其他已知书目则覆盖
   novel_type_rules = cfg["combat_rules"]
   protagonist_card = cfg["protagonist"]
   tone_anchor      = cfg.get("tone_anchor", "")
   _mc_name         = cfg.get("mc_name", "")
   _mc_gender       = cfg.get("protagonist_gender", "male")
   for book_id, bcfg in BOOK_CONFIG.items():
       if any(kw in lore_lower for kw in bcfg["genre_keywords"]):
           novel_type_rules = bcfg["combat_rules"]
           protagonist_card  = bcfg["protagonist"]
           tone_anchor       = bcfg.get("tone_anchor", tone_anchor)
           _mc_name          = bcfg.get("mc_name", _mc_name)
           _mc_gender        = bcfg.get("protagonist_gender", _mc_gender)
           break
   # 主角代词指令（防后宫文等女性角色多的章节把男主写成 she）
   if _mc_gender == "male":
       _pronoun_directive = (
           f"★ PROTAGONIST GENDER: {_mc_name or 'The protagonist'} is MALE. Always use he/him/his for him. "
           f"This story may have many female characters — be careful NOT to slip and use she/her for the male "
           f"protagonist. Every pronoun referring to {_mc_name or 'the MC'} must be he/him/his, without exception."
       )
   else:
       _pronoun_directive = (
           f"★ PROTAGONIST GENDER: {_mc_name or 'The protagonist'} is FEMALE. Always use she/her for her. "
           f"Be careful not to slip into he/him for the female protagonist."
       )

   prompt = f"""You are a top-tier Webnovel author writing a 3-million-word epic novel.
Current Chapter: {chapter_num}. Target: ~{target_words} words.

★★★ TONE ANCHOR — THIS OVERRIDES EVERYTHING. READ FIRST, OBEY ALWAYS ★★★
{tone_anchor}
No matter what happened in previous chapters, THIS chapter must match the tone above.
If recent chapters have drifted away from this tone, steer back toward it NOW.
★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★

{novel_type_rules}
=== WORLD CONSTITUTION - ABSOLUTE (NEVER CONTRADICT) ===
{constitution}
★ Any specific NUMBER stated in the constitution (the MC's age, a count of years, a quantity, a date) is
LOCKED. Copy it exactly — never change the MC's age or any fixed figure. If the constitution says the MC is
17, he is 17 (write "seventeen", never "sixteen" or any other number) until the story explicitly ages him.

{hot_facts}

=== WORLD RULES ===
{lore_rules}

=== VOLUME HISTORY ===
{volume_summaries}

=== CURRENT ARC CONTEXT ===
{arc_current}

=== RECENT 5 CHAPTERS ===
{recent_mem}

=== RELEVANT CHARACTERS ===
{json.dumps(relevant_chars, indent=2, ensure_ascii=False)}
★ CHARACTER CONSISTENCY: Each character above has a "character_voice" and personality. Keep every returning
character EXACTLY consistent with how they were established — same speech pattern, same temperament, same way
of treating the MC. A cautious schemer does not suddenly become reckless; a cold villain does not suddenly turn
warm; a terse character does not suddenly become chatty — unless the story has shown a clear reason for the
change. Readers of long series notice instantly when a character acts "out of character."

=== ACTIVE SUBPLOTS ===
{active_threads}

=== VILLAIN SURVIVAL STATUS ===
{villain_text}

=== CURRENT STATUS ===
{json.dumps(status, ensure_ascii=False)}

★ NUMERIC RESOURCE / COUNTER RULE (MANDATORY — applies to ALL countable totals AND story stats):
The ONLY correct values for any countable resource (spirit stones, pills, lifespan, contribution
points, soul essence, forge materials) OR any story stat (mutation %, integration %, affinity,
corruption, progress) are the numbers shown in CURRENT STATUS above (in "resources", "stats", or the status fields).
NEVER calculate, add, or subtract any of these totals yourself — you make arithmetic errors.
If a resource or stat changes this chapter, describe it WITHOUT stating a new exact total
(e.g. "he handed over the stones, his pouch noticeably lighter" — NOT "70,000 remained";
"the mutation crept higher, harder to ignore" — NOT "mutation now at 9.8%").
If you must state a value, copy ONLY the exact number shown above, unchanged.
★★ THIS INCLUDES [SYSTEM] PANELS (critical for LitRPG/system novels): A [SYSTEM:] readout is NOT exempt.
In a system panel you MAY show the CHANGE for flavor ("+45 Soul Essence", "Level up to Lv.2") because a
delta is fine — but you must NEVER write a running TOTAL you computed yourself ("Total: 90", "Soul Essence: 90
available", "Legion 1/2" with a guessed cap). Writing a self-computed total in a panel is the #1 way a system
novel's numbers drift out of sync with the engine and confuse readers. Show deltas and events; let the engine
own the totals. If you truly need to show a total, copy it EXACTLY from the CURRENT STATUS resources block.

★ GOLDEN-FINGER STATE (if "goldfinger_output_state" appears in CURRENT STATUS above): that sentence tells you
EXACTLY what the MC's treasure/system currently holds and what was already consumed. Do NOT let the MC re-use
or re-refine any material it says is already spent/gone. If he needs a new golden-finger output this chapter,
he must obtain a FRESH source first. Treating a consumed material as still available is a continuity break.
★ GOLDEN-FINGER ASSETS (if "goldfinger_assets" appears in CURRENT STATUS): that list is the MC's CURRENT roster
of persistent golden-finger creations (undead minions, reaped souls in reserve, bound servants). Only these
exist. A minion or soul NOT on this list was destroyed/spent in an earlier chapter and CANNOT reappear, fight,
or be commanded — it is gone for good. To field a new one, the MC must forge/reap it fresh this chapter (which
costs a real source and resources). Never let a shattered minion or a spent soul silently return.

=== CURRENT GOALS ===
{json.dumps(quests, ensure_ascii=False)}

=== AUTHOR REMINDERS ===
{reminders_text}
{rewrite_block}
=== WRITING TASK ===
Write Chapter {chapter_num}. Target: ~{target_words} words.

VILLAIN RULE: Any villain with arcs left — wound/repel only. Never permanently defeat.

PERSONALITY RULE: Obey the protagonist personality rules in the lore strictly.

=== PROTAGONIST PERSONALITY CARD (MUST FOLLOW) ===
{protagonist_card}
{_pronoun_directive}
=== END PERSONALITY CARD ===

TENSION RULE: Protagonist is dangerous but NOT omniscient. Genuine danger must exist.
Every 3 Arcs: at least one situation where current power is genuinely insufficient.

=== UNIVERSAL FIGHT-CRAFT ENGINE (applies to EVERY action scene, on top of this book's combat rules) ===
A boring fight kills a webnovel faster than anything. Whenever this chapter contains combat, obey ALL of this:
• STAKES FIRST: before blows land, the reader must know what the MC loses if he fails THIS fight
  (his life, someone he protects, a resource, a secret, his cover). No stakes = no tension. Establish it fast.
• NO BLOW-BY-BLOW ACTIONS-LIST: never narrate a fight as "attack, block, counter, dodge". A fight is a contest of
  WILLS and PLANS. Show intent, read, feint, mistake, adaptation. The MC should be solving a problem, not
  swinging a weapon. The best beat is the MC noticing the one thing that wins it.
• ASYMMETRY & RISING DANGER: the MC should not be comfortably stronger. Make him improvise, bleed, spend a
  trump card, or nearly lose. A fight he wins easily is not worth writing — raise the danger until the win costs him.
• COST IS MANDATORY: every meaningful win leaves a mark — a wound, a spent resource, a revealed card, a
  lasting consequence, a debt. Nothing is free. The reader must feel the price.
• SENSORY & VISCERAL: ground the fight in the body and the senses — the jolt up the arm on impact, the smell of
  ozone/blood/scorched earth, the half-second of tunnel vision, the way the ground feels underfoot. Make it physical.
• PACING — BREATHE THEN STRIKE: alternate tight bursts of fast action with micro-beats of stillness (a held
  breath, a single thought, eye contact). The contrast is what makes the strike hit hard. Never one flat speed.
• BIG FIGHTS SPAN MULTIPLE CHAPTERS: any major named-enemy battle must NOT resolve in one chapter. Build it,
  complicate it, let it turn — break on a cliffhanger mid-battle. Only fodder dies fast.
• MATCH THE GENRE'S FLAVOR: the fight must FEEL like this book's type — an orthodox-xianxia duel of qi, sword-arts
  and realm-pressure reads nothing like a LitRPG necromancer commanding a stitched legion with cooldowns and
  system-callouts, which reads nothing like an elegant villain-protagonist dismantling a foe through schemes and
  fate-reading before a blow is even struck. Lean HARD into this book's specific combat identity from its rules above.
=== END FIGHT-CRAFT ENGINE ===

=== MASTER CRAFT PRINCIPLES (distilled from the genre's greatest works — obey in EVERY chapter) ===
These are the rules that separate a story readers binge for 2000 chapters from one they drop at chapter 20.
• HARD RULES CANNOT BE BROKEN, ONLY AVOIDED. If a danger is above the MC's current power, he must NOT escape
  it by luck, a sudden convenient power-up, or the plot bailing him out. He survives by avoiding it, outwitting
  it, paying a price, or running. A problem solved by luck or asspull is the #1 thing that makes readers quit.
  (This is the soul of the genre's best work: the world is a ruthless pyramid and the MC is not exempt from it.)
• EVERY FIGHT MUST BE "言之有物" — LEGIBLE AND EARNED. The reader must always understand WHY the MC won (which
  trick, item, technique, terrain, or preparation did it) and WHY a loss happened (what he lacked). Never "he
  punched and the enemy exploded". Show the mechanism: the setup, the counter, the thing held in reserve, the
  escape route. A win the reader can't explain is a cheat; a win they can trace is a thrill.
• THE GOLDEN-FINGER / SYSTEM IS A TOOL, NOT THE ANSWER. The MC's special advantage drives the plot but must NOT
  directly solve his problems. It is used through patience and cleverness. The reader should sometimes almost
  forget it exists. The MC wins because he is smart and careful, not because his cheat is strong.
• ★ NEVER EXCEED THE GOLDEN-FINGER'S DEFINED LIMITS ★ — Check the ABSOLUTE FACTS for exactly what the MC's
  treasure/system can and cannot do, and NEVER let it do more. If it is defined as PASSIVE (e.g. "slowly refines
  one sealed item; no panels, no combat power, only refinement"), then it has NO offensive use, NO directed
  output, NO blasting, NO draining enemies, NO activation in a fight — it cannot be weaponized, period. A mortal
  with no cultivation especially CANNOT actively channel a treasure in combat. Giving the golden-finger a new
  power it was never defined to have is an instant continuity rejection. The treasure grows the MC's options
  SLOWLY and INDIRECTLY (better materials, better pills, hidden edges) — never as a sudden combat trump card.
  If you are tempted to use the treasure to win a fight, STOP: the MC must win with wits, terrain, traps, and
  preparation instead.
• ★ GOLDEN-FINGER OUTPUTS ARE ONE-TIME AND NEED A FRESH SOURCE ★ — Anything the treasure/system produces is
  CONSUMED when used and CANNOT be reused. The SOURCE MATERIAL is also one-time: blood refined into essence is
  GONE once refined; once that essence is spent, it does not come back, and you cannot refine "the same blood"
  again. To produce a new golden-finger output, the MC must obtain a NEW source THIS chapter (fresh blood from
  a new wound, a newly gathered herb, a freshly killed enemy's soul). Check what the MC actually still has —
  never let him re-refine or re-use a material the story already consumed in an earlier chapter. Conjuring a
  resource out of nothing is the kind of continuity break that gets a chapter rejected.
• SUPPORTING CHARACTERS HAVE THEIR OWN AGENDAS. No character exists only to serve the MC. Every meaningful
  ally, rival, elder, or faction has private motives, plays their own game, and may help or betray for their own
  reasons. The MC navigates a web of competing interests — he is rarely the only schemer in the room.
• POWER IS A PYRAMID; PROGRESS MUST BE FELT. Show the brutal gap between tiers. When the MC grows stronger, make
  the reader FEEL the new altitude — something that almost killed him last arc is now manageable, but a new and
  larger threat looms above. Progression is the drug; never let a breakthrough feel weightless or unearned.
• DARE TO WRITE SACRIFICE AND LOSS. Not everything works out. Sometimes the MC must abandon someone, lose a
  treasure, or make a cold choice with real cost. A story where everyone the MC likes ends up safe and happy is
  hollow "小白文". Occasional genuine loss and hard trade-offs are what give the long climb its weight.
• SLOW-BURN IS FINE — BUT EVERY CHAPTER NEEDS A HOOK. A quiet chapter still plants a question, a threat, an
  opportunity, or an unresolved tension that pulls the reader to the next one. Never end on flat resolution.
• MATCH THE GENRE'S SATISFACTION ENGINE. Orthodox xianxia satisfies through scheming, realm-pressure and the
  cold logic of survival; LitRPG/system satisfies through a self-consistent system where numbers MEAN something
  and growth is visible; villain-protagonist satisfies through elegant, three-moves-ahead intellectual dominance.
  Lean into THIS book's specific engine of satisfaction — do not write a generic fantasy that could be any of them.
=== END MASTER CRAFT PRINCIPLES ===

REALM PACING RULE: Do NOT rush breakthroughs. Each realm needs 2-3 major arcs.
ANTI-RUSH: If ahead of schedule 20+ chapters, introduce a bottleneck or enemy too strong to beat yet.

=== HUMAN WRITING STYLE RULES — ELIMINATE AI SMELL ===

1. SENTENCE VARIETY: Mix lengths aggressively. Short hits. Then longer pulls the reader forward.
  FORBIDDEN: Three+ sentences of similar length in a row.

2. BAN CORPORATE VOCABULARY:
  NEVER use: testament, beacon, tapestry, pivotal, crucial, profound, intricate, bustling,
  meticulous, showcase, furthermore, needless to say, couldn't help but, found himself, made his way.

3. BAN AI STACCATO PATTERN:
  FORBIDDEN: "Not X. Not Y. It was Z." pattern more than ONCE per chapter.
  Show what IS happening. Never define a moment by what it isn't.

4. BAN MODERN VOCABULARY IN GENRE SETTINGS:
  FORBIDDEN in cultivation/fantasy settings: cognitive dissonance, variables, catalogued,
  parameters, algorithm, optimize, metrics, calibrate, protocol.
  Replace with in-world equivalents.

5. NEVER WRITE THE AI PATCH:
  FORBIDDEN: Acknowledging a logical impossibility and ignoring it.
  If something unusual happens, justify it in-universe.

6. SHOW DON'T EXPLAIN: Show emotions through physical detail, action, and dialogue.
  FORBIDDEN: "He felt a surge of power." → Write WHAT the power felt like physically.

7. PARAGRAPH RHYTHM: Vary paragraph length. One-line paragraphs for impact, used strategically.

8. DIALOGUE MUST SOUND SPOKEN: Allow interruptions, unfinished thoughts (em-dashes), avoidance.
  Tags: mostly "said" and "asked". Avoid: exclaimed, proclaimed, declared, intoned.

9. SENSORY ANCHOR RULE (NEW — CRITICAL):
  Every scene must open with a concrete sensory detail — sound, smell, temperature, or texture.
  FORBIDDEN: Opening a scene with visual description or background narration.
  CORRECT: "Stone pressed cold through his robe." / "Somewhere below, water dripped in the dark."
  FORBIDDEN: "The courtyard was large and imposing." / "It was a dark night."
  At least ONE non-visual sense must appear per scene: sound, smell, heat, cold, pain, texture.
  ★ VARY THE OPENING — DO NOT use the same template every chapter. In particular, do NOT keep opening
    with taste/smell of air ("The air tasted of...", "The air smelled of...") or "The [object] was cold."
    Rotate the entry point: a sound, a sudden motion, a line of dialogue, a physical sensation on the skin,
    a smell, the weight of something in hand. The opening sentence of each chapter should feel structurally
    different from the previous chapters' openings. Sensory ≠ one fixed formula.

9b. METAPHOR RESTRAINT RULE (NEW — CRITICAL AI TELL):
  Do NOT pour out a simile/metaphor/poetic image every few sentences. A constant stream of
  "quotable" figurative lines is one of the strongest AI tells. Let MOST of the prose be plain,
  literal, functional narration. Use at most ONE figurative image per ~200 words, and NONE during
  routine action beats. Save your best image for the scene's key moment so it lands hard.
  A page of clean literal prose makes the single metaphor that follows far more powerful.
  Also vary the page shape: occasionally a longer dense paragraph (5-8 lines), occasionally a
  one-word line ("Run."), and the odd small human friction (a hesitation, a thing that fails once,
  "He almost laughed.") — so the rhythm is never AI's too-even 1-3-sentence pattern.

10. MICRO-ACTION RULE (NEW — CRITICAL):
   FORBIDDEN: Summary narration. "He defeated the enemy and left."
   Instead: Write the micro-actions. The tremor in the muscle before the sword swings.
   The sound of blood hitting stone. The specific way the body falls.
   Show the physical reality of every significant moment.
   When a character does something important — slow down and inhabit the action.

11. ZERO DIALOGUE ADJECTIVES RULE (NEW):
   FORBIDDEN: "he said coldly" / "she whispered nervously" / "he laughed arrogantly"
   Replace with: character's action, gaze, or body language before or after the dialogue.
   CORRECT: He set down the cup. "You have three days."
   FORBIDDEN: "You have three days," he said with cold finality.

12. NO OMNISCIENT NARRATOR: FORBIDDEN: Explaining WHY the protagonist does something from outside.
   Show intelligence through consequences and actions. Let readers piece it together.

13. ELASTIC PACING: Not every chapter needs a fight. Not every fight needs a reward.
   Allow occasional chapters of pure atmosphere, preparation, or recovery.

14. PROTAGONIST ALLOWED TO BE IMPERFECT: Under extreme pressure or exhaustion,
   allow: irritation, minor miscalculation, retrospective fear after a close call.

15. ABILITY ACQUISITION IS EARNED: Any technique used must have been acquired on-screen.
   First use of new ability: show the protagonist referencing the source.

16. CLIFFHANGER / HOOK (MANDATORY — the chapter's last beat decides if they read the next one):
    The final 1-2 paragraphs MUST leave an unresolved pull forward — a concrete threat, a looming danger, a
    hard decision, a question, an opportunity with a ticking clock, or a sudden reveal. This applies EVEN to
    quiet slow-burn chapters: a calm chapter still ends on tension, not on peaceful reflection.
    WRONG (flat, reflective — do NOT do this): "He closed his eyes. He let it rest there, and smiled once in
      the dark." (resolves everything, pulls nowhere → readers stop here).
    RIGHT (plants a pull): end on the footsteps stopping outside his door / an elder's gaze lingering on him a
      beat too long / the realization that someone already knows / a deadline he cannot meet / a name he was
      not supposed to hear. Make the reader NEED the next chapter. Never end on a settled, contented note.

17. CHARACTER MOMENT (MANDATORY): One scene showing protagonist personality beyond action.

18. ANTI-SEQUENCE RULE: FORBIDDEN: Writing the chapter as a numbered list of events.
   FORBIDDEN: "First X happened. Then Y occurred. After that Z."
   Instead: Plant the reader inside ONE moment. Let other events emerge from it organically.
   A fight is not "attack → block → counter". It is one instant of cold clarity before a swing.
   A revelation is not "he learned X and then did Y". It is the weight of X landing in his chest.
   Slow down. Inhabit the moment. Let the sequence disappear into lived experience.

=== ABSOLUTE OUTPUT FORBIDDEN ===
- NEVER write "[Next Chapter Teaser", preview blocks, chapter teasers.
- NEVER write "Chapter X End", "End of Chapter", or end labels.
- NEVER write author notes or any text outside the story.
- The chapter ends when the story moment ends. Nothing after the final story sentence.

FORMAT: First line = 'Chapter {chapter_num}: [Unique Title]'. No markdown in title.{recent_titles_hint}
Output ONLY pure story text.
"""
   story = call_deepseek(prompt, temperature=temperature, timeout=800, max_tokens=32000)
   if not story:
       return story

   story = clean_ai_endings(story)
   print(f"  ✅ 章节正文生成完毕（{len(story)} 字符）。")

   # ── 去AI味润色（第二道处理）──────
   print(f"  ✂️  [润色] 正在执行去AI味后处理...")
   polish_prompt = f"""You are a human author's final editor. Your job is to make the following chapter
feel like it was written by a real human novelist, not an AI.

DO NOT change the plot, characters, events, or story content in any way.
DO NOT add or remove scenes.
DO NOT change what happens.

ONLY make these specific edits:

1. BREAK SYMMETRY: Find any groups of 3+ sentences that follow the same rhythm or length.
  Disrupt them by varying SENTENCE LENGTH — make one a short COMPLETE sentence, make one longer.
  Do NOT create sentence fragments to do this; a short complete sentence ("He waited.") breaks rhythm
  just as well and reads human, not AI. Never increase the number of subject-less fragments.

2. ROUGHEN DIALOGUE: If any dialogue tag uses an adverb ("coldly", "quietly", "calmly"),
  delete the adverb and replace with a physical action beat before or after the line.

3. INTERRUPT SYSTEM TEXT (for system-fiction novels): If [SYSTEM: ...] notifications
  appear more than once in sequence, make at least one of them cut off or feel glitchy.
  Real system UI feels mechanical, not conversational.

4. ADD ONE INCOMPLETE THOUGHT: Find one place where the POV character starts a thought
  and doesn't finish it. Use an em-dash or just let it trail.
  Example: "He could feel the fragment warming — "
  The next paragraph starts a new action. Don't resolve the unfinished thought.

5. REMOVE ONE EXPLANATION: Find the single most over-explained moment in the chapter
  where the narrator tells the reader what to think or feel.
  Delete the explanation. Leave the action. Trust the reader.

6. VARY ONE PARAGRAPH BREAK: Find a long paragraph that should breathe.
  Split it somewhere unexpected — not at a logical break, but at a moment of tension.
  One sentence alone. Then the rest continues.

7. ROUGHEN ONE METAPHOR: Find the cleanest, most AI-sounding metaphor or simile.
  Make it slightly stranger, more specific, or more unexpected. Less poetic. More real.
  Example: "like fire" → "like touching the side of a furnace three hours after the coal ran out"

8. FIRST-WORD AUDIT: Check the first word of every paragraph.
  If more than 40% of paragraphs start with He/She/The/A/An, fix at least half of them.
  Options: Start with a location detail. Start with a sound or smell. Start with the result of an action.
  WRONG: "He scanned the room." → RIGHT: "Dust motes drifted through the light. He scanned—"
  WRONG: "She stepped forward." → RIGHT: "Cold stone under her boots. She stepped forward."
  This is the single most reliable tell between AI and human prose. Fix it.

9. ★★ HIGHEST PRIORITY — ELIMINATE STACCATO NEGATION ★★
  This is the #1 reason chapters get rejected. You MUST hunt down and rewrite EVERY
  "Not X." / "Not Y." / "No Z." short negation fragment used for dramatic effect.
  The HARD LIMIT is 2 such fragments in the ENTIRE chapter. Aim for ZERO.
  WRONG: "It was not fear. Not hesitation. Not doubt. It was something colder."
  RIGHT: "What rose in him was colder than fear, steadier than doubt — something he had no name for."
  Method: find every sentence that defines a thing by what it ISN'T, and rewrite it to
  state what the thing IS, in a single flowing sentence. Scan the whole chapter twice for these.
  Do not leave more than 2. This single fix prevents most rejections.

10. ★★ THIN OUT METAPHORS & IMAGERY (critical AI tell) ★★
  AI writing piles on a simile/metaphor/poetic image every few sentences ("a finch's heart against
  a tin can", "cold iron", "old bone", "standing at the bottom of a well"...). A constant stream of
  "quotable" lines is one of the clearest AI tells. CUT roughly HALF of the figurative language.
  Let plain, functional narration carry most of the page; let descriptions just be literal.
  Save ONE or TWO genuinely striking images for the chapter's key moments, where they will hit hard.
  Rule of thumb: at most one figurative image per ~200 words, and NONE in routine action beats.
  Plain is not weak — a page of clean literal prose makes the single metaphor that follows land harder.

11. ★★ BREAK THE RHYTHM — avoid AI's too-even pacing (use SPARINGLY) ★★
  AI makes every paragraph a tidy 1-3 sentences and every event flow smoothly in order. Disrupt it:
  - Occasionally fuse several beats into ONE longer, denser paragraph (5-8 lines) where tension builds.
  - Very rarely (1-2 times in the whole chapter) drop a ONE-WORD or three-word line for impact ("Run.").
  - Add the odd small human friction: a hesitation, a thing that doesn't work the first time, a flicker
    of real reaction — one short beat is enough, don't overdo it.
  Vary paragraph length deliberately. But the variation comes mainly from SENTENCE LENGTH, not from
  chopping sentences into fragments. A short COMPLETE sentence ("He ran.") varies rhythm just as well as
  a fragment ("Running.") — and reads human instead of AI. Prefer the short complete sentence.

11b. ★★★ THE #1 REWRITE-TRIGGER — READ THIS AND OBEY IT EXACTLY ★★★
  The single most common reason a chapter gets rejected and rewritten is TOO MANY FRAGMENTS. Avoid it
  from the FIRST draft — do not rely on a later edit. Here is the one rule that prevents 90% of rewrites:

  ►► EVERY SENTENCE MUST HAVE A SUBJECT AND A VERB, with only RARE exceptions. ◄◄

  A "fragment" = any sentence missing a subject or a main verb. Examples of what to AVOID:
      "Picked clean." → "The shelf was picked clean."
      "Knife untouched." → "His knife lay untouched."
      "Pouch on the table." → "He set the pouch on the table."
      "Cold. Slick. Wrong." → "The stone was cold and slick, and something about it felt wrong."
      "Lunged. The disciple." → "He lunged at the disciple."
      "Forward, he crept." → "He crept forward."

  HARD COUNTABLE BUDGET for the ENTIRE chapter (count them as you write — do NOT exceed):
      • Subject-less / verb-less fragments: AT MOST 3 in the whole chapter (target: 0-2).
      • Verb-fronted scraps ("Lunged.", "Stoppered the vial."): AT MOST 1.
      • Fronted/inverted sentences: AT MOST 2. These start with a preposition/adverb and push the subject
        back. The detector flags sentences starting with ANY of: Into/Under/Behind/Beside/Before/From/
        Across/Beneath/Toward/Through/Over/Against/Out/Up/Down/Past/Along/Within/Atop/Above/Below.
        WRONG: "Behind him, the ravine opened into darkness." → RIGHT: "The ravine opened into darkness behind him."
        WRONG: "From the crevice, he stepped out." → RIGHT: "He stepped out of the crevice."
        WRONG: "Beside the pool lay something massive." → RIGHT: "Something massive lay beside the pool."
        A couple of these are fine for variety; more than 2 reads as an AI tic and triggers a rewrite.
      • One-word lines: AT MOST 2.
  If a chapter is ~1500 words and you have written more than 3 fragments, you have ALREADY failed —
  go back and rejoin them into complete sentences before finishing. When in doubt, write the COMPLETE
  sentence. A page of clean subject-verb-object prose with varied LENGTH is exactly what a skilled human
  writes; a page sprinkled with fragments is the clearest machine tell and WILL be sent back for rewrite.

  ►► ALSO WATCH PARAGRAPH OPENINGS: do not start more than ~45% of paragraphs with He/She/The/A/An.
  Vary openings with a sensory detail, a sound, a location, the result of an action, or a clause. ◄◄

11b-2. ★★ DON'T NARRATE LIKE A PLOT SUMMARY (no "then... then... after that... finally") ★★
  Do NOT string events together with sequential connectors. If the prose leans on "then he", "then she",
  "after that", "next,", "finally," to move from beat to beat, it reads like a synopsis, not a scene, and
  triggers a rewrite. HARD LIMIT: AT MOST 3 such sequence markers in the whole chapter.
  WRONG: "He drew the talisman. Then he lit it. After that he threw it. Finally the array collapsed."
  RIGHT: "He drew the talisman and touched flame to its edge. The paper caught — he flung it into the array's
         heart, and the formation buckled, light bleeding from the cracks."
  Transition through cause-and-effect, sensory shifts, or white space between paragraphs — not a checklist.

11c. ★★ NO MECHANICAL "He did X. He did Y. He did Z." CHAINS ★★
  Do NOT write four or more sentences in a row that all start with "He" or "She" followed by a verb.
  That machine-gun subject-verb pattern is a strong AI tell. After at most THREE such sentences, break
  the chain: combine two actions into one sentence, start from an object or a sensation, give a line of
  dialogue, or add a beat of reaction. HARD RULE: never more than 3 consecutive "He/She + verb" sentences.
  WRONG: "He stood. He crossed the room. He opened the door. He stepped outside. He looked around."
  RIGHT: "He stood and crossed the room. The door opened onto a cold yard, and he paused on the threshold,
         scanning the shadows before he stepped out."

11d. ★★ DON'T NARRATE LIKE A PLOT SUMMARY (no "then... then... after that... finally") ★★
  Do NOT string the chapter's events together with sequential connectors. If the prose leans on
  "then he", "after that", "next", "finally" to move from beat to beat, it reads like a synopsis, not a scene.
  HARD RULE: across the whole chapter use at most THREE such sequence markers ("then he/she", "after that",
  "next,", "finally,") combined. Instead, let scenes transition through cause-and-effect, sensory shifts,
  white space between paragraphs, or a new line of action — not a checklist of "and then".
  WRONG: "He drew the talisman. Then he lit it. After that he threw it. Finally the array collapsed."
  RIGHT: "He drew the talisman and touched flame to its edge. The paper caught — he flung it into the
         array's heart, and the formation buckled, light bleeding out of the cracks."

12. ★★ NO REPEATED ONE-WORD "COOL REACTION" BEATS ★★
  A single isolated one-word line ("Interesting." / "Convenient." / "Predictable." / "Useful.") can hit hard —
  but AI overuses them and, worse, REPEATS the same one twice in a chapter. That is a glaring AI tell.
  HARD RULE: the same single-word reaction line may appear AT MOST ONCE per chapter. If you see "Interesting."
  (or any such word) used twice, rewrite all but one — fold it into a real sentence or cut it. Across the whole
  chapter, use at most TWO such isolated one-word reaction lines total. Make them earn their place.

13. ★★ KILL "LABEL-TAGGING" EXPLANATION PHRASES (strong AI tell) ★★
  AI loves to explain a character by tagging an abstract category onto them, especially the construction
  "the particular X of someone who ..." or "with the air of a person who ...". These read as AI analysis,
  not human storytelling. Hunt them down and rewrite into concrete, shown behavior.
  WRONG: "the particular arrogance of someone who believed suffering had earned him cruelty."
  RIGHT: "He said it the way men do when they've rehearsed the line in a mirror — chin up, daring the room to laugh."
  Also avoid meta-narrative numbers that break immersion (e.g. "at Chapter 147"); phrase fate/destiny in-world
  ("years from now", "when the frost moon rose") instead of citing chapter numbers.

14. ★★ FIX CHOPPY FRAGMENTS & INVERTED-SENTENCE OVERUSE (critical AI tell in action scenes) ★★
  When rule 11 ("break the rhythm") is pushed too far, AI does TWO bad things that you must now correct:
  (a) SUBJECT-LESS FRAGMENTS: it chops normal sentences into verb-only or object-only scraps —
      "Picked clean." "Believed it." "Knife untouched." "Map folded, slipped into his jacket."
      A reader feels machine-gun staccato, not power. FIX: most sentences must have a clear subject and
      verb. A bare fragment is seasoning — at most ONE every ~150-200 words, and never several in a row.
      Rejoin chopped scraps into proper sentences: "He believed it." not "Believed it."
  (b) FRONTED / INVERTED CLAUSES: it starts action sentences with the object or adverb and pushes the
      subject to the back — "Into his pocket the knife dropped." "Under the bus he went." "Backward he
      threw himself." One such inversion can punch; a whole chapter of them is a glaring AI tic.
      FIX: keep AT MOST 2-3 inverted/fronted action sentences in the entire chapter. Rewrite the rest in
      natural subject-verb-object order: "He dropped the knife into his pocket." "He scrambled under the bus."
  Goal: clean, natural prose where MOST sentences are ordinary S-V-O, and fragments/inversions are rare,
  deliberate accents — not the default texture. This does NOT contradict rule 11; it is the correction
  for overdoing it. Varied rhythm = a few accents in a bed of normal sentences, not constant chopping.

Return the complete revised chapter text. Keep the Chapter title line exactly as-is.
Output ONLY the story text. No comments, no explanations.

[CHAPTER TO POLISH]:
{story}
"""
   polished = call_deepseek(polish_prompt, temperature=0.6, timeout=800,
                            max_tokens=32000, presence_penalty=0, frequency_penalty=0)
   if polished and len(polished) > len(story) * 0.7:
       polished = clean_ai_endings(polished)
       print(f"  ✅ 去AI味润色完成（{len(polished)} 字符）。")
   else:
       print(f"  ⚠️  润色返回异常，使用原始稿件。")
       polished = story

   # ── 专项二次清洗：Staccato Negation（重写头号元凶，送审前必须压到≤2）──
   neg_count = len(re.findall(r'\bNot\s+\w[\w\s]{0,20}\.', polished))
   if neg_count >= 3:
       print(f"  🎯 [专项清洗] 检测到 {neg_count} 处 'Not X.' 句式，触发定向重写...")
       fix_prompt = f"""The chapter below overuses the "Not X. Not Y." staccato negation pattern
({neg_count} occurrences). This is the single most common AI writing tell.

Your ONLY task: rewrite EVERY instance so the chapter contains AT MOST 2 such fragments. Aim for 0.
For each "Not X." fragment that defines something by what it isn't, rewrite it into a single
flowing sentence that states what the thing IS instead.
Change NOTHING else — same plot, same events, same dialogue, same length. Only fix the negations.
Keep the Chapter title line exactly as-is. Output ONLY the full revised story text.

[CHAPTER]:
{polished}"""
       refixed = call_deepseek(fix_prompt, temperature=0.5, timeout=800, max_tokens=32000, presence_penalty=0, frequency_penalty=0)
       if refixed and len(refixed) > len(polished) * 0.7:
           refixed = clean_ai_endings(refixed)
           new_count = len(re.findall(r'\bNot\s+\w[\w\s]{0,20}\.', refixed))
           print(f"  ✅ [专项清洗] 'Not X.' 句式 {neg_count} → {new_count}。")
           polished = refixed
       else:
           print(f"  ⚠️  [专项清洗] 返回异常，保留润色稿。")

   # ── 专项二次清洗：禁用词（送审前替换成符合世界观的词，避免被主编扣分打回）──
   found_banned = [w for w in BANNED_WORDS if w in polished.lower()]
   if found_banned:
       print(f"  🎯 [专项清洗] 检测到禁用词 {found_banned}，触发定向替换...")
       fix_prompt = f"""The chapter below contains banned modern/translationese vocabulary that breaks
immersion in a xianxia/fantasy setting: {found_banned}

Your ONLY task: replace EVERY occurrence of these words (and their inflected forms like
-ed/-ing/-s) with genre-appropriate alternatives that fit a cultivation/fantasy world.
Examples: "calibrate"→"attune/tune", "parameters"→"limits/bounds", "protocol"→"rite/method",
"optimize"→"refine/hone", "algorithm"→"pattern/method", "testament"→"proof/mark",
"catalogued"→"recorded/noted", "metrics"→"measures".
Change NOTHING else — same plot, events, dialogue, length. Only swap the banned words.
Keep the Chapter title line exactly as-is. Output ONLY the full revised story text.

[CHAPTER]:
{polished}"""
       refixed = call_deepseek(fix_prompt, temperature=0.4, timeout=800, max_tokens=32000, presence_penalty=0, frequency_penalty=0)
       if refixed and len(refixed) > len(polished) * 0.7:
           refixed = clean_ai_endings(refixed)
           still_banned = [w for w in BANNED_WORDS if w in refixed.lower()]
           print(f"  ✅ [专项清洗] 禁用词 {found_banned} → 剩余 {still_banned if still_banned else '无'}。")
           polished = refixed
       else:
           print(f"  ⚠️  [专项清洗] 禁用词替换返回异常，保留原稿。")

   # ── 专项二次清洗：段首词单调（He/She/The/A 开头占比过高）──
   paras = [p.strip() for p in polished.split('\n\n') if p.strip()]
   firsts = [p.split()[0].lower().rstrip('.,!?;:') for p in paras if p.split()]
   boring = sum(1 for w in firsts if w in {'he','she','the','a','an'})
   if len(firsts) >= 8 and boring / len(firsts) > 0.45:
       print(f"  🎯 [专项清洗] 段首词单调 {boring}/{len(firsts)}，触发定向改写...")
       fix_prompt = f"""In the chapter below, {boring} of {len(firsts)} paragraphs begin with He/She/The/A/An.
This is a strong AI tell. Rewrite paragraph OPENINGS so that at most ~30% start with those words.
For the ones you change, start instead with: a sensory detail, a location, a sound/smell,
the result of an action, a short fragment, or a subordinate clause.
Change ONLY the opening words/clause of affected paragraphs. Keep all plot, events, dialogue,
and length identical. Keep the Chapter title line exactly as-is. Output ONLY the full story text.

[CHAPTER]:
{polished}"""
       refixed = call_deepseek(fix_prompt, temperature=0.5, timeout=800, max_tokens=32000, presence_penalty=0, frequency_penalty=0)
       if refixed and len(refixed) > len(polished) * 0.7:
           refixed = clean_ai_endings(refixed)
           p2 = [p.strip() for p in refixed.split('\n\n') if p.strip()]
           f2 = [p.split()[0].lower().rstrip('.,!?;:') for p in p2 if p.split()]
           b2 = sum(1 for w in f2 if w in {'he','she','the','a','an'})
           print(f"  ✅ [专项清洗] 段首词单调 {boring}/{len(firsts)} → {b2}/{len(f2)}。")
           polished = refixed
       else:
           print(f"  ⚠️  [专项清洗] 段首词改写返回异常，保留原稿。")

   # ── 代词定向修复：把指代主角的错误性别代词直接改对（避免 book2/book3 这类女性角色多的书反复整章重写）──
   if _mc_name:
       _first = _mc_name.split()[0]
       _wrong = r'\b(she|her|herself)\b' if _mc_gender == "male" else r'\b(he|him|himself|his)\b'
       _bad_sentences = [s for s in re.split(r'(?<=[.!?])\s+', polished)
                         if _first.lower() in s.lower() and re.search(_wrong, s, re.IGNORECASE)]
       if _bad_sentences:
           print(f"  🎯 [专项清洗] 检测到 {len(_bad_sentences)} 处指代主角的错误性别代词，触发定向修复...")
           correct = "he/him/his" if _mc_gender == "male" else "she/her"
           fix_prompt = f"""The chapter below has a critical error: the protagonist {_mc_name} is MALE/FEMALE as follows —
{_mc_name} is {_mc_gender}. Every pronoun referring to {_mc_name} MUST be {correct}.
Some sentences wrongly use the opposite-gender pronoun for {_mc_name}. Fix EVERY such pronoun so that all
references to {_mc_name} use {correct}. Do NOT change pronouns that correctly refer to OTHER characters.
Change ONLY pronouns. Keep all plot, dialogue, wording, and length identical. Keep the Chapter title line as-is.
Output ONLY the full corrected story text.

[CHAPTER]:
{polished}"""
           fixed = call_deepseek(fix_prompt, temperature=0.3, timeout=800, max_tokens=32000, presence_penalty=0, frequency_penalty=0)
           if fixed and len(fixed) > len(polished) * 0.7:
               fixed = clean_ai_endings(fixed)
               after_bad = [s for s in re.split(r'(?<=[.!?])\s+', fixed)
                            if _first.lower() in s.lower() and re.search(_wrong, s, re.IGNORECASE)]
               print(f"  ✅ [专项清洗] 主角代词错误 {len(_bad_sentences)} → {len(after_bad)} 处。")
               polished = fixed
           else:
               print(f"  ⚠️  [专项清洗] 代词修复返回异常，保留原稿。")

   # ── 句式总闸：送审前一次性清理 碎句/倒装/流水账（这三类是反复触发重写的元凶）──
   #   复用规则扫描定位问题，命中任一类就做一次定向清洗，避免主编一类一类地打回（"打地鼠"）。
   style_issues = rule_based_smell_check(polished)
   style_killers = [i for i in style_issues if any(k in i for k in
       ("CHOPPY FRAGMENTS", "INVERTED-SENTENCE", "BROKEN-INVERSION", "SEQUENCE NARRATION"))]
   if style_killers:
       print(f"  🎯 [句式总闸] 送审前检出 {len(style_killers)} 类句式问题，触发一次性清理...")
       issues_text = "\n".join(f"  - {i}" for i in style_killers)
       sweep_prompt = f"""You are a line editor. The chapter below has these specific sentence-structure problems
that will get it rejected:
{issues_text}

Fix ALL of them at once, following these rules:
1. FRAGMENTS: every sentence must have a subject and a main verb. Rejoin scraps like "Picked clean." into
   "The shelf was picked clean." Keep AT MOST 2 deliberate fragments in the whole chapter.
2. INVERTED/FRONTED sentences (starting with Into/Behind/Beside/From/Across/Toward/Through/Against/Out/etc.):
   rewrite into normal subject-verb-object order. "Behind him the ravine opened." → "The ravine opened behind him."
   Keep AT MOST 2 in the whole chapter.
3. VERB-FRONTED scraps ("Lunged." "Stopped." "Returned."): rewrite as "He lunged." etc. Keep AT MOST 1.
4. SEQUENCE markers ("then he", "after that", "finally,"): reduce to AT MOST 3; transition via cause-effect instead.

Change ONLY sentence structure. Keep ALL plot, events, dialogue, imagery, and length identical.
Keep the Chapter title line exactly as-is. Output ONLY the full revised story text, nothing else.

[CHAPTER]:
{polished}"""
       swept = call_deepseek(sweep_prompt, temperature=0.4, timeout=800, max_tokens=32000, presence_penalty=0, frequency_penalty=0)
       if swept and len(swept) > len(polished) * 0.7:
           swept = clean_ai_endings(swept)
           after = rule_based_smell_check(swept)
           after_killers = [i for i in after if any(k in i for k in
               ("CHOPPY FRAGMENTS", "INVERTED-SENTENCE", "BROKEN-INVERSION", "SEQUENCE NARRATION"))]
           print(f"  ✅ [句式总闸] 句式问题 {len(style_killers)} → {len(after_killers)} 类。")
           polished = swept
       else:
           print(f"  ⚠️  [句式总闸] 返回异常，保留原稿。")

   # ── 代词定向修复：检测到主角被写成错误性别代词，专门做一次"只改代词"的轻量清洗 ──
   #   后宫文/女性角色多的章节，主笔易把男主写成 she。比整章重写快得多、稳得多。
   if _mc_name:
       _first = _mc_name.split()[0]
       _wrong = r'\b(she|her|herself)\b' if _mc_gender == "male" else r'\b(he|him|himself)\b'
       _bad = 0
       for _s in re.split(r'(?<=[.!?])\s+', polished):
           if _first.lower() in _s.lower() and re.search(_wrong, _s, re.IGNORECASE):
               _bad += 1
       if _bad >= 1:
           print(f"  🎯 [代词修复] 检测到 {_bad} 处主角性别代词错误，触发定向修复...")
           _correct = "he/him/his" if _mc_gender == "male" else "she/her/hers"
           _wronglabel = "she/her/herself" if _mc_gender == "male" else "he/him/himself"
           pron_prompt = f"""The protagonist {_mc_name} is {_mc_gender.upper()}. In the chapter below, some
sentences wrongly use {_wronglabel} to refer to {_mc_name}. Fix EVERY pronoun that refers to {_mc_name} so it
is {_correct}. Do NOT change pronouns for other (genuinely female/male) characters. Change ONLY pronouns —
keep all plot, dialogue, wording, and length identical. Keep the Chapter title line exactly as-is.
Output ONLY the corrected full chapter text.

[CHAPTER]:
{polished}"""
           fixed_pron = call_deepseek(pron_prompt, temperature=0.2, timeout=800,
                                      max_tokens=32000, presence_penalty=0, frequency_penalty=0)
           if fixed_pron and len(fixed_pron) > len(polished) * 0.7:
               fixed_pron = clean_ai_endings(fixed_pron)
               _after = sum(1 for _s in re.split(r'(?<=[.!?])\s+', fixed_pron)
                            if _first.lower() in _s.lower() and re.search(_wrong, _s, re.IGNORECASE))
               print(f"  ✅ [代词修复] 主角性别代词错误 {_bad} → {_after}。")
               polished = fixed_pron
           else:
               print(f"  ⚠️  [代词修复] 返回异常，保留原稿。")

   return polished

# ─────────────────────────────────────────────────
# 步骤 1.5a：纯规则AI味扫描（零API消耗）
# ─────────────────────────────────────────────────

def rule_based_smell_check(text):
   """纯规则扫描，零API消耗，结果附加给主编AI提升判断准确性"""
   if not text:
       return []
   issues = []
   paragraphs = [p.strip() for p in text.split('\n\n') if p.strip()]

   # 1. 段首词单调检测
   first_words = []
   for p in paragraphs:
       words = p.split()
       if words:
           first_words.append(words[0].lower().rstrip('.,!?;:'))
   boring_starters = {'he', 'she', 'the', 'a', 'an'}
   boring_count = sum(1 for w in first_words if w in boring_starters)
   if len(first_words) >= 5 and boring_count / len(first_words) > 0.45:
       issues.append(f"FIRST-WORD MONOTONY: {boring_count}/{len(first_words)} paragraphs start with He/She/The/A — exceeds 45% threshold.")

   # 2. 禁用词检测
   found_banned = [w for w in BANNED_WORDS if w in text.lower()]
   if found_banned:
       issues.append(f"BANNED VOCABULARY DETECTED: {found_banned}")

   # 3. Staccato negation 检测
   not_pattern = re.findall(r'\bNot\s+\w[\w\s]{0,20}\.', text)
   if len(not_pattern) >= 3:
       issues.append(f"STACCATO NEGATION OVERUSE: {len(not_pattern)} 'Not X.' patterns (max 2 allowed).")

   # 3b. 重复的单词成段"高冷反应"检测（如 Interesting. 连用两次 = AI味）
   one_word_lines = [p.strip().rstrip('.') for p in paragraphs
                     if len(p.split()) == 1 and p.strip().rstrip('.!?').isalpha()]
   from collections import Counter as _Counter
   _wc = _Counter(w.lower() for w in one_word_lines)
   _repeated = [w for w, c in _wc.items() if c >= 2]
   if _repeated:
       issues.append(f"REPEATED ONE-WORD REACTION: {_repeated} used as a standalone line 2+ times (max 1 each; AI tell).")
   if len(one_word_lines) > 3:
       issues.append(f"TOO MANY ONE-WORD LINES: {len(one_word_lines)} standalone one-word paragraphs (max ~2-3).")

   # 3c. 无主语残句 & 倒装句滥用检测（动作章顽疾）
   import re as _re3
   # 把正文拆成句子
   _sentences = _re3.split(r'(?<=[.!?])\s+', text.replace('\n', ' '))
   _sentences = [s.strip() for s in _sentences if s.strip() and len(s.split()) >= 1]
   if len(_sentences) >= 20:
       # 无主语残句：很短(2-4词)、不以常见主语/对话开头、首词是动词过去式/现在分词的可能性高
       _subjectless = 0
       _pronouns = {'he','she','it','they','i','you','we','his','her','their','the','a','an','there','that','this'}
       for s in _sentences:
           w = s.split()
           if 1 <= len(w) <= 4 and not s.startswith(('"', '\u201c', '*')):
               first = w[0].lower().rstrip('.,!?;:')
               # 首词不是主语/冠词/指示词，且整句很短 → 疑似无主语残句
               if first not in _pronouns:
                   _subjectless += 1
       _frag_ratio = _subjectless / len(_sentences)
       if _subjectless >= 6 and _frag_ratio > 0.10:
           issues.append(f"CHOPPY FRAGMENTS: ~{_subjectless} subject-less/scrap sentences ({_frag_ratio*100:.0f}%) — rejoin into full S-V-O sentences (max ~1 per 150-200 words).")
       # 倒装/前置句：以介词短语或方位/方向词开头、且主语在动词后
       _inv_starts = ('into ','under ','behind ','backward ','forward ','across ','beneath ','toward ','through ','onto ','over ','beside ','against ','from the ','out ','up ','down ','past ','along ','beyond ','within ','atop ')
       _inv_samples = [s[:45] for s in _sentences if s.lower().startswith(_inv_starts)]
       _inversions = len(_inv_samples)
       if _inversions >= 3:
           _ieg = " / ".join(f'"{x}"' for x in _inv_samples[:3])
           issues.append(f"INVERTED-SENTENCE OVERUSE: {_inversions} fronted/inverted action sentences (e.g. {_ieg}) (max 2); rewrite most as natural subject-verb-object.")
       # ★ 破碎倒装/动词前置残句检测：如 "Lunged. The scarred disciple." / "Blinded, he..." /
       #   "Stoppered the vial." / "Settled. The guards had." —— 把动词或分词甩到句首造成的反人类语序。
       #   这是动作章最刺眼的 AI 腔，必须强检。包含单词动词残句（Lunged./Settled.）。
       _ved_frag = 0
       _ed_or_ing = _re3.compile(r'^[A-Z][a-z]+(?:ed|ing)\b')
       _frag_samples = []
       for s in _sentences:
           w = s.split()
           # 1-5词的极短句，以 -ed/-ing 动词开头（非对话、非常见主语开头）
           if 1 <= len(w) <= 5 and not s.startswith(('"', '\u201c', '*')):
               first = w[0].lower().rstrip('.,!?;:')
               if _ed_or_ing.match(s) and first not in {'he','she','it','they','i','you','we','everything','nothing','someone','something'}:
                   _ved_frag += 1
                   if len(_frag_samples) < 3:
                       _frag_samples.append(s[:40])
       if _ved_frag >= 2:
           _eg = " / ".join(f'"{x}"' for x in _frag_samples)
           issues.append(f"BROKEN-INVERSION FRAGMENTS: {_ved_frag} verb-fronted scrap sentences (e.g. {_eg}) (max 1); rewrite as normal 'He lunged at the man.' word order.")

   # 4. 机械动作链检测（连续4+个 He/She + 动词句）
   lines = text.split('\n')
   mech_streak = max_streak = 0
   _mech_start = ""
   _cur_start = ""
   for line in lines:
       if re.match(r'^(He|She)\s+\w+', line.strip()):
           if mech_streak == 0:
               _cur_start = line.strip()[:50]
           mech_streak += 1
           if mech_streak > max_streak:
               max_streak = mech_streak
               _mech_start = _cur_start
       else:
           mech_streak = 0
   if max_streak >= 4:
       issues.append(f"MECHANICAL ACTION CHAIN: {max_streak} consecutive 'He/She + verb' lines (chain starts near \"{_mech_start}\"); break it after 3 — combine actions, add a sensation or dialogue beat.")

   # 5. 事件列表模式检测（修正：带逗号的标记 \b 边界会失效，改用非捕获+显式标点）
   seq_markers = re.findall(r'\b(?:then he|then she|after that)\b|\b(?:next|first|second|finally),', text.lower())
   if len(seq_markers) >= 4:
       issues.append(f"SEQUENCE NARRATION: {len(seq_markers)} sequential markers ('then he/she', 'after that', 'finally,') — chapter reads like a plot summary; use at most 3, transition via cause-effect or sensory shifts instead.")

   return issues

def rule_based_smell_check_with_threads(text, threads, chapter_num, status=None):
   """扩展版规则扫描：在基础AI味检测基础上，加入过期高优先级线程强制检测。
   过期10章以上的高优先级线程 → 产生 OVERDUE_THREAD_FORCE 类型问题，主编会强制不通过。"""
   issues = rule_based_smell_check(text)

   # 过期10章以上的高优先级线程检测
   active = threads.get("active_threads", [])
   severely_overdue = []
   for t in active:
       if t.get("urgency") == "high":
           overdue_by = chapter_num - t.get("must_resolve_by_chapter", chapter_num)
           if overdue_by >= 10:
               severely_overdue.append(f"[{t['id']}] '{t['description']}' overdue by {overdue_by} chapters")

   if severely_overdue:
       issues.append(
           f"OVERDUE_THREAD_FORCE: The following HIGH URGENCY threads are 10+ chapters overdue and MUST be "
           f"explicitly advanced or resolved in THIS chapter: {'; '.join(severely_overdue)}. "
           f"If this chapter does not address them, it FAILS regardless of other scores."
       )

   # ── 调性漂移检测：系统流书目缺失系统面板 ──
   cfg = get_book_config()
   if cfg.get("requires_system_panel"):
       if "[SYSTEM" not in text and "[ SYSTEM" not in text:
           issues.append(
               "TONE_DRIFT_NO_SYSTEM: This is a SYSTEM-flow novel but the chapter has NO [SYSTEM:] panel. "
               "The snarky system panel must appear. Tone is drifting away from the book's core identity."
           )

   # ── 主角代词一致性检测：防止主笔把男主写成 she/her（或反之）──
   #   三本主角均为男性；从配置读 protagonist_gender，默认 male。
   #   启发式：含主角名的句子里若出现错误性别代词，高度可疑 → 报错。
   gender = cfg.get("protagonist_gender", "male")
   _st = status or {}
   mc_name_full = _st.get("mc_name") or cfg.get("mc_name") or ""
   mc_name = mc_name_full.split()[0] if mc_name_full else ""
   if mc_name:
       import re as _rp
       wrong_pat = r'\b(she|her|herself)\b' if gender == "male" else r'\b(he|him|himself)\b'
       wrong_label = "female pronouns (she/her)" if gender == "male" else "male pronouns (he/him)"
       sex_label = "male" if gender == "male" else "female"
       suspicious = 0
       for s in _rp.split(r'(?<=[.!?])\s+', text):
           if mc_name.lower() in s.lower() and _rp.search(wrong_pat, s, _rp.IGNORECASE):
               suspicious += 1
       if suspicious >= 1:
           issues.append(
               f"PRONOUN-GENDER ERROR: The {sex_label} protagonist ({mc_name}) is referred to with {wrong_label} "
               f"in {suspicious} sentence(s) that mention him/her by name. Fix every wrong pronoun — this is a "
               f"glaring continuity error readers spot instantly."
           )

   return issues

# ─────────────────────────────────────────────────
# 步骤 1.5b：主编审稿
# ─────────────────────────────────────────────────

def chief_editor_review(story_text, lore, status, quests, threads, chapter_num):
   if not story_text:
       return False, "故事内容为空", 0, ["EMPTY"]
   print(f"📋 [主编审稿] 正在审核第 {chapter_num} 章质量...")

   # 纯规则预扫描（零token消耗），含过期线程强制检测
   rule_issues = rule_based_smell_check_with_threads(story_text, threads, chapter_num, status)
   if rule_issues:
       print(f"  🔍 [规则扫描] 发现 {len(rule_issues)} 个问题: {rule_issues}")
       rule_issues_text = "\n[PRE-SCAN RULE VIOLATIONS — CONFIRMED, NOT AI JUDGMENT]:\n" + "\n".join(f"- {i}" for i in rule_issues) + "\n"
   else:
       print(f"  ✅ [规则扫描] 无明显AI味。")
       rule_issues_text = ""

   # 截断发给主编的正文（主编只需要判断质量，不需要全文；节省token加快审稿速度）
   story_for_editor = story_text if len(story_text) <= 6000 else (
       story_text[:3000] + "\n\n[... MIDDLE SECTION OMITTED FOR REVIEW SPEED ...]\n\n" + story_text[-2500:]
   )

   review_prompt = f"""
You are the Chief Editor of a professional webnovel publishing house. Be strict but fair.

[WORLD CONSTITUTION (S-tier + recent 20ch)]: {_get_constitution(lore, chapter_num)}
[Current MC Status]: {json.dumps(status, ensure_ascii=False)}
[Villain Status]: {_get_villain_status_text(quests)}
[Active Subplots]: {_get_active_threads_text(threads)}
{rule_issues_text}[Chapter {chapter_num} Draft]: {story_for_editor}

=== REVIEW CHECKLIST ===
1. POWER CONSISTENCY: MC's actions match current realm ({status.get('realm') or status.get('rank','unknown')})?
2. VILLAIN RULE: Any villain with arcs left permanently killed/crippled?
3. MC PERSONALITY: Fear/panic/trembling/desperation? Or machine with zero personality? Both fail.
4. TENSION: Genuine stakes? Did anything feel pre-ordained or too easy?
5. SYSTEM UI (if applicable): More than 4 system notifications? DP numbers mid-combat?
5b. LITRPG ROSTER LIMITS (ONLY for system/LitRPG novels with a minion legion or similar roster): Does the MC
   command MORE persistent creations (undead minions, summoned servants) than his stated capacity allows
   (e.g. Legion Capacity)? Does any creation that was destroyed/shattered in a PREVIOUS chapter reappear and
   act? Either is a HARD continuity violation — flag it. (Skip this entirely for non-system novels.)
5c. SAFETY-RULE COMPLIANCE (ONLY for novels whose lore contains a heroine-consent / anti-coercion safety rule,
   e.g. the villain-harem book): Did any heroine join the MC through coercion, theft from a loving partner, or
   anything non-consensual, instead of her own free informed choice after seeing an abuser's true nature? If the
   chapter violates the lore's stated safety rule, this is a HARD failure — flag it. (Skip for other novels.)
5d. SCHEME-OVER-FORCE (ONLY for the intellectual villain-protagonist book): Did the MC win PURELY by raw power
   with no cleverness, when his whole identity is out-thinking rivals three moves ahead? If a confrontation was
   resolved by brute force alone with zero scheming/anticipation, note it (do not hard-fail, but deduct).
6. ECONOMY: Unreasonable resource gains? Windfalls that break the economy?
7. PACING: Did the chapter cover a complete satisfying plot point?
8. CLIFFHANGER: Does the chapter end on a genuine high-stakes moment?
9. CHARACTER MOMENT: At least one scene showing MC personality beyond combat/action?
9b. CHARACTER CONSISTENCY: Did any returning character act OUT OF CHARACTER versus their established voice/
   personality in [Key Characters] (e.g. a cold schemer suddenly reckless, a terse figure suddenly chatty,
   a villain suddenly warm) with no story reason? Flag any unexplained personality/voice drift.
10. CONTINUITY: Anything contradict ABSOLUTE FACTS or recent context?
   EXCEPTION — NUMERIC RESOURCES & STORY STATS: Do NOT fail or deduct for arithmetic on any countable
   total (spirit stones, pills, lifespan, points) OR any story stat (mutation %, integration %, affinity,
   corruption, progress). These values are managed by the engine in code, not the prose. Only flag a HARD
   contradiction (dead character alive, consumed item back, realm regressed) — never a numeric total/stat mismatch.
10b. ★ GOLDEN-FINGER OUTPUT SOURCING (critical — prevents resource snowballing): The MC's golden-finger
   (vial/system/treasure) produces things from a SOURCE MATERIAL (e.g. the vial refines blood/herbs into
   essence; a system reaps a soul from a fresh kill). Check the recent context: did the MC this chapter
   re-use a source material that was ALREADY consumed in a previous chapter, or conjure a golden-finger
   output with no fresh source? If the prose treats an already-spent material (e.g. "the blood he already
   refined into essence last chapter") as still available to refine AGAIN, that is a HARD continuity
   violation — flag it and require a rewrite. Each golden-finger output must come from a NEW, traceable
   source obtained THIS chapter; a one-time material cannot be used twice.
11. FORBIDDEN OUTPUT: Any chapter teasers, end labels, or author notes?
12. REALM PACING (INFORMATIONAL — DO NOT FAIL FOR THIS): If MC stuck at same realm
   15+ chapters with no breakthrough imminent, note it in "pacing_handoff" so the
   Director can schedule a breakthrough NEXT chapter. This is a HISTORICAL/scheduling
   issue that CANNOT be fixed by rewriting THIS chapter — never fail or deduct for it.
13. AI SMELL DETECTION (three-tier — NOT an instant fail at low count):
   a) STACCATO NEGATION: "Not X. Not Y. [Statement]" pattern occurrences.
      1-2: note only. 3-4: deduct 10pts. 5+: FAIL this check.
   b) MODERN VOCABULARY in genre setting: cognitive dissonance, variables,
      catalogued, parameters, algorithm, optimize, metrics, calibrate, protocol.
      Each word = 1 tell toward threshold.
   c) AI PATCH: Acknowledging impossibility then ignoring it. = 2 tells each.
   d) MECHANICAL ACTION CHAINS: 4+ "[He/She]+[verb]" in sequence = 1 tell.
   e) AUTHOR NOTE HALLUCINATION: Implies reader community on early chapter. = 3 tells.
   TIER 1 (1-2 tells): note in feedback only. DO NOT fail.
   TIER 2 (3-4 tells): deduct 10 points. DO NOT fail.
   TIER 3 (5+ tells): check fails.

CRITICAL DISTINCTION — what justifies a REWRITE vs what does not:
  REWRITE-WORTHY (this chapter is broken, rewriting fixes it):
    power inconsistency, villain rule violation, broken MC personality, economy break,
    continuity contradiction, forbidden output, TIER-3 AI smell.
  NOT REWRITE-WORTHY (historical/scheduling — rewriting THIS chapter cannot fix it):
    realm pacing (stuck too long), overdue threads, "arc has been slow lately".
    For these, populate "pacing_handoff" / "thread_handoff" instead of failing.

Return EXACTLY this JSON:
{{
   "passed": true or false,
   "score": 0-100,
   "failed_checks": ["check names that failed"],
   "feedback": "If failed: specific actionable problems with exact quotes to fix. If passed: empty string.",
   "pacing_handoff": "If realm pacing is lagging, one instruction for the Director to schedule next chapter (else empty)",
   "thread_handoff": "If a thread is overdue, one instruction for the Director to resolve it next chapter (else empty)"
}}

PASSING THRESHOLD: Score 70+ AND no critical failures (checks 1,2,3,6,10,11).
Check 12 (realm pacing) NEVER fails — it only produces a handoff.
Check 13 fails only at TIER 3 (5+ tells).
"""
   result_text = call_deepseek(review_prompt, temperature=0.1, timeout=650)
   review_data = extract_json(result_text)

   if not review_data:
       print("  ⚠️  主编AI返回格式异常，默认放行。")
       return True, "", 75, []

   passed   = review_data.get("passed", True)
   score    = review_data.get("score", 0)
   failed   = review_data.get("failed_checks", [])
   feedback = review_data.get("feedback", "")
   pacing_handoff = review_data.get("pacing_handoff", "").strip()
   thread_handoff = review_data.get("thread_handoff", "").strip()

   # ★ 硬规则：规则扫描检测到禁用词 → 强制评分上限82，不允许高分通过
   if rule_issues:
       banned_issues = [i for i in rule_issues if "BANNED VOCABULARY" in i]
       if banned_issues and score > 82:
           print(f"  ⚠️  [硬规则] 禁用词存在，评分从 {score} 强制压至 82。")
           score = 82
           if passed and score < 83:
               passed = False
               failed = failed + ["BANNED_VOCABULARY_HARD_CAP"]
               feedback = (feedback + "\n" if feedback else "") + f"Rule scan confirmed banned vocabulary: {banned_issues}. Must be removed before passing."

   # ★ 硬规则：倒装句/破碎倒装/碎句滥用 → 强制不通过（这是 RR 读者一眼识破的 AI 腔，零容忍）
   #   这些是确定性的句式病，不依赖 AI 主编主观判断；规则一旦命中，必须重写。
   if rule_issues:
       _style_killers = [i for i in rule_issues if any(k in i for k in (
           "INVERTED-SENTENCE OVERUSE",
           "BROKEN-INVERSION FRAGMENTS",
           "CHOPPY FRAGMENTS",
           "MECHANICAL ACTION CHAIN",
       ))]
       if _style_killers:
           if score > 78:
               print(f"  ⚠️  [硬规则] 句式 AI 腔确认存在，评分从 {score} 强制压至 78。")
               score = 78
           if passed:
               passed = False
               failed = failed + ["STYLE_AI_TELL_HARD_FAIL"]
               _kill_text = "; ".join(_style_killers)
               feedback = (feedback + "\n" if feedback else "") + (
                   f"Rule scan confirmed sentence-structure AI tells that MUST be fixed before passing: {_kill_text}. "
                   "Rewrite the flagged sentences into ordinary subject-verb-object order. "
                   "Keep at most one or two deliberate inversions in the entire chapter."
               )

   # ★ 过期高优先级线程：不再触发重写（历史问题，本章改不了根因），转为导演待办
   if rule_issues:
       overdue_issues = [i for i in rule_issues if "OVERDUE_THREAD_FORCE" in i]
       if overdue_issues:
           if not thread_handoff:
               thread_handoff = overdue_issues[0]
           print(f"  📋 [转导演] 过期线程转下章处理，不触发重写。")

   # 收集本章的导演待办（节奏/线程），写入待办文件供下一章生成时强制注入
   handoffs = []
   if pacing_handoff: handoffs.append(f"PACING: {pacing_handoff}")
   if thread_handoff: handoffs.append(f"THREAD: {thread_handoff}")
   if handoffs:
       safe_write_text(FILES["director_todo"], "\n".join(handoffs))

   if passed:
       print(f"  ✅ 主编审稿通过！评分: {score}/100")
   else:
       print(f"  ❌ 主编审稿不通过！评分: {score}/100")
       print(f"  🔴 失败项目: {failed}")
       if feedback: print(f"  📝 问题反馈: {feedback[:200]}...")

   return passed, feedback, score, failed

# ─────────────────────────────────────────────────
# 步骤 2：HTML排版
# ─────────────────────────────────────────────────

def format_html_content(content, chapter_num):
   lines = content.strip().split('\n')
   if lines and "Chapter" in lines[0]:
       lines = lines[1:]
   html_lines = []
   for line in lines:
       clean_line = line.strip()
       if clean_line:
           html_lines.append(f"<p>{clean_line}</p>")
   return '\n'.join(html_lines)

def clean_title(title, chapter_num=None):
   title = unicodedata.normalize('NFKC', title)
   # ★ 必须先还原 HTML 实体，再删 # 号。否则 "&#039;" 的 # 会被先删掉，
   #   变成认不出的 "&039;"，导致撇号乱码修不掉。
   title = html.unescape(title)
   title = title.replace("&#039;", "'").replace("&#39;", "'").replace("&apos;", "'")
   title = title.replace("&quot;", '"').replace("&amp;", "&")
   # 还原之后再清理 markdown 符号和不可见字符
   title = title.replace('#','').replace('*','').replace('_','').replace('`','')
   title = title.replace('\u200b','').replace('\ufeff','').replace('\u00a0',' ')
   title = ''.join(c for c in title if unicodedata.category(c) not in ('Cc','Cf'))
   # ★ 关键修复：把 ASCII 直撇号 ' 换成 Unicode 弯撇号 '(U+2019)。
   #   xmlrpc.client 发送时会把 ASCII 的 ' 转义成 &#039; 而 Typecho 不解码，导致标题显示乱码。
   #   弯撇号不会被 XML 转义，显示正常且更美观。同理处理直双引号。
   title = title.replace("'", "\u2019")
   title = title.replace('"', '\u201d')
   title = title.strip()

   # 空标题/占位符兜底：防止 "[CHAPTER]:"、空串、纯标点这种坏标题发出去。
   _low = title.lower().replace(' ', '')
   _stripped = re.sub(r'[^0-9A-Za-z]', '', title)
   is_bad = (len(_stripped) == 0) or ('[chapter' in _low) or (_low in ('chapter', 'chapter:', ':')) or (title.strip(':　[] ') == '')
   if is_bad:
       title = f"Chapter {chapter_num}" if chapter_num is not None else "Chapter"
   return title
  

def deduplicate_chapter(story_text):
   """★ 整章重复检测与去重（修复"第五章整章被复制两遍"的致命 bug）。

   DeepSeek 在长输出时偶发"重启续写"——把已经写完的正文从头又输出一遍。
   表现为：同一段正文（甚至连同章节标题）在文中出现两次。若直接发布，
   读者第一眼就判定为劣质 AI 农场。本函数检测并切除重复的后半部分，只保留第一份完整版。

   策略（多重保险）：
     1. 整体对折检测：若全文前半与后半高度相似（>85% 段落重合），判定为完整复制，截取前半。
     2. 章节标题二次出现检测：若 "Chapter N" 标题样式在正文中段再次出现，从该处截断。
     3. 长段落指纹检测：若某个 >120 字符的段落在文中完整出现 2 次，从第二次出现处截断。
   """
   if not story_text or len(story_text) < 800:
       return story_text

   original = story_text
   text = story_text.strip()

   # ── 策略2（最稳）：章节标题在正文中段再次出现 → 从该处截断 ──
   # 匹配 "Chapter 5: The Black Market Manual" 这类标题在非开头位置重复出现。
   # 注意：模型重启时标题常黏在上一句句尾（如 "...in earnest.Chapter 5: ..."），
   # 所以不要求标题独占一行，用 (?:^|[.!?\s]) 作为前界即可。
   _title_pat = re.compile(r'(?:^|[.!?\s])(Chapter\s+\d+\s*[:：]\s*[A-Z].{2,80})', re.MULTILINE)
   _mid_title_hits = []
   for m in _title_pat.finditer(text):
       pos = m.start(1)
       if pos > len(text) * 0.15:   # 只看正文 15% 之后的标题重复（开头标题是正常的）
           _mid_title_hits.append(pos)
   if _mid_title_hits:
       cut = _mid_title_hits[0]
       trimmed = text[:cut].strip()
       if len(trimmed) >= 600:  # 截断后仍有足够正文才采纳
           print(f"  ✂️  [去重] 检测到章节标题在正文中段重复出现，已从第 {cut} 字符处截断（{len(text)}→{len(trimmed)} 字符）。")
           return trimmed

   # ── 策略3：长段落指纹——同一长段落完整出现两次 → 从第二次处截断 ──
   paras = [p.strip() for p in re.split(r'\n\s*\n', text) if len(p.strip()) >= 120]
   seen = {}
   for p in paras:
       fp = p[:200]  # 用前200字符做指纹
       if fp in seen:
           # 找到重复长段落，定位它在全文第二次出现的位置
           second_pos = text.find(p, text.find(p) + len(p) - 50)
           if second_pos > len(text) * 0.30:
               trimmed = text[:second_pos].strip()
               if len(trimmed) >= 600:
                   print(f"  ✂️  [去重] 检测到长段落完整重复，已从第 {second_pos} 字符处截断（{len(text)}→{len(trimmed)} 字符）。")
                   return trimmed
       else:
           seen[fp] = True

   # ── 策略1：整体对折相似度——前半 vs 后半段落集合高度重合 → 判定完整复制 ──
   all_paras = [p.strip() for p in re.split(r'\n\s*\n', text) if len(p.strip()) >= 60]
   n = len(all_paras)
   if n >= 8:
       half = n // 2
       first_set = set(p[:150] for p in all_paras[:half])
       second_set = set(p[:150] for p in all_paras[half:])
       if first_set and second_set:
           overlap = len(first_set & second_set) / min(len(first_set), len(second_set))
           if overlap > 0.85:
               # 后半基本是前半的复制，保留前半
               rebuilt = "\n\n".join(all_paras[:half]).strip()
               if len(rebuilt) >= 600:
                   print(f"  ✂️  [去重] 检测到全文对折重复（重合度 {overlap*100:.0f}%），已保留前半（{len(text)}→{len(rebuilt)} 字符）。")
                   return rebuilt

   return original


def inject_author_voice(story_text, chapter_num):
   # ★ 章末作者寄语已关闭。原因：池子里只有固定几句，每隔几章重复同一句，
   #   细心读者看到重复会判定为机器生成——反而比没有寄语更像 AI。真人作者每次寄语都不同。
   #   如需重新启用：把下面的 ENABLE_AUTHOR_NOTE 改为 True 并补充足够多样的句子。
   ENABLE_AUTHOR_NOTE = False
   if not ENABLE_AUTHOR_NOTE:
       return story_text

   import random
   cfg = get_book_config()
   notes = cfg.get("author_notes", [
       "\n\n---\n*More tomorrow.*",
       "\n\n---\n*Thanks for reading.*",
   ])
   # ★ 中文防火墙：英文站点的正文绝不允许出现中日韩字符的作者note。
   _safe_notes = [n for n in notes if not re.search(r'[\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7af]', n)]
   if not _safe_notes:
       _safe_notes = ["\n\n---\n*More tomorrow. The road is long.*"]
   if random.random() < 0.15:
       return story_text + random.choice(_safe_notes)
   return story_text

# ─────────────────────────────────────────────────
# 步骤 3：发布
# ─────────────────────────────────────────────────

def publish_to_website(title, html_content, chapter_num):
   title  = clean_title(title)
   print(f"🌐 [发布] 正在推送: {title} ...")
   server = xmlrpc.client.ServerProxy(TYPECHO_RPC_URL)
   # ★ slug 带书名前缀，确保跨书唯一，永不撞车。
   #   例如 book2 第28章 → slug "book2-28" → 网址 book2-28.html
   #   旧逻辑只用 str(chapter_num)，多本书同章号会让 Typecho 自动加乱后缀(-1/-2/-3)，导致冲突。
   unique_slug = f"{NOVEL_ID}-{chapter_num}" if SLUG_PREFIX_BY_BOOK else str(chapter_num)
   post_data = {"title": title, "description": html_content, "categories": [CATEGORY_NAME], "wp_slug": unique_slug}
   try:
       server.metaWeblog.newPost(1, TYPECHO_USER, TYPECHO_PASS, post_data, True)
       print(f"  ✅ 章节发布成功！(slug: {unique_slug})")
       return True
   except Exception as e:
       print(f"  ❌ 网站发布失败: {e}")
       return False
# ─────────────────────────────────────────────────
# 步骤 4：审计
# ─────────────────────────────────────────────────

def _parse_stat_number(raw):
    """把状态数值解析成 float。支持 9.2、"9.2"、"9.2%"、None 等。无法解析则返回 0.0。"""
    if raw is None:
        return 0.0
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, str):
        import re as _re
        m = _re.search(r'-?\d+(?:\.\d+)?', raw)
        if m:
            try:
                return float(m.group())
            except ValueError:
                return 0.0
    return 0.0


def audit_and_update_db(chapter_text, status, characters, threads, chap_index, chapter_num, lore, quests):
   print("🕵️  [审计] 正在校验物理属性与故事连贯性...")
   audit_prompt = f"""
Read the [New Chapter Text]. Extract ALL state changes.

IMPORTANT — NUMERIC RESOURCES / COUNTERS (currency, pills, lifespan, contribution points, etc.):
Do NOT report new totals. For ANY countable resource that changed this chapter, report ONLY the
NET CHANGE in the "resource_changes" object, using the SAME key names shown in the status "resources" block.
  Examples:
    spent 50,000 spirit stones        → "resource_changes": {{"spirit_stones": -50000}}
    earned 30,000 spirit stones + 2 pills → "resource_changes": {{"spirit_stones": 30000, "pills": 2}}
    lost 10 years of lifespan          → "resource_changes": {{"lifespan_years": -10}}
    nothing changed                    → "resource_changes": {{}}
The engine computes every real total by code. NEVER compute, add, subtract, or guess any total yourself.
Use the exact key names already present in the status "resources" object; do not invent new ones unless
the chapter genuinely introduces a brand-new countable resource.

IMPORTANT — STORY STAT VALUES (mutation %, integration %, affinity, corruption, progress bars, etc.):
These are numeric story-stats that only go up or down gradually (e.g. kaelen_mutation, somatic_integration).
Do NOT report new totals. Report ONLY the NET CHANGE this chapter in the "stat_changes" object, using the
SAME key names shown in the status (top-level or in a "stats" block). Decimals/percentages are fine.
  Examples:
    mutation rose from 9.2% to 9.8%   → "stat_changes": {{"kaelen_mutation": 0.6}}
    integration +1.5, affinity +1     → "stat_changes": {{"somatic_integration": 1.5, "affinity": 1}}
    nothing changed                    → "stat_changes": {{}}
The engine computes the real stat totals by code. NEVER write or guess the new total yourself.

GOLDEN-FINGER OUTPUT TRACKING: In "goldfinger_output_state", write ONE short sentence describing the current
state of the MC's golden-finger (vial/system/treasure) AT THE END of this chapter: what it currently holds or
has produced, and whether any output was consumed. Examples:
  "Vial is empty; the one drop of blood essence was spent cutting the enforcer and is gone."
  "Vial currently refining a Blood-Clotting Mushroom paste; no essence in reserve."
  "System holds 2 reaped souls (rat, goblin); legion has 1 active Bone Spider."
This is so the NEXT chapter knows what the golden-finger actually still has, preventing reuse of spent material.

GOLDEN-FINGER PERSISTENT ASSETS (for systems that build a roster — undead minions, reaped souls, bound spirits,
read fate-lines, etc.): If this chapter the MC CREATED or GAINED a persistent golden-finger asset (a forged
undead, a reaped soul kept in reserve, a bound servant), list each in "goldfinger_assets_added" (short names,
e.g. ["Bone Spider", "Goblin soul"]). If a persistent asset was DESTROYED, consumed, lost, or used up this
chapter (a minion shattered, a soul spent in a stitch, a one-use fate-read expended), list each in
"goldfinger_assets_removed" (e.g. ["Bone Spider"]). This keeps the roster accurate so a destroyed minion or a
spent soul cannot silently reappear in a later chapter. Leave both as [] if nothing persistent changed.

[Current Status]: {json.dumps(status, ensure_ascii=False)}
[Current Characters]: {json.dumps(characters, ensure_ascii=False)}
[Active Threads]: {json.dumps(threads.get('active_threads',[]), ensure_ascii=False)}
[ABSOLUTE FACTS]: {_get_absolute_facts(lore)}
[New Chapter Text]: {chapter_text}

Return EXACTLY this JSON:
{{
   "realm_changed": false, "new_realm": "",
   "location_changed": false, "new_location": "",
   "new_items_acquired": [], "items_consumed": [], "destiny_points_change": 0, "resource_changes": {{}}, "stat_changes": {{}},
   "character_updates": [{{"name":"","status":"","cultivation":"","relationship":"","new_key_event":""}}],
   "villain_updates": [{{"name":"","outcome":"wounded/escaped/repelled/defeated_permanently","new_status":""}}],
   "thread_updates": [{{"id":"","action":"progressed/resolved","new_description":"","resolution":""}}],
   "new_threads": [{{"description":"","urgency":"low/medium/high","must_resolve_by_chapter":0}}],
   "new_absolute_fact": "",
   "goldfinger_output_state": "",
   "goldfinger_assets_added": [],
   "goldfinger_assets_removed": [],
   "chapter_index_summary": "",
   "contradiction_detected": false,
   "contradiction_detail": ""
}}
"""
   audit_data = extract_json(call_deepseek(audit_prompt, temperature=0.1, timeout=500))
   if not audit_data:
       print("  ⚠️  审计AI返回格式异常，跳过。"); return False, False

   if audit_data.get("contradiction_detected"):
       detail = audit_data.get("contradiction_detail", "")
       print(f"  🚨 审计发现叙事矛盾: {detail}")
       # ★ 自动修复轻微矛盾（如 inventory 遗留、状态字段过期）
       # 重大矛盾（故事情节层面）仍记录日志，不强行覆盖
       minor_keywords = ["inventory", "item", "pill", "status", "rank", "realm", "location"]
       is_minor = any(kw in detail.lower() for kw in minor_keywords)
       if is_minor:
           print(f"  🔧 [自动修复] 检测为轻微数据矛盾，尝试自动修正...")
           fix_prompt = f"""A minor data contradiction was found after writing chapter {chapter_num}.
[Contradiction]: {detail}
[Current Status]: {json.dumps(status, ensure_ascii=False)}
[ABSOLUTE FACTS]: {_get_absolute_facts(lore)}

Provide the corrected status fields only. Return EXACTLY:
{{"field_to_fix": "field_name", "correct_value": "correct_value"}}
Only fix what the contradiction describes. Do not change other fields."""
           fix = extract_json(call_deepseek(fix_prompt, temperature=0.1, timeout=60))
           if fix and fix.get("field_to_fix") and fix.get("correct_value") is not None:
               field = fix["field_to_fix"]
               val   = fix["correct_value"]
               if field == "inventory" and isinstance(val, list):
                   status["inventory"] = val
               elif field in status:
                   status[field] = val
               safe_write_json(FILES["status"], status)
               print(f"  ✅ [自动修复] {field} 已修正为: {str(val)[:60]}")
           # 轻微矛盾继续执行，不中断流程
       else:
           safe_append_text(os.path.join(BASE_DIR, "contradiction_log.txt"),
               f"Ch{chapter_num}: {detail}\n")
           return False, True

   if audit_data.get("realm_changed") and audit_data.get("new_realm"):
       for k in ["realm","rank","kaelen_rank","eli_tier","kane_rank"]:
           if k in status:
               status[k] = audit_data["new_realm"]; break
       else:
           status["realm"] = audit_data["new_realm"]
   if audit_data.get("location_changed") and audit_data.get("new_location"):
       status["location"] = audit_data["new_location"]
   if audit_data.get("new_items_acquired"):
       status.setdefault("inventory", []).extend(audit_data["new_items_acquired"])

   # ★ 审计AI明确上报的消耗道具 → 直接从 inventory 删除（比关键词扫描更精确）
   items_consumed = audit_data.get("items_consumed", [])
   if items_consumed:
       inventory = status.get("inventory", [])
       removed = []
       for consumed in items_consumed:
           consumed_lower = consumed.lower().strip()
           to_remove = [item for item in inventory if consumed_lower in item.lower() or item.lower() in consumed_lower]
           for item in to_remove:
               inventory.remove(item)
               removed.append(item)
       if removed:
           status["inventory"] = inventory
           print(f"  🧹 [审计清理] 消耗道具已从 inventory 删除: {removed}")
   if audit_data.get("destiny_points_change"):
       status["destiny_points"] = status.get("destiny_points", 0) + audit_data["destiny_points_change"]

   # ★ 通用数值资源代码记账：由 Python 精确加减，绝不让 AI 自己算总数。
   #   AI 只上报每种资源的本章净变化 resource_changes={"key": delta}，引擎逐项精确计算。
   #   适用于灵石、丹药、寿命、贡献点等任何可计数资源——新书无需改代码，加新 key 即可。
   resource_changes = audit_data.get("resource_changes", {})
   # 向后兼容：若旧字段 spirit_stones_change 仍被返回，并入处理
   legacy_ss = audit_data.get("spirit_stones_change", 0)
   if legacy_ss:
       resource_changes = dict(resource_changes)
       resource_changes["spirit_stones"] = resource_changes.get("spirit_stones", 0) + legacy_ss

   if isinstance(resource_changes, dict) and resource_changes:
       resources = status.setdefault("resources", {})
       for key, delta in resource_changes.items():
           try:
               delta = int(delta)
           except (ValueError, TypeError):
               continue
           if delta == 0:
               continue
           # 兼容历史：若旧数据把资源直接放在 status 顶层（如 status["spirit_stones"]），优先沿用该处
           if key in status and key not in resources and isinstance(status.get(key), (int, float)):
               old_val = int(status.get(key, 0))
               new_val = max(0, old_val + delta)
               status[key] = new_val
           else:
               try:
                   old_val = int(resources.get(key, 0))
               except (ValueError, TypeError):
                   old_val = 0
               new_val = max(0, old_val + delta)   # 资源不会变成负数
               resources[key] = new_val
           sign = "+" if delta >= 0 else ""
           print(f"  💰 [资源记账] {key}: {old_val} {sign}{delta} = {new_val}（由代码精确计算）")

   # ★ 金手指产出物状态追踪：把审计提取的"金手指当前持有/消耗状态"写入 status，
   #   下一章会注入给主笔和审计，防止重复利用已消耗的原料/产出物（资源凭空增加的滚雪球隐患）。
   gf_state = audit_data.get("goldfinger_output_state", "").strip()
   if gf_state:
       status["goldfinger_output_state"] = gf_state
       print(f"  🔮 [金手指追踪] 当前状态已记录: {gf_state[:80]}")

   # ★ 金手指造物清单维护（通用，覆盖各书不同机制）：精确增删持久造物，
   #   防止"被摧毁的undead/已消耗的灵魂/用过的一次性命格"在后续章节凭空复活。
   gf_added = audit_data.get("goldfinger_assets_added", []) or []
   gf_removed = audit_data.get("goldfinger_assets_removed", []) or []
   if gf_added or gf_removed:
       roster = status.setdefault("goldfinger_assets", [])
       for a in gf_added:
           a = str(a).strip()
           if a and a not in roster:
               roster.append(a)
       for r in gf_removed:
           r = str(r).strip()
           # 移除一个匹配项（按名字，宽松匹配，避免大小写/单复数误差）
           for existing in list(roster):
               if r.lower() in existing.lower() or existing.lower() in r.lower():
                   roster.remove(existing)
                   break
       status["goldfinger_assets"] = roster
       if gf_added:
           print(f"  ⚙️  [金手指造物] 新增: {gf_added} → 当前清单: {roster}")
       if gf_removed:
           print(f"  ⚙️  [金手指造物] 移除(损毁/消耗): {gf_removed} → 当前清单: {roster}")

   # ★ 状态数值代码记账：突变度/整合度/好感度/进度等剧情数值，同样由 Python 精确累加。
   #   AI 只上报本章净变化 stat_changes={"key": delta}（可带小数/百分比），引擎逐项精确计算。
   #   适用于 kaelen_mutation、somatic_integration、affinity、corruption 等单调变化的状态数值。
   #   新书无需改代码——AI 报哪个 key 就记哪个，并自动维护在 status["stats"] 或顶层同名字段。
   stat_changes = audit_data.get("stat_changes", {})
   if isinstance(stat_changes, dict) and stat_changes:
       stats = status.setdefault("stats", {})
       for key, delta in stat_changes.items():
           try:
               delta = float(delta)
           except (ValueError, TypeError):
               continue
           if delta == 0:
               continue
           # 解析旧值：优先顶层同名字段（可能是 "9.2%" 这类带符号字符串），否则用 stats 字典
           raw_old = status.get(key) if (key in status and key not in stats) else stats.get(key, 0)
           in_top = key in status and key not in stats
           old_num = _parse_stat_number(raw_old)
           new_num = old_num + delta
           if new_num < 0:
               new_num = 0.0   # 状态数值不会变成负数
           # 整数则去掉小数尾巴，更干净
           new_store = int(new_num) if abs(new_num - round(new_num)) < 1e-9 else round(new_num, 2)
           # 保留原显示格式：旧值带 % 就继续带 %
           if isinstance(raw_old, str) and "%" in raw_old:
               new_store = f"{new_store}%"
           if in_top:
               status[key] = new_store
           else:
               stats[key] = new_store
           sign = "+" if delta >= 0 else ""
           print(f"  📊 [状态记账] {key}: {old_num} {sign}{delta} = {new_store}（由代码精确计算）")

   # ★ 消耗型道具自动清理：扫描绝对事实，找到 consumed/used/destroyed 关键词 → 从 inventory 删除
   inventory = status.get("inventory", [])
   if inventory:
       facts_text = _get_absolute_facts(lore).lower()
       items_to_remove = []
       consume_keywords = ["consumed", "used", "destroyed", "expended", "shattered", "broken", "spent"]
       for item in inventory:
           item_lower = item.lower()
           # 在绝对事实里找这个道具被消耗的证据
           if any(kw in facts_text for kw in [f"{item_lower} {ck}" for ck in consume_keywords] +
                  [f"{ck} {item_lower}" for ck in consume_keywords] +
                  [f"{ck} the {item_lower}" for ck in consume_keywords]):
               items_to_remove.append(item)
       if items_to_remove:
           for item in items_to_remove:
               inventory.remove(item)
           status["inventory"] = inventory
           print(f"  🧹 [自动清理] 已消耗道具从 inventory 删除: {items_to_remove}")

   safe_write_json(FILES["status"], status)

   for cu in audit_data.get("character_updates", []):
       name = cu.get("name")
       if not name: continue
       if name not in characters:
           characters[name] = {"basic": {}, "relationship_with_mc": {}, "key_events": []}
       char = characters[name]
       if cu.get("status"):     char.setdefault("basic", {})["status"]      = cu["status"]
       if cu.get("cultivation"): char.setdefault("basic", {})["cultivation"] = cu["cultivation"]
       if cu.get("relationship"): char.setdefault("relationship_with_mc", {})["surface"] = cu["relationship"]
       if cu.get("new_key_event"):
           char.setdefault("key_events", []).append(f"Ch{chapter_num}: {cu['new_key_event']}")
           if len(char["key_events"]) > 50: char["key_events"] = char["key_events"][-50:]
       char.setdefault("basic", {})["last_seen_chapter"] = chapter_num
   safe_write_json(FILES["characters"], characters)

   villain_updates = audit_data.get("villain_updates", [])
   if villain_updates:
       active_villains = quests.get("villain_status", {}).get("active_villains", [])
       for vu in villain_updates:
           vname = vu.get("name", ""); outcome = vu.get("outcome", "")
           found = False
           for v in active_villains:
               if v["name"] == vname:
                   v["current_status"] = vu.get("new_status", "")
                   if outcome == "defeated_permanently": active_villains.remove(v)
                   found = True; break
           if not found and outcome != "defeated_permanently" and vname:
               active_villains.append({"name": vname, "arcs_survived": 0, "minimum_arcs_required": 2,
                                       "current_status": vu.get("new_status",""), "next_appearance_hint": ""})
       quests.setdefault("villain_status", {})["active_villains"] = active_villains
       safe_write_json(FILES["quests"], quests)

   active_threads   = threads.get("active_threads", [])
   resolved_threads = threads.get("resolved_threads", [])
   for tu in audit_data.get("thread_updates", []):
       for t in active_threads:
           if t["id"] == tu.get("id"):
               if tu.get("action") == "progressed":
                   if tu.get("new_description"): t["description"] = tu["new_description"]
                   t["last_mentioned_chapter"] = chapter_num
               elif tu.get("action") == "resolved":
                   t["resolved_chapter"] = chapter_num; t["resolution"] = tu.get("resolution","")
                   resolved_threads.append(t); active_threads.remove(t)
               break
   for nt in audit_data.get("new_threads", []):
       if nt.get("description"):
           new_id = f"thread_{len(active_threads)+len(resolved_threads)+1:03d}"
           active_threads.append({"id": new_id, "description": nt["description"],
               "opened_chapter": chapter_num, "urgency": nt.get("urgency","medium"),
               "must_resolve_by_chapter": nt.get("must_resolve_by_chapter", chapter_num+50),
               "last_mentioned_chapter": chapter_num})
   threads["active_threads"]   = active_threads
   threads["resolved_threads"] = resolved_threads
   safe_write_json(FILES["threads"], threads)

   if audit_data.get("chapter_index_summary"):
       chap_index[str(chapter_num)] = audit_data["chapter_index_summary"]
       safe_write_json(FILES["chapter_index"], chap_index)

   new_fact = audit_data.get("new_absolute_fact","").strip()

   # ★ 越级战斗自动补充绝对事实：如果本章有战斗结果（wounded/repelled/escaped），
   #   且 audit 未写绝对事实，自动生成"MC依靠[X]手段胜过高阶对手"的事实，防止后续矛盾。
   villain_updates = audit_data.get("villain_updates", [])
   if villain_updates and not new_fact:
       combat_outcomes = [v for v in villain_updates if v.get("outcome") in ("wounded","escaped","repelled")]
       if combat_outcomes:
           outcomes_text = "; ".join([f"{v['name']} {v['outcome']}" for v in combat_outcomes])
           auto_fact_prompt = f"""In Ch.{chapter_num}, the following combat outcomes occurred: {outcomes_text}.
MC current status: {json.dumps(status, ensure_ascii=False)}.
Write ONE sentence (under 40 words) explaining HOW the MC achieved this result (environmental advantage, item, special technique, sacrifice, etc.).
This will be recorded as an absolute fact to prevent future continuity errors.
Output ONLY the sentence. No preamble."""
           auto_fact = call_deepseek(auto_fact_prompt, temperature=0.1, timeout=60)
           if auto_fact and len(auto_fact.strip()) < 200:
               new_fact = auto_fact.strip()
               print(f"  🤖 [自动事实] 越级战斗机制已记录: {new_fact[:80]}...")

   if new_fact:
       # ★ 守门：若新事实破坏金手指核心边界（如把被动法宝写成主动武器），拒绝固化为绝对事实。
       if _new_fact_conflicts_with_core(new_fact, safe_read_text(FILES["lore"], "")):
           print(f"  🛡️  [守门] 新事实疑似破坏金手指核心设定，已拒绝固化为绝对事实：{new_fact[:70]}...")
           print(f"       （已记入巡检清单，请人工确认是否为有意的设定扩展）")
           safe_append_text(os.path.join(BASE_DIR, "inspection_priority.txt"),
               f"Ch{chapter_num}: [守门拦截] 审计欲新增可能破坏金手指设定的绝对事实，已拒绝：{new_fact}\n")
           new_fact = ""   # 清空，不写入

   if new_fact:
       lore_text = safe_read_text(FILES["lore"], "")
       if "=== END ABSOLUTE FACTS ===" in lore_text:
           lore_text = lore_text.replace("=== END ABSOLUTE FACTS ===", f"\nCh.{chapter_num}: {new_fact}\n=== END ABSOLUTE FACTS ===")
           safe_write_text(FILES["lore"], lore_text)
       # ★ S级永久事实自动入池（境界/生死/永久残疾/誓约等，永不过期、永远注入）
       if _classify_fact_is_s_tier(new_fact):
           _append_perma_fact(chapter_num, new_fact)
           print(f"  ⭐ [S级永久事实] 已入永久池: {new_fact[:70]}...")
       else:
           print(f"  📌 新绝对事实: {new_fact}")

   print("  ✅ 所有数据库更新完毕！")
   return True, False

# ─────────────────────────────────────────────────
# 步骤 5：记忆压缩
# ─────────────────────────────────────────────────

def update_sliding_memory(chapter_num, story_text):
   print("🧠 [记忆] 正在压缩并归档本章记忆...")
   # 提取章节标题
   lines = story_text.strip().split('\n')
   title = clean_title(lines[0], chapter_num) if lines else f"Chapter {chapter_num}"
   prompt = f"""
Extract story status at END of this chapter as 3-5 sentences (no line breaks).
Include: what happened, MC's location, final cliffhanger, MC's next intent, enemy status.

[Chapter Text]: {story_text}
"""
   result = call_deepseek(prompt, temperature=0.2, timeout=180)

   # ★ 记忆链不可断裂：AI 压缩失败时用降级方案兜底，绝不留下记忆空洞。
   #   （记忆缺一章会导致下一章剧情断层或重复，是长程一致性静默崩坏的主因。）
   if not result:
       print("  ⚠️  AI 记忆压缩失败，启用降级兜底（截取正文要点，保证记忆链连续）。")
       body = '\n'.join(lines[1:]).strip() if len(lines) > 1 else story_text.strip()
       # 取正文开头2句 + 结尾2句作为粗略摘要，确保下一章仍有上下文衔接
       _sents = re.split(r'(?<=[.!?])\s+', body.replace('\n', ' '))
       _sents = [s.strip() for s in _sents if s.strip()]
       if len(_sents) >= 4:
           result = " ".join(_sents[:2] + ["..."] + _sents[-2:])
       elif _sents:
           result = " ".join(_sents)
       else:
           result = f"Chapter {chapter_num} occurred; AI summary unavailable."
       result = "[AUTO-FALLBACK SUMMARY] " + result
       # 记录到巡检清单，提醒人工/巡检引擎日后回补精确摘要
       safe_append_text(os.path.join(BASE_DIR, "inspection_priority.txt"),
           f"Ch{chapter_num}: 记忆AI压缩失败，已用降级摘要兜底，建议回补精确摘要。\n")

   summary  = result.strip().replace('\n', ' ')
   arc_line = f"Ch{chapter_num}: {title} — {summary[:100]}"
   safe_append_text(FILES["chronicles"],  f"Chapter {chapter_num}: {summary}\n")
   safe_append_text(FILES["arc_current"], arc_line + "\n")

   memories = [l.strip() for l in safe_read_text(FILES["recent_memory"], "").splitlines() if l.strip()]
   memories.append(f"Chapter {chapter_num} Summary: {summary}")
   if len(memories) > 5: memories = memories[-5:]
   safe_write_text(FILES["recent_memory"], "\n".join(memories))
   print(f"  ✅ 记忆归档完毕（滑动窗口 {len(memories)} 章）。")
   return True

def compress_arc_if_needed(chapter_num, volumes, quests):
   if chapter_num % ARC_SIZE != 0: return volumes, quests
   print(f"🗜️  [Arc压缩] 第 {chapter_num} 章...")
   arc_text = safe_read_text(FILES["arc_current"], "")
   if not arc_text.strip(): return volumes, quests
   compressed = call_deepseek(
       f"Compress these arc events into EXACTLY 5 sentences. Focus on major power gains, key enemies defeated, relationship changes, revelations.\n\n{arc_text}",
       temperature=0.1, timeout=120)
   if not compressed: return volumes, quests
   arc_num = chapter_num // ARC_SIZE
   volumes[f"arc_{arc_num:03d}"] = {"chapters": f"{chapter_num-ARC_SIZE+1}-{chapter_num}", "compressed": compressed.strip()}
   safe_write_json(FILES["volumes"], volumes)
   safe_write_text(FILES["arc_current"], "")
   active_villains = quests.get("villain_status", {}).get("active_villains", [])
   if active_villains:
       for v in active_villains: v["arcs_survived"] = v.get("arcs_survived", 0) + 1
       quests["villain_status"]["active_villains"] = active_villains
       safe_write_json(FILES["quests"], quests)
   print(f"  ✅ Arc {arc_num} 已归档。")
   return volumes, quests

def compress_volume_if_needed(chapter_num, volumes, threads):
   if chapter_num % VOLUME_SIZE != 0: return volumes
   print(f"📚 [卷级压缩] 第 {chapter_num} 章...")
   vol_num   = chapter_num // VOLUME_SIZE
   arc_texts = "\n".join([volumes.get(f"arc_{n:03d}", {}).get("compressed","")
                          for n in range((vol_num-1)*(VOLUME_SIZE//ARC_SIZE)+1, vol_num*(VOLUME_SIZE//ARC_SIZE)+1)])
   vol_data  = extract_json(call_deepseek(
       f"Produce volume milestone record from arc summaries.\nReturn EXACTLY: {{\"compressed_summary\":\"5 sentences\",\"power_milestones\":[],\"resolved_conflicts\":[],\"unresolved_threads_inherited\":[]}}\n\n{arc_texts}",
       temperature=0.1, timeout=180))
   if not vol_data: return volumes
   start_ch = (vol_num-1)*VOLUME_SIZE+1
   volumes[f"volume_{vol_num}"] = {"chapters": f"{start_ch}-{chapter_num}", "title": f"Volume {vol_num}", "completed": True,
       "compressed_summary": vol_data.get("compressed_summary",""),
       "power_milestones":   vol_data.get("power_milestones",[]),
       "resolved_conflicts": vol_data.get("resolved_conflicts",[]),
       "unresolved_threads_inherited": vol_data.get("unresolved_threads_inherited",[])}
   safe_write_json(FILES["volumes"], volumes)
   print(f"  ✅ 卷 {vol_num} 里程碑已归档。")
   return volumes

# ─────────────────────────────────────────────────
# 步骤 6：导演
# ─────────────────────────────────────────────────

def auto_evolve_plot(chapter_text, quests, threads, characters, chapter_num):
   print("🎬 [导演] 正在推演下章剧情...")
   active_threads  = threads.get("active_threads", [])
   dormant_warning = ""
   dormant         = [t for t in active_threads if chapter_num - t.get("last_mentioned_chapter",0) > 30 and t.get("urgency") == "high"]
   if dormant:
       dormant_warning = "\nWARNING — HIGH URGENCY THREADS DORMANT 30+ CHAPTERS (MUST surface soon):\n" + "\n".join([f"- [{t['id']}] {t['description']}" for t in dormant])

   # ★ 吸收主编转交的导演待办（节奏/线程问题）：这些是上一章无法重写解决的，
   #   必须在规划下一章时强制处理。用完即清空，避免重复。
   todo_text = safe_read_text(FILES["director_todo"], "").strip()
   director_mandate = ""
   if todo_text:
       director_mandate = ("\n=== MANDATORY DIRECTOR TASKS (from Chief Editor — MUST address in next chapter) ===\n"
                           + todo_text +
                           "\nThese are scheduling issues that the previous chapter could not fix by rewriting. "
                           "The NEXT chapter's micro_goal MUST directly act on them "
                           "(e.g. trigger the overdue breakthrough, resolve the overdue thread).\n")
       print(f"  📋 [导演待办] 吸收 {len(todo_text.splitlines())} 条主编转交任务。")

   relevant_chars = {n: d for n, d in characters.items() if "protagonist" not in d.get("narrative_role","").lower()}
   tone_anchor = get_book_config().get("tone_anchor", "")
   prompt = f"""
You are a top-tier Webnovel Architect. Goal: keep readers addicted across 3 million words.

★★★ TONE ANCHOR — the next chapter's plan MUST fit this tone ★★★
{tone_anchor}
If the chapter just written has drifted from this tone, your next micro_goal MUST steer back toward it.
★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★

[Current Quests]: {json.dumps(quests, ensure_ascii=False)}
[Active Subplots]: {_get_active_threads_text(threads)}
[Villain Status]: {_get_villain_status_text(quests)}
[Key Characters]: {json.dumps(relevant_chars, indent=2, ensure_ascii=False)}
[Just Written Ch.{chapter_num}]: {chapter_text}
{dormant_warning}
{director_mandate}
Task: Did MC achieve immediate_micro_goal? If yes → next high-dopamine micro_goal.
If no → force brutal resolution next chapter. If macro_goal resolved → NEW macro_goal.
Villains with arcs left: escalate threats, never resolve.
If DORMANT HIGH URGENCY threads listed: weave into next chapter.
If MANDATORY DIRECTOR TASKS are present: the next micro_goal MUST act on them directly.

Return EXACTLY this JSON:
{{"macro_goal":"","immediate_micro_goal":"","active_subplots_to_mention":[],"character_interactions_needed":[],
 "villain_status":{{"active_villains":[{{"name":"","arcs_survived":0,"minimum_arcs_required":2,"current_status":"","next_appearance_hint":""}}]}},
 "chapter_budget":{{"combat_and_dominance":"60%","character_moment":"20%","worldbuilding_or_mystery":"20%"}}}}
"""
   new_quests = extract_json(call_deepseek(prompt, temperature=0.7, timeout=600))
   if new_quests:
       # ★ 合并 villain_status 而不是覆盖：保留 minimum_arcs_required 等重要字段
       existing_villains = {v["name"]: v for v in quests.get("villain_status", {}).get("active_villains", [])}
       new_villains = new_quests.get("villain_status", {}).get("active_villains", [])
       merged_villains = []
       for nv in new_villains:
           name = nv.get("name", "")
           if name in existing_villains:
               ev = existing_villains[name]
               # 保留原有的关键字段，只更新 current_status 和 next_appearance_hint
               merged = dict(ev)
               merged["current_status"]      = nv.get("current_status", ev.get("current_status", ""))
               merged["next_appearance_hint"] = nv.get("next_appearance_hint", ev.get("next_appearance_hint", ""))
               merged_villains.append(merged)
           else:
               merged_villains.append(nv)
       new_quests.setdefault("villain_status", {})["active_villains"] = merged_villains
       safe_write_json(FILES["quests"], new_quests)
       # ★ 待办已吸收进下章计划，清空，避免重复注入
       if todo_text:
           safe_write_text(FILES["director_todo"], "")
       print(f"  ✅ 下章目标: {new_quests.get('immediate_micro_goal','')[:80]}...")
       return True
   print("  ⚠️  导演AI返回异常，保持原任务。")
   return False

# ─────────────────────────────────────────────────
# 微信推送 (Telegram)
# ─────────────────────────────────────────────────

def send_telegram_notification(chapter_num, status, rewrite_count=0):
   print("📲 [推送] 正在发送 Telegram 捷报...")
   if not TG_BOT_TOKEN or not TG_CHAT_ID:
       print("  ⚠️ Telegram Token或Chat ID未配置，跳过推送。")
       return

   url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
   realm = status.get("realm") or status.get("rank") or status.get("kaelen_rank") or "未知"
   rewrite_note = f"\n- 🔄 <b>主编重写次数</b>：{rewrite_count} 次" if rewrite_count > 0 else ""
   text = f"""🎉 <b>[{NOVEL_ID}] 第 {chapter_num} 章已自动发布！</b>

<b>🚀 战报</b>
- 📖 <b>最新发布</b>：Chapter {chapter_num}
- ⚡ <b>主角境界</b>：{realm}
- 📍 <b>当前位置</b>：{status.get('location','未知')}{rewrite_note}

<i>引擎运转平稳。躺平就行。</i>
"""
   payload = {"chat_id": TG_CHAT_ID, "text": text, "parse_mode": "HTML"}
   try:
       r = requests.post(url, json=payload, timeout=30)
       r.raise_for_status()
       print("  ✅ Telegram 推送成功！")
   except Exception as e:
       print(f"  ❌ Telegram 推送失败: {e}")

# ─────────────────────────────────────────────────
# 主流程
# ─────────────────────────────────────────────────

def health_monitor(chapter_num, story_text, ed_score, characters, status=None):
   """长篇健康监控（四合一），每章末尾运行。把数据写日志，异常时预警，防止长篇"写着写着悄悄崩盘"。
   1) 质量评分趋势：记录每章主编评分，连续走低时预警。
   2) 角色出场频率：追踪重要角色多少章没出现，长期缺席时预警（防后宫/配角被遗忘）。
   3) 战斗/文戏占比：统计近期战斗章占比，过高或过低时预警（防连续打斗或连续文戏）。
   4) 剧情推进度：追踪境界/地点等主线指标，长期停滞时预警（防主角卡在同一场景循环里原地打转）。
   所有预警写入 health_alerts.txt，绝不中断主流程。"""
   import json as _json
   monitor_path = os.path.join(BASE_DIR, "health_monitor.json")
   alert_path   = os.path.join(BASE_DIR, "health_alerts.txt")
   data = safe_read_json(monitor_path, {"scores": [], "char_last_seen": {}, "combat_flags": []})

   alerts = []

   # ── 1. 质量评分趋势 ──
   data["scores"].append({"ch": chapter_num, "score": ed_score})
   data["scores"] = data["scores"][-50:]   # 只留最近50章
   recent_scores = [s["score"] for s in data["scores"][-5:]]
   if len(recent_scores) >= 5:
       avg5 = sum(recent_scores) / len(recent_scores)
       if avg5 < 70:
           alerts.append(f"⚠️ 质量预警：最近5章平均分 {avg5:.0f}（<70），质量可能在下滑，建议人工抽查。")
       # 连续3章下降
       last3 = [s["score"] for s in data["scores"][-3:]]
       if len(last3) == 3 and last3[0] > last3[1] > last3[2]:
           alerts.append(f"⚠️ 质量预警：连续3章评分下降（{last3[0]}→{last3[1]}→{last3[2]}），注意趋势。")

   # ── 2. 角色出场频率 ──
   text_lower = (story_text or "").lower()
   # 取重要角色（女主/主角/反派/关键配角）
   important = {n: d for n, d in (characters or {}).items()
               if any(k in d.get("narrative_role", "").lower()
                      for k in ["lead", "protagonist", "heroine", "female", "villain", "main"])}
   for name, d in important.items():
       # 角色名可能是 Lu_Changan 这种，取首段做匹配
       display = name.replace("_", " ").lower()
       first_name = display.split()[0] if display.split() else display
       appeared = first_name in text_lower or display in text_lower
       if appeared:
           data["char_last_seen"][name] = chapter_num
       else:
           last = data["char_last_seen"].get(name, chapter_num)
           gap = chapter_num - last
           # 女主/关键角色超过40章没出现 → 预警
           role = d.get("narrative_role", "").lower()
           threshold = 40 if ("lead" in role or "heroine" in role or "female" in role) else 80
           if gap >= threshold and gap % 20 == 0:  # 每20章提醒一次，避免刷屏
               alerts.append(f"⚠️ 角色预警：[{name}] 已 {gap} 章未出现（角色定位:{role}），可能被遗忘，考虑安排回归。")

   # ── 3. 战斗/文戏占比 ──
   # 用关键词粗略判定本章是否战斗章
   combat_kw = ['blood', 'sword', 'strike', 'blast', 'wound', 'kill', 'attack', 'qi surged',
                'spell', 'undead', 'formation', 'talisman', 'roared', 'shattered', 'slammed']
   combat_hits = sum(1 for kw in combat_kw if kw in text_lower)
   is_combat = combat_hits >= 5
   data["combat_flags"].append(1 if is_combat else 0)
   data["combat_flags"] = data["combat_flags"][-10:]   # 近10章
   if len(data["combat_flags"]) >= 10:
       ratio = sum(data["combat_flags"]) / len(data["combat_flags"])
       if ratio >= 0.8:
           alerts.append(f"⚠️ 节奏预警：近10章 {int(ratio*100)}% 是战斗章，连续打斗易疲劳，建议插入文戏/谋划/日常章。")
       elif ratio <= 0.1:
           alerts.append(f"⚠️ 节奏预警：近10章几乎无战斗，长期文戏易使读者流失，建议安排冲突/战斗。")

   # ── 4. 剧情推进度（防主角长期卡在同一场景/境界原地打转）──
   _st = status or {}
   cur_rank = str(_st.get("rank") or _st.get("current_great_realm") or _st.get("current_realm_tier") or "")
   cur_loc  = str(_st.get("location") or "")
   prog = data.setdefault("progress", {"rank": "", "rank_since": chapter_num,
                                       "loc": "", "loc_since": chapter_num})
   # 境界停滞检测
   if cur_rank and cur_rank == prog.get("rank"):
       rank_stalled = chapter_num - prog.get("rank_since", chapter_num)
       # 凡人流慢热是优点，但读者需要进度感：阈值设18章，之后每6章提醒一次。
       # 第一次突破不宜拖太久（Royal Road 读者耐心有限），18章起持续提醒主笔推进修炼。
       if rank_stalled >= 18 and rank_stalled % 6 == 0:
           alerts.append(f"⚠️ 推进预警：主角境界({cur_rank})已 {rank_stalled} 章未变化，应尽快安排一次实质的修炼进展或突破，给读者进度感（凡人流可以慢，但不能一直原地不动）。")
   else:
       # 境界变了（或首次记录）。首次记录时，若境界仍是初始的"凡人/无修为"状态，
       # 起点回溯到第1章——否则 book1 这种已跑十几章的会从当前章重新计数，导致预警迟迟不触发。
       is_initial_mortal = any(k in cur_rank.lower() for k in
                               ["mortal", "凡人", "no cultivation", "尚未", "未踏入"])
       if not prog.get("rank") and is_initial_mortal:
           prog["rank_since"] = 1
       else:
           prog["rank_since"] = chapter_num
       prog["rank"] = cur_rank
   # 地点停滞检测（防主角几十章卡在同一个地方）
   #   用宽松匹配：地点描述常有细微措辞变化（"eastern shed" vs "eastern terraces"），
   #   只要核心地名关键词重叠就视为同一地点，避免 stall 计数被反复误重置。
   def _loc_key(loc):
       # 提取地点的核心名词（去掉方位/修饰），取最长的2个词做指纹
       words = [w for w in re.findall(r'[a-z]+', loc.lower()) if len(w) > 3
                and w not in ('the','near','edge','side','area','outer','inner','eastern','western',
                              'northern','southern','region','place','where')]
       return set(words[:3])
   prev_loc_key = _loc_key(prog.get("loc", ""))
   cur_loc_key = _loc_key(cur_loc)
   same_loc = bool(cur_loc and prev_loc_key and (cur_loc_key & prev_loc_key))
   if cur_loc and (cur_loc == prog.get("loc") or same_loc):
       loc_stalled = chapter_num - prog.get("loc_since", chapter_num)
       if loc_stalled >= 20 and loc_stalled % 10 == 0:
           alerts.append(f"⚠️ 推进预警：主角已在同一地点({cur_loc[:30]})停留 {loc_stalled} 章，考虑推进剧情、转换场景或进入新区域，避免读者审美疲劳。")
   else:
       prog["loc"] = cur_loc
       prog["loc_since"] = chapter_num
   data["progress"] = prog

   safe_write_json(monitor_path, data)

   # ★ 把"可由下一章写作修正"的预警(节奏/角色回归)写入待办，供 precheck 注入下一章主笔指令，形成闭环。
   #   质量趋势类预警只提醒人工，不注入(改不了根因)。
   actionable = []
   for a in alerts:
       if "节奏预警" in a:
           if "连续打斗" in a:
               actionable.append("PACING: Recent chapters have been combat-heavy. This chapter should slow down — focus on scheming, character interaction, preparation, or daily life instead of another fight.")
           elif "几乎无战斗" in a:
               actionable.append("PACING: Recent chapters have had little conflict. Introduce a genuine threat, confrontation, or action beat in this chapter to re-energize the pace.")
       elif "角色预警" in a:
           m = re.search(r'\[([^\]]+)\]', a)
           if m:
               cname = m.group(1).replace("_", " ")
               actionable.append(f"CHARACTER: {cname} has been absent for a long time. Find a natural way to bring this character back into the story soon (this chapter or very shortly).")
       elif "推进预警" in a:
           if "境界" in a:
               actionable.append("PROGRESSION: The MC's cultivation/power has been static for a long time. Within the next few chapters, give a concrete, earned step forward (a breakthrough, a new technique mastered, a tangible power gain) so readers feel progress — without rushing or breaking the hard-won pacing.")
           elif "地点" in a:
               actionable.append("PLOT MOVEMENT: The story has lingered in the same location/situation too long. Push the main plot forward — move the MC toward a new place, a new objective, or a new confrontation, instead of repeating the same kind of scene.")
   if actionable:
       safe_write_text(os.path.join(BASE_DIR, "health_todo.txt"), "\n".join(actionable))

   if alerts:
       print("  📊 [健康监控] 发现以下提醒：")
       for a in alerts:
           print(f"     {a}")
           safe_append_text(alert_path, f"Ch{chapter_num}: {a}\n")
   else:
       print("  📊 [健康监控] 质量/角色/节奏均正常。")


def main():
   print("🚀 主笔引擎 v7.0 启动！开头换花样 + 标题兜底去雷同 + 反碎句反倒装 + 双记账 + 调性锚定\n")

   auto_init_files()

   db = load_database()
   if not db:
       print("❌ 数据库加载失败，流程终止。"); return

   lore, status, characters, quests, threads, volumes, chap_index, recent_mem, arc_current, chronicles = db
   current_chapter = status.get("chapter", 1)
   print(f"📖 当前目标：第 {current_chapter} 章\n" + "─" * 50)

   status, threads, characters, quests = auto_health_check_and_repair(
       status, lore, threads, characters, quests, current_chapter, chronicles)

   # ── 步骤 0：合并预检与境界 ──────────────────────
   reminders = precheck_and_pacing(lore, status, threads, quests, current_chapter)

   # ── 步骤 1 + 1.5：生成 → 主编审稿 → 自动重写 ───
   story_text      = None
   rewrite_count   = 0
   editor_feedback = ""
   last_draft      = None
   last_score      = 0
   last_failed     = []

   for attempt in range(1, MAX_REWRITE_ATTEMPTS + 2):
       gen_temp = max(0.6, 0.8 - (rewrite_count * 0.08))
       draft = generate_story(lore, status, characters, quests, threads, volumes,
                              recent_mem, arc_current, current_chapter, reminders, editor_feedback, temperature=gen_temp)
       if not draft:
           print(f"  ⚠️  主笔生成失败，第 {attempt} 次重试..."); continue

       print(f"\n" + "─" * 50)
       passed, editor_feedback, ed_score, ed_failed = chief_editor_review(draft, lore, status, quests, threads, current_chapter)
       last_draft, last_score, last_failed = draft, ed_score, ed_failed

       if passed:
           story_text = draft
           break
       else:
           rewrite_count += 1
           if attempt <= MAX_REWRITE_ATTEMPTS:
               print(f"\n  🔄 触发第 {rewrite_count} 次自动重写 (当前生成温度降至: {max(0.6, 0.8 - (rewrite_count * 0.08)):.2f})...")
           else:
               # 达到最大重写次数：分数够高就放行，否则放行但标记需巡检引擎重点回校
               if ed_score >= RELEASE_FLOOR_SCORE:
                   print(f"\n  ✅ 已达最大重写次数，末稿评分 {ed_score}≥{RELEASE_FLOOR_SCORE}，正常放行。")
               else:
                   print(f"\n  ⚠️  已达最大重写次数，末稿评分 {ed_score}<{RELEASE_FLOOR_SCORE}，放行并标记巡检重点复查。")
                   # 结构化失败记录：写一行 JSON，方便统计到底卡在哪
                   fail_record = {
                       "chapter": current_chapter,
                       "score": ed_score,
                       "failed_checks": ed_failed,
                       "feedback": editor_feedback[:300],
                   }
                   safe_append_text(os.path.join(BASE_DIR, "editor_log.jsonl"),
                       json.dumps(fail_record, ensure_ascii=False) + "\n")
                   # 同时写入巡检引擎的优先复查清单
                   safe_append_text(os.path.join(BASE_DIR, "inspection_priority.txt"),
                       f"Ch{current_chapter}: 末稿评分{ed_score}, 失败项{ed_failed}\n")
               story_text = draft
               break

   if not story_text:
       # 兜底：所有尝试都失败但有草稿，放行最后一稿，绝不空手而归
       if last_draft:
           print("  ⚠️  全部尝试未通过，放行最后一稿（已记录待巡检）。")
           story_text = last_draft
       else:
           print("❌ 故事生成彻底失败，流程终止。"); return

   lines      = story_text.strip().split('\n')
   cool_title = clean_title(lines[0], current_chapter)
   real_story = '\n'.join(lines[1:]).strip()
   real_story = deduplicate_chapter(real_story)   # ★ 发布前整章去重，切除模型重复输出
   real_story = inject_author_voice(real_story, current_chapter)

   print(f"\n📋 章节标题: {cool_title}")
   if rewrite_count > 0: print(f"   （经过 {rewrite_count} 次主编重写后定稿）")

   # ── 步骤 2：HTML排版
   formatted_story = f"<h2 style='text-align: center;'><strong>{cool_title}</strong></h2>\n" + real_story
   final_html      = format_html_content(formatted_story, current_chapter)

   # ── 步骤 3：发布 ────────────────────────────────
   print(f"\n" + "─" * 50)
   success = publish_to_website(cool_title, final_html, current_chapter)
   if not success:
       print("❌ 发布失败，流程终止（未推进章节号）。"); return

   # ── 步骤 4：审计 ────────────────────────────────
   print(f"\n" + "─" * 50)
   audit_ok, contradiction = audit_and_update_db(
       story_text, status, characters, threads, chap_index, current_chapter, lore, quests)
   if contradiction:
       print(f"  🚨 审计发现叙事矛盾，已记录日志。")
       safe_append_text(os.path.join(BASE_DIR, "contradiction_log.txt"),
           f"Ch{current_chapter}: {cool_title} — 矛盾，需人工复查\n")

   # ── 步骤 5：记忆压缩 ───────────────────────────
   print(f"\n" + "─" * 50)
   update_sliding_memory(current_chapter, story_text)
   volumes, quests = compress_arc_if_needed(current_chapter, volumes, quests)
   volumes         = compress_volume_if_needed(current_chapter, volumes, threads)

   # ── 步骤 6：导演推演 ───────────────────────────
   print(f"\n" + "─" * 50)
   auto_evolve_plot(story_text, quests, threads, characters, current_chapter)

   # ── 步骤 6.5：长篇健康监控（质量趋势/角色出场/战斗节奏/剧情推进度）──
   health_monitor(current_chapter, story_text, last_score, characters, status)

   # ── 推进章节号 ─────────────────────────────────
   status["chapter"] = current_chapter + 1
   safe_write_json(FILES["status"], status)

   print(f"\n{'═' * 50}")
   print(f"🎉 [{NOVEL_ID}] 第 {current_chapter} 章全套工序完美收官！")
   if rewrite_count > 0: print(f"   主编重写 {rewrite_count} 次，质量有保障。")
   print(f"   系统已重置为第 {status['chapter']} 章的准备状态。")
   print(f"{'═' * 50}\n")

   send_telegram_notification(current_chapter, status, rewrite_count)

if __name__ == "__main__":
   main()