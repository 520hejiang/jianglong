#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
大纲解析脚本 —— 把 Markdown / TXT 大纲转成可注入系统的 JSON，或直接通过 API 写入。

支持的输入结构（用一级标题 # 或「【】」分节，关键词模糊匹配，顺序随意）：

    # 总纲
    韩立，一介凡人，凭谨慎与机缘一步步登临仙界……

    # 核心设定
    世界观：修仙界弱肉强食，无利不起早……
    地理：天南、乱星海……

    # 境界体系
    - 炼气 13
    - 筑基 12
    - 结丹 9

    # 分卷大纲
    ## 第一卷 山村少年 (1-60)
    简介：韩立入七玄门，得神秘小瓶，结识墨大夫。
    关键事件：
    - 拜入七玄门
    - 得神秘小瓶
    - 墨大夫之死
    ## 第二卷 初入江湖 (61-130)
    ……

    # 核心人物
    ## 韩立
    身份：protagonist
    境界：炼气 1
    别名：厚土印主人
    法宝：青元剑诀, 神秘小瓶
    简介：心思缜密，极度谨慎。
    ## 墨大夫
    身份：ally
    ……

    # 核心法宝          (可选，单列法宝设定，会并入主角或登记为说明)
    ## 神秘小瓶
    属性：可加速灵药生长
    ……

用法：
    # 仅生成 JSON（打印到 stdout，并可 -o 写文件）
    python tools/parse_outline.py 大纲.md -o book.json

    # 解析后直接通过 API 创建书 + seed 角色
    python tools/parse_outline.py 大纲.md \\
        --api https://novel-engine.xxx.workers.dev --token $ADMIN_TOKEN --push

只依赖 Python 标准库。
"""
import argparse
import json
import re
import sys
import urllib.request

# 默认凡人流境界体系（境界体系一节缺省时使用）
DEFAULT_POWER = [
    {"index": 0, "name": "炼气", "subLayers": 13},
    {"index": 1, "name": "筑基", "subLayers": 12},
    {"index": 2, "name": "结丹", "subLayers": 9},
    {"index": 3, "name": "元婴", "subLayers": 9},
    {"index": 4, "name": "化神", "subLayers": 9},
    {"index": 5, "name": "炼虚", "subLayers": 9},
    {"index": 6, "name": "合体", "subLayers": 9},
    {"index": 7, "name": "大乘", "subLayers": 9},
    {"index": 8, "name": "渡劫", "subLayers": 9},
]

ROLE_MAP = {
    "主角": "protagonist", "protagonist": "protagonist",
    "盟友": "ally", "同伴": "ally", "ally": "ally",
    "敌": "enemy", "反派": "enemy", "enemy": "enemy",
}


def normalize(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def split_top_sections(text: str):
    """按一级标题 (#, 【】) 切分为 (title, body) 列表。"""
    lines = normalize(text).split("\n")
    sections, cur_title, cur_body = [], "__preamble__", []
    for ln in lines:
        m = re.match(r"^\s*#\s+(.+?)\s*$", ln) or re.match(r"^\s*【(.+?)】\s*$", ln)
        if m:
            sections.append((cur_title, "\n".join(cur_body).strip()))
            cur_title, cur_body = m.group(1).strip(), []
        else:
            cur_body.append(ln)
    sections.append((cur_title, "\n".join(cur_body).strip()))
    return [(t, b) for t, b in sections if t != "__preamble__" or b]


def split_sub(body: str):
    """按二级标题 ## 切分一个 section 的 body 为 [(subtitle, subbody)]。"""
    lines = body.split("\n")
    items, cur, buf = [], None, []
    for ln in lines:
        m = re.match(r"^\s*##\s+(.+?)\s*$", ln)
        if m:
            if cur is not None:
                items.append((cur, "\n".join(buf).strip()))
            cur, buf = m.group(1).strip(), []
        else:
            buf.append(ln)
    if cur is not None:
        items.append((cur, "\n".join(buf).strip()))
    return items


def field(body: str, *keys):
    """从形如 '境界：炼气 1' 的行里取字段值，支持中英文冒号。"""
    for ln in body.split("\n"):
        m = re.match(r"^\s*[-*]?\s*(\w+|[一-龥]+)\s*[:：]\s*(.+)$", ln)
        if m and m.group(1).strip() in keys:
            return m.group(2).strip()
    return ""


def bullets(body: str, after_key=None):
    """取列表项；若 after_key 给定，只取该关键词行之后的列表。"""
    lines = body.split("\n")
    start = 0
    if after_key:
        for i, ln in enumerate(lines):
            if re.search(after_key, ln):
                start = i + 1
                break
        else:
            return []
    out = []
    for ln in lines[start:]:
        m = re.match(r"^\s*[-*]\s+(.+)$", ln)
        if m:
            out.append(m.group(1).strip())
        elif out and not ln.strip():
            continue
        elif out:
            break
    return out


def parse_volumes(body: str):
    vols, vol_no, prev_end = [], 0, 0
    for title, sub in split_sub(body):
        vol_no += 1
        # 标题里抽章号范围： (1-60) / 1-60 / 第1-60章
        rng = re.search(r"(\d+)\s*[-–~]\s*(\d+)", title)
        start_ch = int(rng.group(1)) if rng else prev_end + 1
        end_ch = int(rng.group(2)) if rng else start_ch + 59
        prev_end = end_ch
        clean_title = re.sub(r"[\(（]?\s*第?\d+\s*[-–~]\s*\d+\s*章?\s*[\)）]?", "", title).strip()
        clean_title = re.sub(r"^第[一二三四五六七八九十\d]+卷\s*", "", clean_title).strip()
        summary = field(sub, "简介", "简述", "summary") or sub.split("关键事件")[0].strip()[:300]
        events = bullets(sub, after_key=r"关键事件|key_events|事件")
        vols.append({
            "vol": vol_no, "title": clean_title or f"第{vol_no}卷",
            "start_ch": start_ch, "end_ch": end_ch,
            "summary": summary, "key_events": events,
        })
    return vols


def parse_power(body: str):
    ranks, idx = [], 0
    for b in bullets(body) or body.split("\n"):
        m = re.match(r"^\s*[-*]?\s*([一-龥A-Za-z]+)\s*[，,\s]*?(\d+)?\s*层?\s*$", b.strip())
        if m and m.group(1):
            ranks.append({"index": idx, "name": m.group(1), "subLayers": int(m.group(2) or 9)})
            idx += 1
    return ranks or DEFAULT_POWER


def parse_characters(body: str):
    chars = []
    for name, sub in split_sub(body):
        role_raw = field(sub, "身份", "角色", "role")
        role = ROLE_MAP.get(role_raw, ROLE_MAP.get(role_raw.lower(), "npc"))
        realm = field(sub, "境界", "realm")
        ri, rn, rs = 0, "", 0
        rm = re.match(r"\s*([一-龥A-Za-z]+)?\s*(\d+)?", realm)
        if rm:
            rn = rm.group(1) or ""
            rs = int(rm.group(2) or 0)
            for r in DEFAULT_POWER:
                if r["name"] == rn:
                    ri = r["index"]
        aliases = [a.strip() for a in re.split(r"[，,、/]", field(sub, "别名", "道号", "aliases")) if a.strip()]
        arts = [{"name": a.strip(), "grade": "未定", "durability": 100}
                for a in re.split(r"[，,、/]", field(sub, "法宝", "artifacts")) if a.strip()]
        techs = [{"name": t.strip(), "layer": 1, "maxLayer": 9}
                 for t in re.split(r"[，,、/]", field(sub, "功法", "techniques")) if t.strip()]
        notes = field(sub, "简介", "简述", "设定", "notes") or sub.strip()[:200]
        chars.append({
            "name": name, "role": role, "alive": True, "aliases": aliases,
            "realm_index": ri, "realm_name": rn, "realm_sub": rs,
            "techniques": techs, "artifacts": arts, "relations": [], "status_notes": notes,
        })
    return chars


def parse(text: str, title=None, target_chapters=800, start_chapter=1):
    sections = split_top_sections(text)
    book = {
        "title": title or "未命名",
        "start_chapter": start_chapter,
        "target_chapters": target_chapters,
        "master_outline": "",
        "core_settings": "",
        "power_system": "",
        "volume_outline": "[]",
        "characters": [],
    }
    extra_settings = []
    for t, body in sections:
        low = t.lower()
        if re.search(r"总纲|主线|梗概|master", t, re.I):
            book["master_outline"] = body
        elif re.search(r"分卷|卷纲|volume|章节大纲", t, re.I):
            book["volume_outline"] = json.dumps(parse_volumes(body), ensure_ascii=False)
        elif re.search(r"境界|战力体系|power", t, re.I):
            book["power_system"] = json.dumps(parse_power(body), ensure_ascii=False)
        elif re.search(r"人物|角色|character", t, re.I):
            book["characters"] = parse_characters(body)
        elif re.search(r"法宝|功法|artifact", t, re.I):
            # 单列的法宝设定并入核心设定文本（供 LLM 参考）
            extra_settings.append(f"【{t}】\n{body}")
        elif re.search(r"核心设定|世界观|设定集|setting", t, re.I):
            extra_settings.append(body)
        else:
            extra_settings.append(f"【{t}】\n{body}")
    book["core_settings"] = "\n\n".join(s for s in extra_settings if s).strip()
    if not book["power_system"]:
        book["power_system"] = json.dumps(DEFAULT_POWER, ensure_ascii=False)
    return book


def api_post(base, token, path, payload):
    req = urllib.request.Request(
        base.rstrip("/") + path,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode("utf-8"))


def main():
    ap = argparse.ArgumentParser(description="大纲 Markdown/TXT -> 系统 JSON / API 注入")
    ap.add_argument("input", help="大纲文件路径 (.md / .txt)")
    ap.add_argument("-o", "--output", help="输出 JSON 文件路径")
    ap.add_argument("--title", help="书名（缺省取「总纲」首行或文件名）")
    ap.add_argument("--target", type=int, default=800, help="目标章数")
    ap.add_argument("--start", type=int, default=1, help="起始章号")
    ap.add_argument("--api", help="Worker API 地址，配合 --push")
    ap.add_argument("--token", help="ADMIN_TOKEN")
    ap.add_argument("--push", action="store_true", help="直接通过 API 创建书并 seed 角色")
    args = ap.parse_args()

    with open(args.input, encoding="utf-8") as f:
        text = f.read()

    # 书名优先级：--title > 标题行「# 书名：xxx」> 文件名
    title = args.title
    if not title:
        m = re.search(r"#\s*书名\s*[:：]?\s*(.+)", text)
        title = (m.group(1).strip() if m else args.input.rsplit("/", 1)[-1].rsplit(".", 1)[0])

    book = parse(text, title=title, target_chapters=args.target, start_chapter=args.start)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(book, f, ensure_ascii=False, indent=2)
        print(f"已写入 {args.output}", file=sys.stderr)
    else:
        print(json.dumps(book, ensure_ascii=False, indent=2))

    print(f"\n解析结果：{len(json.loads(book['volume_outline']))} 卷 / "
          f"{len(book['characters'])} 个核心人物", file=sys.stderr)

    if args.push:
        if not (args.api and args.token):
            sys.exit("错误：--push 需要 --api 与 --token")
        chars = book.pop("characters")
        res = api_post(args.api, args.token, "/api/books", book)
        book_id = res["id"]
        if chars:
            api_post(args.api, args.token, f"/api/books/{book_id}/characters", {"characters": chars})
        print(f"\n✅ 已创建书 id={book_id}，并 seed {len(chars)} 个角色。"
              f"\n到控制台点「开始」即可全自动生成。", file=sys.stderr)


if __name__ == "__main__":
    main()
