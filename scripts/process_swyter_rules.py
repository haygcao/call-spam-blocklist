#!/usr/bin/env python3
"""
第二步：分析本地 raw_sources/ 原始数据库并生成分国家规则

位置：位于 call-spam-blocklist/scripts/process_swyter_rules.py
功能：完全在 Swyter 本地仓库下解包并分国家导出 rules 订阅。
"""

import hashlib
import json
import os
import struct
import sys
from collections import defaultdict
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
REPO_DIR = SCRIPT_DIR.parent
RAW_SWYTER_DIR = REPO_DIR / "raw_sources"
OUT_DIR = REPO_DIR / "swyter_rules"

CATEGORY_TAGS = [
    "choose_category",  # 0
    "telemarketer",     # 1
    "debt_collector",   # 2
    "silent_call",      # 3
    "nuisance_call",    # 4
    "unsolicited_call", # 5
    "call_centre",      # 6
    "fax_machine",      # 7
    "non_profit_org",   # 8
    "political_call",   # 9
    "scam_call",        # 10
    "prank_call",       # 11
    "sms",              # 12
    "survey",           # 13
    "other",            # 14
    "finance_service",  # 15
    "company",          # 16
    "service",          # 17
    "robocall",         # 18
]

COUNTRY_CODE_MAP = {
    "1": "US",    # 美国/加拿大/NANP
    "33": "FR",   # 法国
    "49": "DE",   # 德国
    "86": "CN",   # 中国
    "91": "IN",   # 印度
    "55": "BR",   # 巴西
    "34": "ES",   # 西班牙
    "44": "UK",   # 英国
    "39": "IT",   # 意大利
    "81": "JP",   # 日本
    "82": "KR",   # 韩国
    "90": "TR",   # 土耳其
    "7": "RU",    # 俄罗斯
}


def generate_rule_id(prefix: str, value: str) -> str:
    raw = f"{prefix}:{value}".encode("utf-8")
    return hashlib.md5(raw).hexdigest()


def extract_country_code(e164_str: str) -> str:
    digits = e164_str.strip().lstrip("+")
    if digits[:2] in COUNTRY_CODE_MAP:
        return COUNTRY_CODE_MAP[digits[:2]]
    if digits[:1] in COUNTRY_CODE_MAP:
        return COUNTRY_CODE_MAP[digits[:1]]
    return "GLOBAL"


def map_category_to_label_id(cat_tag: str) -> str:
    if "scam" in cat_tag or "prank" in cat_tag:
        return "scam"
    if "robo" in cat_tag or "silent" in cat_tag:
        return "robocall"
    if "telemarketer" in cat_tag or "survey" in cat_tag or "unsolicited" in cat_tag:
        return "telemarketing"
    if "debt" in cat_tag:
        return "debt_collector"
    return "spam"


def parse_data_slice(file_path: Path, global_data: dict, needed_magic: str):
    if not file_path.exists():
        return

    with open(file_path, "rb") as f:
        magic = struct.unpack("4s", f.read(4))[0].decode("ascii", errors="ignore")
        if magic != needed_magic:
            return

        f.seek(0x0F)
        added_count = struct.unpack("<I", f.read(4))[0]

        for _ in range(added_count):
            tlf = struct.unpack("<Q", f.read(8))[0]
            positive = struct.unpack("<B", f.read(1))[0]
            negative = struct.unpack("<B", f.read(1))[0]
            neutral = struct.unpack("<B", f.read(1))[0]
            _padding = struct.unpack("<B", f.read(1))[0]
            category = struct.unpack("<B", f.read(1))[0]

            cat_tag = (
                CATEGORY_TAGS[category]
                if category < len(CATEGORY_TAGS)
                else "other"
            )

            if negative >= 1 and negative > positive and negative > neutral:
                global_data[tlf] = {
                    "positive": positive,
                    "negative": negative,
                    "neutral": neutral,
                    "category": cat_tag,
                }

        try:
            cp = struct.unpack("2s", f.read(2))[0].decode("ascii", errors="ignore")
            if cp == "CP":
                removed_count = struct.unpack("<I", f.read(4))[0]
                for _ in range(removed_count):
                    tlf = struct.unpack("<Q", f.read(8))[0]
                    global_data.pop(tlf, None)
        except Exception:
            pass


def main():
    print("=== 第二步：分析本地 raw_sources/ 原始数据库并生成规则订阅 ===")

    if not RAW_SWYTER_DIR.exists():
        print(f"❌ 原始数据库目录不存在: {RAW_SWYTER_DIR}，请先执行第一步下载。")
        sys.exit(1)

    global_data = {}

    for dat_file in RAW_SWYTER_DIR.glob("data_slice_*.dat"):
        parse_data_slice(dat_file, global_data, "MTZF")

    update_bin = RAW_SWYTER_DIR / "data_slice_downloaded_update.bin"
    if update_bin.exists():
        parse_data_slice(update_bin, global_data, "MTZD")

    print(f"✅ 从原始库中成功解析并过滤出 {len(global_data)} 条有效骚扰号码。")

    by_country = defaultdict(list)

    for tlf, meta in global_data.items():
        e164_phone = f"+{tlf}"
        cat_tag = meta["category"]
        neg_count = meta["negative"]
        label_id = map_category_to_label_id(cat_tag)
        country = extract_country_code(e164_phone)

        rule = {
            "id": generate_rule_id("swyter", e164_phone),
            "name": f"ShouldIAnswer [{cat_tag}] (被投诉 {neg_count} 次)",
            "ruleType": "phone_rule",
            "phoneNumber": e164_phone,
            "labelId": label_id,
            "priority": 3,
            "action": "block",
            "isEnabled": 1,
            "count": neg_count,
        }
        by_country[country].append(rule)

    global_rules = []
    for country, rules in by_country.items():
        global_rules.extend(rules)
        country_dir = OUT_DIR / country
        country_dir.mkdir(parents=True, exist_ok=True)
        out_file = country_dir / "full_block.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(rules, f, ensure_ascii=False, indent=2)
        print(f"  -> 已保存 [{country}] 规则 ({len(rules)} 条) 到 {out_file}")

    global_dir = OUT_DIR / "GLOBAL"
    global_dir.mkdir(parents=True, exist_ok=True)
    global_file = global_dir / "full_block.json"
    with open(global_file, "w", encoding="utf-8") as f:
        json.dump(global_rules, f, ensure_ascii=False, indent=2)
    print(f"  -> 已保存 [GLOBAL] 汇总规则 ({len(global_rules)} 条) 到 {global_file}")

    print("\n=== 第二步：规则订阅转换完成 ===")


if __name__ == "__main__":
    main()
