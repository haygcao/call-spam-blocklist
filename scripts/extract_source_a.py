#!/usr/bin/env python3
"""
第二步A：数据源 A 二进制解包、元数据提取与动态国家切分存入 source_a/

位置：位于 call-spam-blocklist/scripts/extract_source_a.py
无需任何硬编码国家列表，采用 phonenumbers (libphonenumber) 动态解析全球任意国家的 ISO 二字代码 (如 US, FR, ES, CN, DE)。
"""

import hashlib
import json
import os
import struct
import sys
from collections import defaultdict
from pathlib import Path

try:
    import phonenumbers
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "phonenumbers"])
    import phonenumbers

SCRIPT_DIR = Path(__file__).parent
REPO_DIR = SCRIPT_DIR.parent
RAW_SOURCES_DIR = REPO_DIR / "raw_sources"
SOURCE_A_DIR = REPO_DIR / "source_a"

MAX_RECORDS_PER_FILE = 25000

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

CATEGORY_TO_NAME = {
    "telemarketer": "Telemarketer",
    "debt_collector": "Debt Collector",
    "silent_call": "Silent Call",
    "nuisance_call": "Nuisance Call",
    "unsolicited_call": "Unsolicited Call",
    "call_centre": "Call Centre",
    "fax_machine": "Fax Machine",
    "non_profit_org": "Non-Profit Organization",
    "political_call": "Political Call",
    "scam_call": "Scam Call",
    "prank_call": "Prank Call",
    "sms": "SMS Spam",
    "survey": "Survey",
    "other": "Spam Call",
    "finance_service": "Financial Service",
    "company": "Company",
    "service": "Customer Service",
    "robocall": "Robocall",
}

CATEGORY_TO_LABEL_ID = {
    "telemarketer": "telemarketing",
    "debt_collector": "collection",
    "silent_call": "robocall",
    "nuisance_call": "spamlikely",
    "unsolicited_call": "telemarketing",
    "call_centre": "telemarketing",
    "fax_machine": "other",
    "non_profit_org": "charity",
    "political_call": "political",
    "scam_call": "scamslikely",
    "prank_call": "scamslikely",
    "sms": "spamlikely",
    "survey": "survey",
    "other": "other",
    "finance_service": "financial",
    "company": "other",
    "service": "customerservice",
    "robocall": "robocall",
}


def generate_rule_id(prefix: str, value: str) -> str:
    raw = f"{prefix}:{value}".encode("utf-8")
    return hashlib.md5(raw).hexdigest()


def extract_country_code_dynamic(e164_str: str) -> str:
    """使用 libphonenumber 动态解析 E.164 号码对应的全球 ISO 二字国家代码 (如 US, FR, ES, CN, DE)"""
    try:
        phone_raw = e164_str if e164_str.startswith("+") else f"+{e164_str}"
        parsed = phonenumbers.parse(phone_raw, None)
        region = phonenumbers.region_code_for_number(parsed)
        if region and len(region) == 2:
            return region.upper()
    except Exception:
        pass
    return "GLOBAL"


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


def save_chunked_rules(country_code: str, rules_list: list):
    country_dir = SOURCE_A_DIR / country_code
    country_dir.mkdir(parents=True, exist_ok=True)

    total = len(rules_list)
    if total == 0:
        return

    if total <= MAX_RECORDS_PER_FILE:
        out_file = country_dir / "full_block.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(rules_list, f, ensure_ascii=False, separators=(",", ":"))
        print(f"  -> 已保存 [source_a/{country_code}] 规则 ({total} 条) 到 {out_file.name}")
    else:
        part_idx = 1
        for i in range(0, total, MAX_RECORDS_PER_FILE):
            chunk = rules_list[i : i + MAX_RECORDS_PER_FILE]
            out_file = country_dir / f"full_block_part{part_idx}.json"
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(chunk, f, ensure_ascii=False, separators=(",", ":"))
            print(f"  -> 已保存 [source_a/{country_code}] 分片 {part_idx} ({len(chunk)} 条) 到 {out_file.name}")
            part_idx += 1


def main():
    print("=== 开始使用 libphonenumber 动态解析国家代码存入 source_a/ ===")
    if not RAW_SOURCES_DIR.exists():
        print(f"❌ 原始数据库目录不存在: {RAW_SOURCES_DIR}，请先执行第一步。")
        sys.exit(1)

    global_data = {}

    for dat_file in RAW_SOURCES_DIR.glob("data_slice_*.dat"):
        parse_data_slice(dat_file, global_data, "MTZF")

    update_bin = RAW_SOURCES_DIR / "data_slice_downloaded_update.bin"
    if update_bin.exists():
        parse_data_slice(update_bin, global_data, "MTZD")

    by_country = defaultdict(list)

    for tlf, meta in global_data.items():
        e164_phone = f"+{tlf}"
        cat_tag = meta["category"]
        neg_count = meta["negative"]

        label_id = CATEGORY_TO_LABEL_ID.get(cat_tag, "spamlikely")
        display_name = CATEGORY_TO_NAME.get(cat_tag, "Spam Call")
        # 动态解析国家/地区代码
        country = extract_country_code_dynamic(e164_phone)

        rule = {
            "id": generate_rule_id("source_a", e164_phone),
            "name": display_name,
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
        save_chunked_rules(country, rules)

    save_chunked_rules("GLOBAL", global_rules)
    print("=== 数据源 A 动态国家分拣完成 ===")


if __name__ == "__main__":
    main()
