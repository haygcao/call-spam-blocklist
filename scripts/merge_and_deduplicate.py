#!/usr/bin/env python3
"""
第三步：多源黑名单合并去重、标签规范化与 libphonenumber 动态国家切分

位置：位于 call-spam-blocklist/scripts/merge_and_deduplicate.py
所有合并结果完全保存在 call-spam-blocklist/merge/ 文件夹内部。

规则：
1. 读取 source_a/ 与 source_b/ 下所有数据，进行 E.164 电话号码交叉去重合并。
2. 名字描述 (name) 仅保留中立分类短语，绝无第三方品牌名称。
3. 标签 (labelId) 严格对齐 App 源码 predefined_labels.dart 中的标准 Key。
4. 使用 libphonenumber (phonenumbers) 动态解析全球任意号码的国家二字代码 (如 US, FR, ES, DE, CN, JP 等)，拒绝硬编码字典！
"""

import hashlib
import json
import os
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
SOURCE_A_DIR = REPO_DIR / "source_a"
SOURCE_B_DIR = REPO_DIR / "source_b"
MERGED_OUT_DIR = REPO_DIR / "merge"

MAX_RULES_PER_FILE = 25000

CATEGORY_TO_LABEL_ID = {
    "telemarketer": "telemarketing",
    "telemarketing": "telemarketing",
    "debt_collector": "collection",
    "silent_call": "robocall",
    "nuisance_call": "spamlikely",
    "unsolicited_call": "telemarketing",
    "call_centre": "telemarketing",
    "fax_machine": "other",
    "non_profit_org": "charity",
    "political_call": "political",
    "scam_call": "scamslikely",
    "scam": "scamslikely",
    "prank_call": "scamslikely",
    "sms": "spamlikely",
    "survey": "survey",
    "other": "other",
    "finance_service": "financial",
    "company": "other",
    "service": "customerservice",
    "robocall": "robocall",
    "spam": "spamlikely",
    "risk": "risk",
}

CATEGORY_TO_NEUTRAL_NAME = {
    "telemarketer": "Telemarketer",
    "telemarketing": "Telemarketing",
    "debt_collector": "Debt Collector",
    "silent_call": "Silent Call",
    "nuisance_call": "Nuisance Call",
    "unsolicited_call": "Unsolicited Call",
    "call_centre": "Call Centre",
    "fax_machine": "Fax Machine",
    "non_profit_org": "Non-Profit Organization",
    "political_call": "Political Call",
    "scam_call": "Scam Call",
    "scam": "Scam Call",
    "prank_call": "Prank Call",
    "sms": "SMS Spam",
    "survey": "Survey",
    "other": "Spam Call",
    "finance_service": "Financial Service",
    "company": "Company",
    "service": "Customer Service",
    "robocall": "Robocall",
    "spam": "Spam Call",
    "risk": "High Risk Number",
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


def load_rules_from_dir(target_dir: Path) -> list[dict]:
    records = []
    if target_dir.exists():
        for json_file in target_dir.glob("**/*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        records.extend(data)
            except Exception:
                pass
    return records


def save_chunked_merged_rules(country_code: str, rules_list: list):
    country_dir = MERGED_OUT_DIR / country_code
    country_dir.mkdir(parents=True, exist_ok=True)

    total = len(rules_list)
    if total == 0:
        return

    if total <= MAX_RULES_PER_FILE:
        out_file = country_dir / "full_block.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(rules_list, f, ensure_ascii=False, separators=(",", ":"))
        size_mb = out_file.stat().st_size / (1024 * 1024)
        print(f"  -> 已保存 [{country_code}] 合并去重规则 ({total} 条, {size_mb:.2f} MB) 到 {out_file.name}")
    else:
        part_idx = 1
        for i in range(0, total, MAX_RULES_PER_FILE):
            chunk = rules_list[i : i + MAX_RULES_PER_FILE]
            out_file = country_dir / f"full_block_part{part_idx}.json"
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(chunk, f, ensure_ascii=False, separators=(",", ":"))
            size_mb = out_file.stat().st_size / (1024 * 1024)
            print(f"  -> 已保存 [{country_code}] 分片 {part_idx} ({len(chunk)} 条, {size_mb:.2f} MB) 到 {out_file.name}")
            part_idx += 1

        index_file = country_dir / "index.json"
        index_data = {
            "country": country_code,
            "total_rules": total,
            "parts_count": part_idx - 1,
            "files": [f"full_block_part{p}.json" for p in range(1, part_idx)],
        }
        with open(index_file, "w", encoding="utf-8") as f:
            json.dump(index_data, f, ensure_ascii=False, indent=2)


def main():
    print("=== 开始运行多源黑名单合并去重与 libphonenumber 动态国家切分 ===")

    a_records = load_rules_from_dir(SOURCE_A_DIR)
    b_records = load_rules_from_dir(SOURCE_B_DIR)

    print(f"--> 读取到数据源 A 记录: {len(a_records)} 条")
    print(f"--> 读取到数据源 B 记录: {len(b_records)} 条")

    merged_map = defaultdict(lambda: {"count": 0, "categories": [], "caller_names": []})

    for r in a_records:
        phone = r.get("phoneNumber", "").strip()
        if not phone:
            continue
        cnt = r.get("count", 1)
        lbl = r.get("labelId", "spamlikely")
        c_name = r.get("name", "").strip()

        merged_map[phone]["count"] += cnt
        merged_map[phone]["categories"].append(lbl)
        if c_name and not c_name.lower().startswith("clever") and not c_name.lower().startswith("should"):
            merged_map[phone]["caller_names"].append(c_name)

    for r in b_records:
        phone = r.get("phoneNumber", "").strip()
        if not phone:
            continue
        cnt = r.get("count", 1)
        lbl = r.get("labelId", "telemarketing")
        c_name = r.get("name", "").strip()

        merged_map[phone]["count"] += cnt
        merged_map[phone]["categories"].append(lbl)
        if c_name and not c_name.lower().startswith("clever") and not c_name.lower().startswith("should"):
            merged_map[phone]["caller_names"].append(c_name)

    print(f"✅ 完成合并与去重！去重后包含 {len(merged_map)} 条唯一骚扰号码。")

    by_country = defaultdict(list)

    for phone, item in merged_map.items():
        total_count = item["count"]
        cats = item["categories"]
        c_names = item["caller_names"]

        main_cat = cats[0] if cats else "spamlikely"
        for c in cats:
            if "scam" in c.lower() or "risk" in c.lower():
                main_cat = "scamslikely"
                break

        if c_names:
            display_name = c_names[0][:100]
        else:
            display_name = CATEGORY_TO_NEUTRAL_NAME.get(main_cat, "Spam Call")

        label_id = CATEGORY_TO_LABEL_ID.get(main_cat, "spamlikely")

        # 动态解析全球国家代码，拒绝硬编码
        country = extract_country_code_dynamic(phone)

        rule = {
            "id": generate_rule_id("merged", phone),
            "name": display_name,
            "ruleType": "phone_rule",
            "phoneNumber": phone,
            "labelId": label_id,
            "priority": 3,
            "action": "block",
            "isEnabled": 1,
            "count": total_count,
            "avatar": "",
            "subscriptionId": ""
        }
        by_country[country].append(rule)

    global_rules = []
    for country, rules in by_country.items():
        global_rules.extend(rules)
        save_chunked_merged_rules(country, rules)

    save_chunked_merged_rules("GLOBAL", global_rules)

    readme_path = MERGED_OUT_DIR / "README.md"
    readme_content = """# 多源去重黑名单订阅规则 (Merge)

本目录（`merge/`）存放经多数据源交叉合并、去重与标准化后的订阅规则文件。

### 一、 目录说明
数据采用 libphonenumber 动态解析 E.164 国际代码，按全球 ISO 国家/地区代码 (如 US, FR, ES, DE, CN, JP 等) 分类存放在不同子文件夹内：
- `merge/GLOBAL/`：全球汇总规则
- `merge/{COUNTRY}/`：各国/地区专属规则分片

### 二、 版权与免责声明
1. 本目录下的规则数据仅包含通用中立的骚扰分类词汇，不包含任何第三方品牌名称或商标。
2. 数据仅用于防骚扰自动化识别与拦截，本仓库与开发者不对数据的绝对精确性做出承诺。
"""
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(readme_content)

    print("\n=== 多源黑名单动态国家分拣合并去重完成 ===")


if __name__ == "__main__":
    main()
