#!/usr/bin/env python3
"""
第二步B：数据源 B 跨地区 API 完整数据抓取与 libphonenumber 动态国家切分存入 source_b/

位置：位于 call-spam-blocklist/scripts/fetch_source_b.py
采用 phonenumbers 动态解析 E.164 国际代码，无任何硬编码国家列表。
"""

import hashlib
import json
import sys
import urllib.request
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
SOURCE_B_DIR = REPO_DIR / "source_b"

CLEVERDIALER_BASE_URL = "https://ws.cleverdialer.com/api/1.3/spam"
AUTH_HEADER = "Basic Y2RhbmQ6djFna3dpamhzbmdyZ29pNjh6c2Z3Mzh2"
REGIONS = ["ES", "DE", "UK", "US", "FR", "IT", "AT"]


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


def map_category_to_label_id(cat_tag: str) -> str:
    cat = (cat_tag or "").lower()
    if "scam" in cat or "prank" in cat:
        return "scamslikely"
    if "robo" in cat or "silent" in cat:
        return "robocall"
    if "telemarket" in cat or "survey" in cat or "sales" in cat:
        return "telemarketing"
    if "debt" in cat:
        return "collection"
    return "spamlikely"


def fetch_source_b_by_region(region: str) -> list[dict]:
    url = f"{CLEVERDIALER_BASE_URL}?region={region}"
    print(f"--> [数据源 B] 正在抓取地区 [{region}] 数据...")

    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "Authorization": AUTH_HEADER,
            "User-Agent": "Mozilla/5.0",
        },
    )

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if isinstance(data, list):
                print(f"    ✅ 成功获取 [{region}] {len(data)} 条数据")
                return data
    except Exception as e:
        print(f"    ❌ 抓取 [{region}] 失败: {e}")
    return []


def main():
    print("=== 开始全量抓取数据源 B 并使用 libphonenumber 动态切分存入 source_b/ ===")
    seen_phones = set()
    by_country = defaultdict(list)

    for region in REGIONS:
        items = fetch_source_b_by_region(region)
        for item in items:
            phone = item.get("normalizedPhone") or item.get("phone")
            if not phone:
                continue

            clean_phone = phone.strip()
            if not clean_phone.startswith("+"):
                clean_phone = f"+{clean_phone}"

            if clean_phone in seen_phones:
                continue
            seen_phones.add(clean_phone)

            caller_name = item.get("callerName") or item.get("name") or ""
            if caller_name and (caller_name.lower().startswith("clever") or caller_name.lower().startswith("should")):
                caller_name = ""

            category = item.get("spamCategory") or item.get("category") or "telemarketing"
            searches = item.get("searches") or item.get("ratings") or 1

            label_id = map_category_to_label_id(category)
            display_name = caller_name if caller_name else "Telemarketing"

            # 动态解析国家代码，拒绝硬编码
            country = extract_country_code_dynamic(clean_phone)

            rule = {
                "id": generate_rule_id("source_b", clean_phone),
                "name": display_name,
                "ruleType": "phone_rule",
                "phoneNumber": clean_phone,
                "labelId": label_id,
                "priority": 3,
                "action": "block",
                "isEnabled": 1,
                "count": searches,
            }
            by_country[country].append(rule)

    global_rules = []
    for country, rules in by_country.items():
        global_rules.extend(rules)
        country_dir = SOURCE_B_DIR / country
        country_dir.mkdir(parents=True, exist_ok=True)
        out_file = country_dir / "full_block.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(rules, f, ensure_ascii=False, separators=(",", ":"))
        print(f"  -> 已保存 [source_b/{country}] 规则 ({len(rules)} 条) 到 {out_file.name}")

    global_dir = SOURCE_B_DIR / "GLOBAL"
    global_dir.mkdir(parents=True, exist_ok=True)
    global_file = global_dir / "full_block.json"
    with open(global_file, "w", encoding="utf-8") as f:
        json.dump(global_rules, f, ensure_ascii=False, separators=(",", ":"))

    print(f"\n[✅] 数据源 B 抓取与动态国家切分完成！保存于 {SOURCE_B_DIR}")


if __name__ == "__main__":
    main()
