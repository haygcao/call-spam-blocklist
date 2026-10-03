#!/usr/bin/env python3
"""
全新独立脚本：CleverDialer 多地区黑名单元数据抓取

不修改任何原始文件，独立输出至 cleverdialer_full_metadata.json。
"""

import json
import urllib.request
from pathlib import Path

CLEVERDIALER_BASE_URL = "https://ws.cleverdialer.com/api/1.3/spam"
AUTH_HEADER = "Basic Y2RhbmQ6djFna3dpamhzbmdyZ29pNjh6c2Z3Mzh2"
REGIONS = ["ES", "DE", "UK", "US", "FR", "IT", "AT"]

OUTPUT_FILE = Path(__file__).parent.parent / "cleverdialer_full_metadata.json"


def fetch_cleverdialer_by_region(region: str) -> list[dict]:
    url = f"{CLEVERDIALER_BASE_URL}?region={region}"
    print(f"--> [CleverDialer] 正在抓取地区 [{region}] 数据...")

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
    print("=== 开始全量抓取 CleverDialer 多地区黑名单元数据 ===")
    all_records = []
    seen_phones = set()

    for region in REGIONS:
        items = fetch_cleverdialer_by_region(region)
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
            category = item.get("spamCategory") or item.get("category") or "telemarketing"
            searches = item.get("searches") or item.get("ratings") or 1

            all_records.append({
                "phoneNumber": clean_phone,
                "callerName": caller_name,
                "category": category,
                "searches": searches,
                "region": region
            })

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(all_records, f, ensure_ascii=False, indent=2)

    print(f"\n[✅] CleverDialer 抓取完成！全量提取 {len(all_records)} 条黑名单，保存于 {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
