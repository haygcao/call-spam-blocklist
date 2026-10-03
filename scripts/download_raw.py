#!/usr/bin/env python3
"""
第一步：原始二进制数据库拉取脚本

位置：位于 call-spam-blocklist/scripts/download_raw.py
功能：原封不动拉取原始二进制数据库，保存于 raw_sources/ 目录下。
"""

import gzip
import os
import sys
import urllib.request
import zipfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
REPO_DIR = SCRIPT_DIR.parent
RAW_SOURCES_DIR = REPO_DIR / "raw_sources"

APK_URL = "https://web.archive.org/web/20211003104644if_/http://download.shouldianswer.net/download/shouldianswer_obsolete.apk"
UPDATE_BIN_URL = "https://srv1.shouldianswer.net/srv2/get-database2?v=6&appver=11014&dbver=1381"


def download_raw_database():
    RAW_SOURCES_DIR.mkdir(parents=True, exist_ok=True)
    headers = {"User-Agent": "Mozilla/5.0"}

    apk_path = RAW_SOURCES_DIR / "shouldianswer_obsolete.apk"
    if not apk_path.exists():
        print("--> 1. 正在拉取原始 APK 基础数据库...")
        try:
            req = urllib.request.Request(APK_URL, headers=headers)
            with urllib.request.urlopen(req) as resp, open(apk_path, "wb") as f:
                f.write(resp.read())
            print("    ✅ 原始 APK 下载完成。")
        except Exception as e:
            print(f"    ❌ 下载 APK 失败: {e}")

    if apk_path.exists():
        print("--> 2. 正在提取原始 data_slice_*.dat 静态数据库文件...")
        try:
            with zipfile.ZipFile(apk_path, "r") as z:
                for file_info in z.infolist():
                    if "data_slice_" in file_info.filename and file_info.filename.endswith(".dat"):
                        file_info.filename = os.path.basename(file_info.filename)
                        z.extract(file_info, RAW_SOURCES_DIR)
            print("    ✅ 原始静态二进制库文件提取完成。")
        except Exception as e:
            print(f"    ❌ 提取原始静态库失败: {e}")

    update_gz_path = RAW_SOURCES_DIR / "update.bin.gz"
    update_bin_path = RAW_SOURCES_DIR / "data_slice_downloaded_update.bin"

    print("--> 3. 正在拉取原始动态增量包 data_slice_downloaded_update.bin...")
    try:
        req = urllib.request.Request(UPDATE_BIN_URL, headers=headers)
        with urllib.request.urlopen(req) as resp, open(update_gz_path, "wb") as f:
            f.write(resp.read())

        if update_gz_path.exists():
            with gzip.open(update_gz_path, "rb") as f_in, open(update_bin_path, "wb") as f_out:
                f_out.write(f_in.read())
            os.remove(update_gz_path)
        print("    ✅ 原始动态增量二进制包拉取成功。")
    except Exception as e:
        print(f"    ❌ 拉取动态增量包失败: {e}")


def main():
    print("=== 第一步：拉取并保存原封不动的原始数据库 ===")
    download_raw_database()
    print("=== 原始数据库同步完成，已存入 raw_sources/ 目录 ===")


if __name__ == "__main__":
    main()
