#!/usr/bin/env python3
"""
冒險之歌網站產生器（加密版）。

讀 Obsidian 的「冒險之歌」資料夾（封面.png、頁/*.md 與同名 png），
把文字和圖片用密碼加密後寫進這個 repo。repo 裡只有亂碼，瀏覽器輸入密碼才解得開。

密碼存在 macOS 鑰匙圈（服務名稱 adventure-song），第一次設定：
    security add-generic-password -s adventure-song -a charles -w
（-w 後面不接密碼，它會讓你自己輸入兩次，密碼不會留在指令紀錄裡）

用法：python3 build.py
"""

import base64
import hashlib
import html
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SRC = Path.home() / "Documents/Obsidian/自我成長/RPG世界/冒險之歌"
OUT = Path(__file__).resolve().parent
# 明文的中間檔放在 repo 外面，不可能被 commit 進去
CACHE = OUT.parent / ".adventure-song-cache"
TEMPLATE = OUT / "template.html"
SALT_FILE = OUT / "salt.txt"
KEYCHAIN_SERVICE = "adventure-song"
PBKDF2_ROUNDS = 600_000   # 瀏覽器端要用同一個數字，改了要一起改 template.html

META_KEYS = {"編號": "id", "時間地點": "when", "章節": "chapter"}


# ---------- 讀 Obsidian ----------

def inline(text: str) -> str:
    """跳脫 HTML，再處理 Obsidian 連結與行內程式碼。"""
    text = html.escape(text)
    text = re.sub(r"\[\[[^\]|]*\|([^\]]*)\]\]", r"\1", text)   # [[目標|顯示]] → 顯示
    text = re.sub(r"\[\[([^\]]*)\]\]", r"\1", text)            # [[目標]] → 目標
    text = re.sub(r"`([^`]*)`", r"<code>\1</code>", text)
    return text


def body_to_html(lines: list[str]) -> str:
    """只處理頁面實際用到的語法：## 小節、> 引言、- 清單、段落。"""
    out, para, quote, items = [], [], [], []

    def flush():
        if para:
            out.append(f"<p>{inline(' '.join(para))}</p>")
            para.clear()
        if quote:
            out.append(f"<blockquote>{inline(' '.join(quote))}</blockquote>")
            quote.clear()
        if items:
            out.append("<ul>" + "".join(f"<li>{inline(i)}</li>" for i in items) + "</ul>")
            items.clear()

    for line in lines:
        s = line.strip()
        if not s:
            flush()
        elif re.match(r"#{2,6} ", s):
            flush()
            out.append(f"<h3>{inline(s.lstrip('#').strip())}</h3>")
        elif s.startswith("> "):
            if para or items:
                flush()
            quote.append(s[2:])
        elif s.startswith("- "):
            if para or quote:
                flush()
            items.append(s[2:])
        else:
            if quote or items:
                flush()
            para.append(s)
    flush()
    return "\n".join(out)


def parse_page(md: Path) -> dict:
    lines = md.read_text(encoding="utf-8").splitlines()
    page = {"title": None, "id": None, "when": "", "chapter": ""}
    body = []
    for line in lines:
        s = line.strip()
        if page["title"] is None and s.startswith("# "):
            page["title"] = s[2:].strip()
            continue
        m = re.match(r"^> (編號|時間地點|章節)：(.*)$", s)
        if m:
            page[META_KEYS[m.group(1)]] = m.group(2).strip()
            continue
        m = re.fullmatch(r"!\[\[([^\]|]+\.png)(?:\|[^\]]*)?\]\]", s)
        if m:
            page.setdefault("embeds", []).append(m.group(1))
            continue
        body.append(line)

    if not page["title"] or not page["id"]:
        sys.exit(f"缺標題或編號：{md.name}")
    if not re.fullmatch(r"\d{4}", page["id"]):
        sys.exit(f"編號不是四位數：{md.name} → {page['id']}")

    date, _, place = page["when"].partition("，")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        sys.exit(f"時間地點開頭不是日期：{md.name} → {page['when']}")
    page["date"], page["place"] = date, place.strip()
    del page["when"]
    page["body"] = body_to_html(body)
    return page


def to_jpg(src: Path, dst: Path, width: int):
    """用 macOS 內建的 sips 轉成 JPEG，網頁載入比 PNG 快很多。"""
    if dst.exists() and dst.stat().st_mtime >= src.stat().st_mtime:
        return
    subprocess.run(
        ["sips", "-s", "format", "jpeg", "-s", "formatOptions", "82",
         "--resampleWidth", str(width), str(src), "--out", str(dst)],
        check=True, capture_output=True, timeout=60,
    )
    if not dst.exists():
        sys.exit(f"圖片轉檔失敗：{src}")


# ---------- 加密 ----------

def read_password() -> str:
    r = subprocess.run(
        ["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"],
        capture_output=True, text=True, timeout=30,
    )
    if r.returncode != 0 or not r.stdout.strip():
        sys.exit("鑰匙圈裡沒有密碼。先執行：security add-generic-password -s adventure-song -a charles -w")
    return r.stdout.rstrip("\n")


def load_salt() -> bytes:
    if not SALT_FILE.exists():
        SALT_FILE.write_text(base64.b64encode(os.urandom(16)).decode() + "\n")
    return base64.b64decode(SALT_FILE.read_text().strip())


def encrypt_if_changed(plain: bytes, dst: Path, key: bytes, cache: dict):
    """
    只有內容變了才重新加密。加密每次都會產生不同的亂碼，
    全部重做的話 git 會把每張圖都存一份新的，repo 很快就會變胖。
    """
    fingerprint = hashlib.sha256(key + plain).hexdigest()
    name = dst.relative_to(OUT).as_posix()
    if dst.exists() and cache.get(name) == fingerprint:
        return False
    iv = os.urandom(12)
    dst.write_bytes(iv + AESGCM(key).encrypt(iv, plain, None))
    cache[name] = fingerprint
    return True


def main():
    if not SRC.exists():
        sys.exit(f"找不到來源資料夾（Obsidian 路徑或 iCloud 同步）：{SRC}")
    CACHE.mkdir(exist_ok=True)
    (OUT / "img").mkdir(exist_ok=True)

    salt = load_salt()
    key = hashlib.pbkdf2_hmac("sha256", read_password().encode("utf-8"), salt, PBKDF2_ROUNDS)
    cache_file = CACHE / "fingerprints.json"
    cache = json.loads(cache_file.read_text()) if cache_file.exists() else {}

    pages = []
    for md in sorted((SRC / "頁").glob("*.md")):
        page = parse_page(md)
        png = md.with_suffix(".png")
        if not png.exists():
            sys.exit(f"缺圖：{png.name}")
        to_jpg(png, CACHE / f"{page['id']}.jpg", 1024)
        page["img"] = f"img/{page['id']}.enc"
        # 主圖以外、頁面裡另外嵌入的圖，依出現順序當第二張、第三張
        page["extra"] = []
        for n, name in enumerate([e for e in page.pop("embeds", []) if e != png.name], start=2):
            extra_png = md.parent / name
            if not extra_png.exists():
                sys.exit(f"缺圖：{name}（{md.name} 裡嵌入的）")
            to_jpg(extra_png, CACHE / f"{page['id']}-{n}.jpg", 1024)
            page["extra"].append(f"img/{page['id']}-{n}.enc")
        pages.append(page)

    ids = [p["id"] for p in pages]
    if len(ids) != len(set(ids)):
        sys.exit(f"編號重複：{ids}")
    pages.sort(key=lambda p: (p["date"], p["id"]))
    to_jpg(SRC / "封面.png", CACHE / "cover.jpg", 1024)

    changed = []
    for p in pages:
        for rel in [p["img"]] + p["extra"]:
            jpg = CACHE / (Path(rel).stem + ".jpg")
            if encrypt_if_changed(jpg.read_bytes(), OUT / rel, key, cache):
                changed.append(rel)
    if encrypt_if_changed((CACHE / "cover.jpg").read_bytes(), OUT / "img/cover.enc", key, cache):
        changed.append("img/cover.enc")
    data = json.dumps(pages, ensure_ascii=False).encode("utf-8")
    if encrypt_if_changed(data, OUT / "data.enc", key, cache):
        changed.append("data.enc")

    # 已經不在來源裡的頁面，把加密檔刪掉
    keep = {r for p in pages for r in [p["img"]] + p["extra"]} | {"img/cover.enc"}
    for f in (OUT / "img").glob("*.enc"):
        rel = f"img/{f.name}"
        if rel not in keep:
            f.unlink()
            cache.pop(rel, None)
            changed.append(f"刪除 {rel}")

    cache_file.write_text(json.dumps(cache, indent=1))
    page_html = (TEMPLATE.read_text(encoding="utf-8")
                 .replace("__SALT__", base64.b64encode(salt).decode())
                 .replace("__ROUNDS__", str(PBKDF2_ROUNDS)))
    (OUT / "index.html").write_text(page_html, encoding="utf-8")

    print(f"完成：{len(pages)} 頁")
    print("有變動：" + ("、".join(changed) if changed else "沒有"))


if __name__ == "__main__":
    main()
