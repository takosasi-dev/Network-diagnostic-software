#!/usr/bin/env python3
"""LAN内デバイススキャンタブ。自分のIPv4/プレフィックスから対象レンジを決め、並列pingで生きている
ホストを洗い出し、ARPテーブルからMAC、OUIからベンダー名、逆引きでホスト名を補完して一覧にする。

MACベンダー判定は「ローカルOUI辞書 → 当たらなければ api.macvendors.com」の2段構え。
APIは実測で1req/1.2秒だと429を返し、1.5秒空ければ安定して200を返したため、未知のOUIだけを
1.5秒間隔で問い合わせるバックグラウンド処理にしてある(失敗はベンダー欄を空欄のまま残す)。
"""
import bisect
import csv
import ipaddress
import json
import re
import socket
import threading
import tkinter as tk
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from tkinter import ttk

import network_diag as nd
import traffic_monitor as tm

PING_WORKERS = 64
DNS_WORKERS = 16
PING_TIMEOUT_MS = 500
MAX_HOSTS = 1024  # /22相当。これ以上は事故なので弾く
VENDOR_API_INTERVAL_S = 1.5  # 実測: 1.2秒間隔だと429、1.5秒なら200

# 主要ベンダーのOUI(先頭3バイト)。APIが落ちている/レート制限された時のフォールバック兼キャッシュ。
OUI_TABLE = {
    # NEC
    "98F199": "NEC Platforms", "00601D": "NEC", "00004C": "NEC", "44856F": "NEC Platforms",
    "8C56C5": "NEC Platforms", "B0C1A0": "NEC Platforms", "3C0771": "NEC Platforms",
    # Buffalo
    "001601": "Buffalo", "002743": "Buffalo", "106F3F": "Buffalo", "4C0F6E": "Buffalo",
    "B0C745": "Buffalo", "DCFB02": "Buffalo", "9CA3BA": "Buffalo",
    # Apple
    "3C0754": "Apple", "A85C2C": "Apple", "F0DBF8": "Apple", "AC87A3": "Apple",
    "8863DF": "Apple", "D02598": "Apple", "F81EDF": "Apple", "9C207B": "Apple",
    # Intel
    "001B21": "Intel", "3C970E": "Intel", "A0A8CD": "Intel", "8C1645": "Intel",
    "E4A471": "Intel", "94E6F7": "Intel", "6045CB": "Intel",
    # Realtek
    "00E04C": "Realtek", "001E8C": "Realtek", "525400": "QEMU/仮想NIC",
    # TP-Link
    "1C61B4": "TP-Link", "5091E3": "TP-Link", "A42BB0": "TP-Link", "C46E1F": "TP-Link",
    "9C5322": "TP-Link", "EC086B": "TP-Link",
    # ASUS
    "1C872C": "ASUSTek", "2C56DC": "ASUSTek", "AC220B": "ASUSTek", "D850E6": "ASUSTek",
    # Sony
    "FCF152": "Sony", "0013A9": "Sony", "5453ED": "Sony", "78843C": "Sony", "A0E453": "Sony",
    # Nintendo
    "0009BF": "Nintendo", "0017AB": "Nintendo", "58BDA3": "Nintendo", "98B6E9": "Nintendo",
    "E84ECE": "Nintendo", "8CCDE8": "Nintendo",
    # Samsung
    "0012FB": "Samsung", "5CF6DC": "Samsung", "8C7712": "Samsung", "F409D8": "Samsung",
    # Google
    "F4F5D8": "Google", "3C5AB4": "Google", "1CF29A": "Google", "A47733": "Google",
    # Amazon
    "44650D": "Amazon", "F0272D": "Amazon", "68DBF5": "Amazon", "FC65DE": "Amazon",
    # Raspberry Pi
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi", "D83ADD": "Raspberry Pi",
    # その他この家で実際に見かけた/よくある機器
    "30F772": "Hon Hai (Foxconn)", "7C66EF": "Hon Hai (Foxconn)",
    "9CAED3": "Seiko Epson", "A4EE57": "Seiko Epson", "641666": "Seiko Epson",
    "000CE7": "MediaTek", "001132": "Synology", "0011D8": "ASUSTek",
    "00174A": "Sharp", "0025F7": "Sharp", "3C2AF4": "Brother", "008077": "Brother",
    "0080F0": "Panasonic", "04A151": "Panasonic", "001B8B": "Panasonic",
    "001CC0": "Intel", "24418C": "Elecom", "9CB6D0": "Rivet Networks",
}

_ARP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})")

_vendor_cache = {}  # OUI(6桁大文字) -> ベンダー名 or ""(不明として確定済み)


# ---------- ネットワーク処理(GUI非依存) ----------

def ping_once(ip, timeout_ms=PING_TIMEOUT_MS):
    """応答があれば往復時間(ms、<1msは0)、無ければNone。
    Windowsのpingは「宛先ホストに到達できません」も受信1件・損失0%として数えるため、
    損失率ではなく実エコー応答にだけ現れる 'TTL=' の有無で生死を判定する。"""
    try:
        r = nd.run(["ping", "-n", "1", "-w", str(timeout_ms), ip], timeout=timeout_ms / 1000 + 4)
    except Exception:
        return None
    if "TTL=" not in r.stdout:
        return None
    return nd.parse_ping_output(r.stdout).get("avg_ms")


def parse_arp_table(text):
    """arp -a の出力を {ip: 'aa:bb:cc:dd:ee:ff'} へ。日本語/英語どちらの見出しでも動く。"""
    return {ip: mac.replace("-", ":").lower() for ip, mac in _ARP_RE.findall(text)}


def get_arp_table():
    try:
        return parse_arp_table(nd.run(["arp", "-a"], timeout=10).stdout)
    except Exception:
        return {}


def oui_of(mac):
    return re.sub(r"[^0-9A-Fa-f]", "", mac).upper()[:6] if mac else ""


def is_random_mac(mac):
    """ローカル管理アドレス(先頭バイトのbit1が立つ)判定。iOS/Androidのプライバシー機能で
    接続ごとに変わるMACはOUIに意味が無く、APIに聞いても必ず404になるので照会自体を省く。"""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except Exception:
        return False


def vendor_from_table(mac):
    if not mac:
        return ""
    return OUI_TABLE.get(oui_of(mac)) or ("ランダムMAC(端末が秘匿)" if is_random_mac(mac) else "")


def lookup_vendor_api(mac, timeout=6):
    """api.macvendors.com へ問い合わせ。不明(404)は ""、失敗(429/通信断)は None を返す。"""
    try:
        req = urllib.request.Request(f"https://api.macvendors.com/{mac}",
                                     headers={"User-Agent": "network-diag/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace").strip()
    except urllib.error.HTTPError as e:
        return "" if e.code == 404 else None
    except Exception:
        return None


def local_ipv4_network():
    """自分のIPv4アドレスとプレフィックス長から所属ネットワークを返す。取れなければ /24 とみなす。"""
    ip = tm.get_local_ipv4()
    prefix = 24
    try:
        out = nd.ps("Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
                    "Select-Object IPAddress,PrefixLength | ConvertTo-Json -Compress")
        data = json.loads(out) if out else []
        if isinstance(data, dict):
            data = [data]
        for entry in data:
            if entry.get("IPAddress") == ip:
                prefix = int(entry["PrefixLength"])
                break
    except Exception:
        pass
    return ip, ipaddress.ip_network(f"{ip}/{prefix}", strict=False)


def parse_range(text):
    """'192.168.3.0/24' を IPv4Network へ。広すぎるレンジは弾く。"""
    net = ipaddress.ip_network(text.strip(), strict=False)
    if net.version != 4:
        raise ValueError("IPv4のみ対応しています")
    if net.num_addresses > MAX_HOSTS:
        raise ValueError(f"レンジが広すぎます(最大 {MAX_HOSTS} アドレス)")
    return net


# ---------- タブ本体 ----------

class LanScanTab:
    COLUMNS = ("ip", "mac", "vendor", "hostname", "ms", "note")
    HEADERS = ("IPアドレス", "MACアドレス", "ベンダー", "ホスト名", "応答(ms)", "備考")
    WIDTHS = (120, 150, 200, 220, 80, 110)

    def __init__(self, parent, ctx):
        self.ctx = ctx
        self.rows = {}          # ip -> dict(結果1行)
        self._sorted_keys = []  # Treeview挿入位置決め用の int(ip) 昇順リスト
        self._stop = threading.Event()
        self._thread = None
        self._progress = (0, 0)
        self._status_text = ""
        self._poll_job = None
        self.local_ip = None
        self.gateway = None

        top = ttk.Frame(parent, padding=(4, 12))
        top.pack(fill="x")
        ttk.Label(top, text="スキャン範囲").grid(row=0, column=0, padx=(0, 6))
        self.range_var = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(top, textvariable=self.range_var, width=20).grid(row=0, column=1, padx=(0, 8))
        ttk.Button(top, text="↻  自動判定", command=self.autodetect_range).grid(row=0, column=2, padx=(0, 8))
        self.scan_btn = ttk.Button(top, text="▶  スキャン開始", style="Accent.TButton", command=self.start_scan)
        self.scan_btn.grid(row=0, column=3, padx=4)
        self.stop_btn = ttk.Button(top, text="⏹  停止", command=self.stop_scan, state="disabled")
        self.stop_btn.grid(row=0, column=4, padx=4)
        ttk.Button(top, text="⬇  CSVへエクスポート", command=self.export_csv).grid(row=0, column=5, padx=4)

        bar = ttk.Frame(parent, padding=(4, 0))
        bar.pack(fill="x")
        self.progress = ttk.Progressbar(bar, mode="determinate")
        self.progress.pack(side="left", fill="x", expand=True)
        self.status = ttk.Label(bar, text="", width=42, anchor="w")
        self.status.pack(side="left", padx=(10, 0))

        self.tree = ttk.Treeview(parent, columns=self.COLUMNS, show="headings", height=18)
        for col, head, width in zip(self.COLUMNS, self.HEADERS, self.WIDTHS):
            self.tree.heading(col, text=head)
            self.tree.column(col, width=width, anchor="w")
        scroll = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(4, 0), pady=(6, 8))
        scroll.pack(side="right", fill="y", pady=(6, 8))

        self.on_theme_changed()
        self.autodetect_range()

    # ---- テーマ ----

    def on_theme_changed(self):
        # ttkはsv_ttkが自動追従するが、Treeviewのタグ色だけは自前で塗り直す必要がある
        t = self.ctx.theme
        self.tree.tag_configure("gateway", foreground=t["warn"])
        self.tree.tag_configure("self", foreground=t["good"])

    # ---- レンジ ----

    def autodetect_range(self):
        try:
            ip, net = local_ipv4_network()
            self.local_ip = ip
            self.range_var.set(str(net))
            self._set_status(f"自分: {ip}")
        except Exception as e:
            self._set_status(f"自動判定失敗: {e}")

    # ---- スキャン ----

    def start_scan(self):
        if self._thread and self._thread.is_alive():
            return
        try:
            net = parse_range(self.range_var.get())
        except Exception as e:
            self._set_status(f"レンジ不正: {e}")
            return

        self.tree.delete(*self.tree.get_children())
        self.rows.clear()
        self._sorted_keys.clear()
        self._stop.clear()
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self._thread = threading.Thread(target=self._scan_worker, args=(net,), daemon=True)
        self._thread.start()
        self._poll()

    def stop_scan(self):
        self._stop.set()
        self.stop_btn.config(state="disabled")

    def _scan_worker(self, net):
        try:
            self.local_ip = self.local_ip or tm.get_local_ipv4()
        except Exception:
            pass
        self.gateway = nd.get_default_gateway()

        hosts = [str(h) for h in net.hosts()]
        total = len(hosts)
        done = 0
        alive = []

        pool = ThreadPoolExecutor(max_workers=PING_WORKERS)
        futures = {pool.submit(ping_once, ip): ip for ip in hosts}
        try:
            for fut in as_completed(futures):
                if self._stop.is_set():
                    break
                ip = futures[fut]
                done += 1
                self._progress = (done, total)
                self._status_text = f"スキャン中 {done}/{total} … 検出 {len(alive)}台"
                ms = fut.result()
                if ms is not None:
                    alive.append(ip)
                    self._add_row(ip, ms)
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

        if self._stop.is_set():
            self._finish(f"停止しました({len(alive)}台検出)")
            return

        # pingの直後はARPテーブルへの反映にラグがあるので、全部終わってから1回だけ叩く
        self._status_text = f"ARPテーブル取得中 … 検出 {len(alive)}台"
        arp = get_arp_table()
        for ip in alive:
            mac = arp.get(ip, "")
            self._update(ip, mac=mac, vendor=vendor_from_table(mac))

        self._status_text = f"ホスト名を逆引き中 … 検出 {len(alive)}台"
        with ThreadPoolExecutor(max_workers=DNS_WORKERS) as ex:
            for ip, name in zip(alive, ex.map(_reverse_dns, alive)):
                if name:
                    self._update(ip, hostname=name)

        self._lookup_vendors(alive)
        path = self._save_json()
        self._finish(f"完了: {len(alive)}台検出 → {path.name if path else '保存失敗'}")

    def _lookup_vendors(self, alive):
        """OUI辞書で埋まらなかったものだけAPIへ。レート制限回避のため間隔を空けて逐次実行。"""
        pending = []
        for ip in alive:
            mac = self.rows.get(ip, {}).get("mac")
            oui = oui_of(mac)
            if not oui or self.rows[ip].get("vendor"):
                continue
            if oui in _vendor_cache:
                self._update(ip, vendor=_vendor_cache[oui])
            else:
                pending.append((ip, mac, oui))

        for i, (ip, mac, oui) in enumerate(pending):
            if self._stop.is_set():
                return
            self._status_text = f"ベンダー照会中 {i + 1}/{len(pending)}"
            name = lookup_vendor_api(mac)
            if name is None:  # 429など。少し待って1回だけ再試行
                self._stop.wait(3.0)
                name = lookup_vendor_api(mac)
            if name is not None:
                _vendor_cache[oui] = name
                self._update(ip, vendor=name)
            self._stop.wait(VENDOR_API_INTERVAL_S)

    def _reverse_lookup_note(self, ip):
        if ip == self.local_ip:
            return "このPC", "self"
        if ip == self.gateway:
            return "ゲートウェイ", "gateway"
        return "", ""

    # ---- UIスレッドへの反映 ----

    def _add_row(self, ip, ms):
        note, tag = self._reverse_lookup_note(ip)
        self.rows[ip] = {"ip": ip, "mac": "", "vendor": "", "hostname": "", "ms": ms, "note": note}
        key = int(ipaddress.ip_address(ip))
        index = bisect.bisect(self._sorted_keys, key)
        self._sorted_keys.insert(index, key)
        self.ctx.root.after(0, lambda: self.tree.insert(
            "", index, iid=ip, tags=(tag,) if tag else (),
            values=(ip, "", "", "", ms, note)))

    def _update(self, ip, **fields):
        if ip not in self.rows:
            return
        self.rows[ip].update(fields)
        self.ctx.root.after(0, lambda: self._apply_update(ip, fields))

    def _apply_update(self, ip, fields):
        if not self.tree.exists(ip):
            return
        for col, value in fields.items():
            self.tree.set(ip, col, value)

    def _set_status(self, text):
        self._status_text = text
        self.status.config(text=text)

    def _poll(self):
        done, total = self._progress
        self.progress.config(maximum=max(total, 1), value=done)
        self.status.config(text=self._status_text)
        if self._thread and self._thread.is_alive():
            self._poll_job = self.ctx.root.after(200, self._poll)
        else:
            self._poll_job = None
            self.scan_btn.config(state="normal")
            self.stop_btn.config(state="disabled")

    def _finish(self, message):
        self._status_text = message

    # ---- 保存 / エクスポート ----

    def _save_json(self):
        try:
            nd.RESULTS_DIR.mkdir(exist_ok=True)
            path = nd.RESULTS_DIR / f"lanscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            path.write_text(json.dumps({
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "range": self.range_var.get().strip(),
                "local_ip": self.local_ip,
                "gateway": self.gateway,
                "devices": [self.rows[ip] for ip in sorted(self.rows, key=lambda x: int(ipaddress.ip_address(x)))],
            }, ensure_ascii=False, indent=2), encoding="utf-8")
            return path
        except Exception:
            return None

    def export_csv(self):
        if not self.rows:
            self._set_status("エクスポートする結果がありません")
            return
        nd.RESULTS_DIR.mkdir(exist_ok=True)
        path = nd.RESULTS_DIR / f"lanscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(self.HEADERS)
            for ip in sorted(self.rows, key=lambda x: int(ipaddress.ip_address(x))):
                row = self.rows[ip]
                writer.writerow([row[c] for c in self.COLUMNS])
        self._set_status(f"✓ CSV出力: {path.name}")

    def on_close(self):
        self._stop.set()
        if self._poll_job:
            try:
                self.ctx.root.after_cancel(self._poll_job)
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=2)


def _reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ---------- 自己テスト (ネットワーク不要) ----------

def selftest():
    arp = parse_arp_table(
        "\nインターフェイス: 192.168.3.12 --- 0x2\n"
        "  インターネット アドレス 物理アドレス           種類\n"
        "  192.168.3.1           30-f7-72-c9-97-a7     動的\n"
        "  192.168.3.16          9C-AE-D3-D5-EC-56     動的\n"
        "  224.0.0.22            01-00-5e-00-00-16     静的\n"
    )
    assert arp["192.168.3.1"] == "30:f7:72:c9:97:a7", arp
    assert arp["192.168.3.16"] == "9c:ae:d3:d5:ec:56", arp
    assert "192.168.3.12" not in arp, "インターフェイス見出し行をMAC付きエントリと誤認している"

    assert parse_arp_table("no entries here") == {}
    assert oui_of("98:f1:99:8b:66:30") == "98F199"
    assert oui_of("98-F1-99-8B-66-30") == "98F199"
    assert oui_of("") == ""
    assert OUI_TABLE[oui_of("b8:27:eb:11:22:33")] == "Raspberry Pi"
    assert vendor_from_table("b8:27:eb:11:22:33") == "Raspberry Pi"
    assert is_random_mac("7a:1e:bb:16:1d:05") and not is_random_mac("30:f7:72:c9:97:a7")
    assert vendor_from_table("7a:1e:bb:16:1d:05").startswith("ランダムMAC")
    assert vendor_from_table("d8:6b:83:d5:6b:f1") == "", "未知の実MACは空欄のままAPI照会に回す"
    assert vendor_from_table("") == ""

    net = parse_range(" 192.168.3.12/24 ")
    assert str(net) == "192.168.3.0/24", net
    assert len(list(net.hosts())) == 254
    for bad in ("192.168.0.0/16", "::1/128", "not-an-ip"):
        try:
            parse_range(bad)
        except Exception:
            pass
        else:
            raise AssertionError(f"{bad} を弾けていない")

    # 生死判定: 到達不能応答は損失0%で返ってくるので TTL= の有無で切り分けている
    alive_out = ("192.168.3.1 からの応答: バイト数 =32 時間 =5ms TTL=64\n"
                 "    パケット数: 送信 = 1、受信 = 1、損失 = 0 (0% の損失)、\n"
                 "    最小 = 5ms、最大 = 5ms、平均 = 5ms\n")
    unreachable_out = ("192.168.3.12 からの応答: 宛先ホストに到達できません。\n"
                       "    パケット数: 送信 = 1、受信 = 1、損失 = 0 (0% の損失)、\n")
    assert "TTL=" in alive_out and nd.parse_ping_output(alive_out)["avg_ms"] == 5
    assert "TTL=" not in unreachable_out and nd.parse_ping_output(unreachable_out)["loss_pct"] == 0

    print("lanscan selftest: OK")


if __name__ == "__main__":
    import sys

    if "--selftest" in sys.argv:
        selftest()
        sys.exit()

    import sv_ttk

    root = tk.Tk()
    root.title("LAN内デバイススキャン")
    root.geometry("1000x600")
    sv_ttk.set_theme("dark")

    class Ctx:
        pass

    ctx = Ctx()
    ctx.root = root
    ctx.font = "Segoe UI"
    ctx.theme = {"bg": "#1c1c1c", "card_bg": "#2b2b2b", "fg": "#f2f2f2", "muted": "#9d9d9d",
                 "good": "#3fb950", "warn": "#e3b341", "bad": "#f85149",
                 "graph_bg": "#232323", "graph_grid": "#3a3a3a"}
    frame = ttk.Frame(root)
    frame.pack(fill="both", expand=True)
    tab = LanScanTab(frame, ctx)
    root.protocol("WM_DELETE_WINDOW", lambda: (tab.on_close(), root.destroy()))
    root.mainloop()
