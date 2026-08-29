#!/usr/bin/env python3
"""経路の地理可視化タブ。tracerouteの各ホップをipinfo.ioで測位し、自前描画の世界地図にプロットする。

地図は tk.Canvas への完全自前描画。外部ライブラリ・画像・オンラインタイルを一切使わないので
単一exeにそのまま同梱できる。輪郭データは Natural Earth 1:50m land を Douglas-Peucker で
簡略化して文字列として埋め込んだもの(90環/約2300点、日本周辺だけ細かめの許容誤差で残してある)。

目玉は「理論最小RTT」列。起点からそのホップまでの累計大圏距離を、光ファイバ内の光速
(真空の約2/3。コア屈折率≈1.47の群速度)で往復するのに物理的に最低限かかる時間として出し、
実測RTTとの差を取る。差が小さければその遅延は距離由来、大きければ機器の処理/キューイング由来。
差が負になるホップは物理的にありえないので、地理DBが嘘をついている(anycast等)証拠として扱う。
"""
import http.client
import ipaddress
import json
import math
import socket
import threading
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from tkinter import ttk

import network_diag as nd

HOSTS = ["1.1.1.1", "8.8.8.8", "github.com", "www.google.com", "www.wikipedia.org", "www.debian.org"]
DEFAULT_HOST = "1.1.1.1"
DEFAULT_MAX_HOPS = 15

EARTH_R_KM = 6371.0088
LIGHT_KM_S = 299792.458
FIBER_FACTOR = 2 / 3          # 光ファイバの群速度は真空中の約68%(コア屈折率≈1.47)
FIBER_KM_S = LIGHT_KM_S * FIBER_FACTOR

WORLD = (-180.0, -90.0, 180.0, 90.0)
MIN_SPAN_DEG = 2.0            # 全ホップが同一都市に測位されても点が潰れないよう確保する最小の視野
SAME_PLACE_DEG = 0.02         # これ以下の差は同一地点とみなして1つのマーカーにまとめる
OVER_WARN_MS = 10.0           # 理論最小との差: これ以下なら距離由来
OVER_BAD_MS = 40.0            # これを超えると機器由来が支配的


# ---------- 地理計算 ----------

def haversine_km(lat1, lon1, lat2, lon2):
    """2点間の大圏距離(km)。"""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_R_KM * math.asin(min(1.0, math.sqrt(a)))


def min_rtt_ms(km):
    """km を光ファイバ内で往復するのに物理的に最低限かかる時間(ms)。約 1ms / 100km。"""
    return km * 2 / FIBER_KM_S * 1000


def projector(view, w, h):
    """等距円筒図法。view=(lon0,lat0,lon1,lat1) が w×h に収まるよう等倍(緯度1度と経度1度が同じpx)。

    view=WORLD かつ w:h=2:1 のとき x=(lon+180)/360*w, y=(90-lat)/180*h に一致する。
    """
    lon0, lat0, lon1, lat1 = view
    scale = min(w / max(lon1 - lon0, 1e-9), h / max(lat1 - lat0, 1e-9))
    cx, cy = (lon0 + lon1) / 2, (lat0 + lat1) / 2

    def proj(lon, lat):
        return w / 2 + (lon - cx) * scale, h / 2 - (lat - cy) * scale

    proj.scale = scale
    proj.inverse = lambda x, y: (cx + (x - w / 2) / scale, cy - (y - h / 2) / scale)
    return proj


def auto_view(points, pad=0.18, min_span=MIN_SPAN_DEG):
    """(lon,lat)群が全部収まるビュー。1点しかない/全部同一地点でも min_span 度の幅を確保する。"""
    if not points:
        return WORLD
    lons = sorted(p[0] for p in points)
    lats = sorted(p[1] for p in points)
    cx, cy = (lons[0] + lons[-1]) / 2, (lats[0] + lats[-1]) / 2
    sw = max(lons[-1] - lons[0], min_span) * (1 + 2 * pad)
    sh = max(lats[-1] - lats[0], min_span) * (1 + 2 * pad)
    return (cx - sw / 2, cy - sh / 2, cx + sw / 2, cy + sh / 2)


def zoom_view(view, factor, focus=None):
    """factor<1 で拡大。focus=(lon,lat) を固定点にする(省略時は中心)。"""
    lon0, lat0, lon1, lat1 = view
    fx, fy = focus if focus else ((lon0 + lon1) / 2, (lat0 + lat1) / 2)
    return (fx + (lon0 - fx) * factor, fy + (lat0 - fy) * factor,
            fx + (lon1 - fx) * factor, fy + (lat1 - fy) * factor)


# ---------- IP測位 (ipinfo.io) ----------

_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def is_private(ip):
    """測位を問い合わせても意味がないIPか。CGNAT(100.64/10)を明示的に含めているのは、
    IPoE(MAP-E/DS-Lite)環境だと宅内〜ISP境界のホップが 100.x.x.x で出てくるため
    (Python版によっては ipaddress.is_private が False を返すので自前で判定する)。"""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (a.is_private or a.is_loopback or a.is_link_local
            or (a.version == 4 and a in _CGNAT))


def private_label(ip):
    a = ipaddress.ip_address(ip)
    if a.version == 4 and a in _CGNAT:
        return "ISP内部 (CGNAT)"
    if a.is_link_local:
        return "リンクローカル"
    return "宅内"


def parse_loc(loc):
    """ipinfo の "35.6895,139.6917" -> (lat, lon)。壊れていれば (None, None)。"""
    try:
        lat, lon = (float(v) for v in loc.split(","))
    except (AttributeError, ValueError, TypeError):
        return None, None
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return None, None
    return lat, lon


def lookup_geo(ip=None, _cache={}):
    """ipinfo.io から緯度経度つきのIP情報を取る。ip=None なら自分のグローバルIP。

    nd.lookup_ip_info と同じ流儀(http.client / プライベートIPは問い合わせない / 結果をキャッシュ)
    だが、あちらは loc フィールドを捨てるので別に実装している。
    -> {"ip","org","city","region","country","lat","lon"} または None
    """
    if ip is not None and is_private(ip):
        return None
    key = ip or "__self__"
    if key in _cache:
        return _cache[key]
    info = None
    try:
        conn = http.client.HTTPSConnection("ipinfo.io", timeout=6)
        conn.request("GET", f"/{ip}/json" if ip else "/json",
                     headers={"User-Agent": "network-diag/1.0"})
        data = json.loads(conn.getresponse().read())
        conn.close()
        if not data.get("bogon"):
            lat, lon = parse_loc(data.get("loc"))
            info = {"ip": data.get("ip"), "org": data.get("org") or "", "city": data.get("city") or "",
                    "region": data.get("region") or "", "country": data.get("country") or "",
                    "lat": lat, "lon": lon}
    except Exception:
        info = None
    _cache[key] = info
    return info


def resolve_ipv4(host):
    """IPv4に固定して名前解決する。

    nd.parse_tracert_output のIP抽出はIPv4専用の正規表現なので、AAAAを持つホスト
    (実測: www.debian.org)をそのまま渡すと tracert がIPv6経路を辿り、RTTは出るのに
    全ホップのIPが None になって測位が一切できなくなる。
    """
    return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]


def traceroute(host, max_hops):
    """nd.measure_traceroute は内部タイムアウトが30秒固定で、無応答ホップが続くと
    15ホップの計測が終わらずエラーになる。その場合だけ長めのタイムアウトで直接叩き直す。"""
    r = nd.measure_traceroute(host, max_hops)
    if isinstance(r, dict) and "error" in r:
        try:
            out = nd.run(["tracert", "-d", "-h", str(max_hops), "-w", "800", host],
                         timeout=max_hops * 4 + 20)
            return nd.parse_tracert_output(out.stdout, max_hops)
        except Exception as e:
            return {"error": str(e)}
    return r


# ---------- 経路の組み立て ----------

def build_route(hops, geo):
    """traceroute結果 + {ip: geo} から表示用の行を作る。

    累計距離は「測位できたホップだけを順に結んだ折れ線」の長さ。測位できないホップは
    区間を持たず、次に測位できたホップが直前の測位済みホップから直接つながる。
    """
    rows = []
    prev = None
    cum = 0.0
    for h in hops:
        ip = h.get("ip")
        g = geo.get(ip) if ip else None
        row = {"hop": h["hop"], "ip": ip, "avg_ms": h.get("avg_ms"),
               "timeout": bool(h.get("timeout")),
               "private": bool(ip) and is_private(ip),
               "org": (g or {}).get("org", ""), "city": (g or {}).get("city", ""),
               "country": (g or {}).get("country", ""),
               "lat": (g or {}).get("lat"), "lon": (g or {}).get("lon"),
               "seg_km": None, "cum_km": None, "min_ms": None, "over_ms": None}
        if row["lat"] is not None and row["lon"] is not None:
            if prev is not None:
                row["seg_km"] = haversine_km(prev[0], prev[1], row["lat"], row["lon"])
                cum += row["seg_km"]
            row["cum_km"] = cum
            row["min_ms"] = min_rtt_ms(cum)
            if row["avg_ms"] is not None:
                row["over_ms"] = row["avg_ms"] - row["min_ms"]
            prev = (row["lat"], row["lon"])
        rows.append(row)
    return rows


def cluster_rows(rows, eps=SAME_PLACE_DEG):
    """同じ座標に測位されたホップを1つのマーカーにまとめる。

    自動ズームだけでは救えないケースへの対策: 国内経路だと複数ホップが同一の都市重心
    (例: 全部 35.6895,139.6917)に測位されるので、拡大しても文字通り同じ画素に重なる。
    -> [{"lon","lat","hops":[番号...],"rows":[...]}]  出現順。
    """
    out = []
    for r in rows:
        if r["lat"] is None:
            continue
        for c in out:
            if abs(c["lat"] - r["lat"]) <= eps and abs(c["lon"] - r["lon"]) <= eps:
                c["hops"].append(r["hop"])
                c["rows"].append(r)
                break
        else:
            out.append({"lat": r["lat"], "lon": r["lon"], "hops": [r["hop"]], "rows": [r]})
    return out


def format_hop_numbers(nums):
    """[2,3,4,7] -> "2-4,7" """
    nums = sorted(set(nums))
    parts, start, prev = [], None, None
    for n in nums + [None]:
        if start is None:
            start = prev = n
            continue
        if n is not None and n == prev + 1:
            prev = n
            continue
        parts.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = n
    return ",".join(parts)


def over_tag(over_ms):
    if over_ms is None:
        return ""
    if over_ms < 0:
        return "bogus"          # 光より速い = 測位が嘘
    if over_ms <= OVER_WARN_MS:
        return "good"
    return "warn" if over_ms <= OVER_BAD_MS else "bad"


def _hex_to_rgb(c):
    c = c.lstrip("#")
    return tuple(int(c[i:i + 2], 16) for i in (0, 2, 4))


def mix(c1, c2, f):
    """色を f の比で混ぜる(f=0でc1)。テーマ色から地図用の中間色を作るのに使う。"""
    a, b = _hex_to_rgb(c1), _hex_to_rgb(c2)
    return "#%02x%02x%02x" % tuple(round(x + (y - x) * f) for x, y in zip(a, b))


# ---------- タブ本体 ----------

COLUMNS = [
    ("hop", "#", 30), ("ip", "IP", 108), ("org", "組織", 120), ("place", "都市 / 国", 96),
    ("rtt", "実測", 50), ("seg", "区間km", 56), ("cum", "累計km", 56),
    ("minrtt", "理論最小", 58), ("over", "超過", 52),
]


class GeoMapTab:
    def __init__(self, parent, ctx):
        self.ctx = ctx
        self.rows = []
        self.clusters = []
        self.origin = None
        self.view = WORLD
        self.auto = True
        self.status_kind = "muted"
        self.sel_hop = None
        self._drag = None
        self._stop = threading.Event()
        self._thread = None

        top = ttk.Frame(parent, padding=(4, 12, 4, 4))
        top.pack(fill="x")
        ttk.Label(top, text="対象ホスト").pack(side="left", padx=(0, 6))
        self.host_var = tk.StringVar(value=DEFAULT_HOST)
        ttk.Combobox(top, textvariable=self.host_var, values=HOSTS, width=22).pack(side="left", padx=(0, 12))
        ttk.Label(top, text="最大ホップ").pack(side="left", padx=(0, 6))
        self.hops_var = tk.IntVar(value=DEFAULT_MAX_HOPS)
        ttk.Spinbox(top, from_=3, to=30, textvariable=self.hops_var, width=5).pack(side="left", padx=(0, 12))
        self.run_btn = ttk.Button(top, text="▶  経路を測位", style="Accent.TButton", command=self.start)
        self.run_btn.pack(side="left", padx=4)
        ttk.Button(top, text="⊕", width=3, command=lambda: self.zoom(0.6)).pack(side="left", padx=(16, 2))
        ttk.Button(top, text="⊖", width=3, command=lambda: self.zoom(1 / 0.6)).pack(side="left", padx=2)
        ttk.Button(top, text="経路に合わせる", command=self.fit).pack(side="left", padx=(8, 2))
        ttk.Button(top, text="世界全体", command=self.reset_view).pack(side="left", padx=2)

        self.status = ttk.Label(parent, text="対象ホストを選んで「経路を測位」", padding=(6, 4))
        self.status.pack(fill="x")

        pane = ttk.PanedWindow(parent, orient="horizontal")
        pane.pack(fill="both", expand=True, padx=4, pady=(2, 6))

        left = ttk.Frame(pane)
        self.canvas = tk.Canvas(left, width=640, height=420, highlightthickness=1, bd=0)
        self.canvas.pack(fill="both", expand=True)
        self.summary = tk.Label(left, text="", anchor="w", justify="left", padx=8, pady=6,
                                font=(ctx.font, 9))
        self.summary.pack(fill="x")
        pane.add(left, weight=3)

        right = ttk.Frame(pane)
        self.tree = ttk.Treeview(right, columns=[c[0] for c in COLUMNS], show="headings", height=18)
        for key, head, width in COLUMNS:
            self.tree.heading(key, text=head)
            self.tree.column(key, width=width, anchor="w" if key in ("ip", "org", "place") else "e",
                             stretch=key in ("org", "place"))
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        pane.add(right, weight=2)
        # PanedWindow の初期配置は子の要求サイズで決まり、列の多い Treeview が地図を潰すので
        # レイアウト確定後に一度だけ実比率で分ける(以後はユーザーがサッシをドラッグできる)
        self.ctx.root.after(200, lambda: self._split(pane))

        self.canvas.bind("<Configure>", lambda e: self.draw())
        self.canvas.bind("<MouseWheel>", self._on_wheel)
        self.canvas.bind("<ButtonPress-1>", self._on_press)
        self.canvas.bind("<B1-Motion>", self._on_drag)
        self.canvas.bind("<ButtonRelease-1>", lambda e: setattr(self, "_drag", None))

        self.on_theme_changed()

    @staticmethod
    def _split(pane):
        """一覧に必要な幅だけ渡して、残りを全部地図に回す。"""
        try:
            need = sum(c[2] for c in COLUMNS) + 24
            w = pane.winfo_width()
            if w > need + 260:
                pane.sashpos(0, w - need)
        except tk.TclError:
            pass

    # ---- テーマ ----

    def on_theme_changed(self):
        t = self.ctx.theme
        self.canvas.config(bg=t["graph_bg"], highlightbackground=t["graph_grid"])
        self.summary.config(bg=t["card_bg"], fg=t["fg"])
        for tag, col in (("good", t["good"]), ("warn", t["warn"]), ("bad", t["bad"]),
                         ("bogus", t["muted"]), ("", t["fg"])):
            if tag:
                self.tree.tag_configure(tag, foreground=col)
        # sv_ttk は style map に -foreground を持っており、そのままだと行タグの色が無視される。
        # 選択状態以外のマッピングを外してタグ色を優先させる(pathmon_tab.py と同じ対処)。
        style = ttk.Style()
        for opt in ("foreground", "background"):
            style.map("Treeview", **{opt: [s for s in style.map("Treeview", query_opt=opt)
                                           if s[0] in ("selected", "!selected")]})
        self.status.config(foreground=t.get(self.status_kind, t["muted"]))
        self.draw()

    def _set_status(self, text, kind="muted"):
        self.status_kind = kind
        self.status.config(text=text, foreground=self.ctx.theme[kind])

    # ---- 計測 ----

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        host = self.host_var.get().strip() or DEFAULT_HOST
        max_hops = max(1, int(self.hops_var.get() or DEFAULT_MAX_HOPS))
        self.run_btn.config(state="disabled")
        self._set_status(f"tracert {host} を実行中… (最大 {max_hops} ホップ、数十秒かかることがあります)")
        self._stop.clear()
        self._thread = threading.Thread(target=self._worker, args=(host, max_hops), daemon=True)
        self._thread.start()

    def _worker(self, host, max_hops):
        try:
            try:
                dest = resolve_ipv4(host)
            except OSError as e:
                self._post(self._failed, f"IPv4で名前解決できません: {host} ({e})")
                return
            hops = traceroute(dest, max_hops)
            if isinstance(hops, dict):
                self._post(self._failed, hops.get("error", "不明なエラー"))
                return
            self._post(self._set_status, f"{host} ({dest}): {len(hops)} ホップ検出。測位中…")
            origin = lookup_geo()      # 自分のグローバルIP = 経路の起点
            ips = [h["ip"] for h in hops if h.get("ip") and not is_private(h["ip"])]
            geo = {}
            if ips:
                with ThreadPoolExecutor(max_workers=4) as pool:
                    for ip, info in zip(ips, pool.map(lookup_geo, ips)):
                        if info:
                            geo[ip] = info
            if self._stop.is_set():
                return
            if origin and origin.get("lat") is not None:
                geo[origin["ip"]] = origin
                hops = [{"hop": 0, "ip": origin["ip"], "avg_ms": None, "timeout": False}] + list(hops)
            self._post(self._done, host, dest, max_hops, build_route(hops, geo), origin)
        except Exception as e:
            self._post(self._failed, f"{type(e).__name__}: {e}")

    def _post(self, fn, *args):
        if not self._stop.is_set():
            self.ctx.root.after(0, fn, *args)

    def _failed(self, msg):
        self.run_btn.config(state="normal")
        self._set_status(f"失敗: {msg}", "bad")

    def _done(self, host, dest, max_hops, rows, origin):
        self.run_btn.config(state="normal")
        self.rows = rows
        self.origin = origin
        self.clusters = cluster_rows(rows)
        self.sel_hop = None
        self.auto = True
        self._fill_tree()
        self.fit()
        located = sum(1 for r in rows if r["lat"] is not None)
        path = self._save(host, dest, max_hops)
        self._set_status(f"{host} ({dest}): {len(rows)} ホップ / 測位できたのは {located} 箇所 "
                         f"({len(self.clusters)} 地点)  →  {path.name}", "good")

    def _save(self, host, dest, max_hops):
        nd.RESULTS_DIR.mkdir(exist_ok=True)
        path = nd.RESULTS_DIR / f"geomap_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        last = next((r for r in reversed(self.rows) if r["cum_km"] is not None), None)
        path.write_text(json.dumps({
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "host": host, "dest_ip": dest, "max_hops": max_hops, "origin": self.origin,
            "total_km": round(last["cum_km"], 1) if last else None,
            "theoretical_min_rtt_ms": round(last["min_ms"], 2) if last else None,
            "fiber_speed_km_s": round(FIBER_KM_S, 1),
            "hops": self.rows,
        }, ensure_ascii=False, indent=2, default=lambda o: None), encoding="utf-8")
        return path

    def on_close(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    # ---- 一覧 ----

    def _fill_tree(self):
        self.tree.delete(*self.tree.get_children())
        for r in self.rows:
            if r["ip"] is None:
                place, ip = ("応答なし" if r["timeout"] else "IPを取得できず", "*")
            elif r["private"]:
                place, ip = (private_label(r["ip"]), r["ip"])
            elif r["lat"] is None:
                place, ip = ("測位できず", r["ip"])
            else:
                place, ip = (", ".join(x for x in (r["city"], r["country"]) if x), r["ip"])
            num = lambda v, f="{:.0f}": f.format(v) if v is not None else "-"
            self.tree.insert("", "end", iid=str(r["hop"]), tags=(over_tag(r["over_ms"]),), values=(
                r["hop"], ip, r["org"], place,      # ホップ0 = 自分のグローバルIP(経路の起点)
                num(r["avg_ms"], "{:.0f}ms"), num(r["seg_km"], "{:,.0f}"), num(r["cum_km"], "{:,.0f}"),
                num(r["min_ms"], "{:.1f}"),
                "-" if r["over_ms"] is None else f"{r['over_ms']:+.1f}",
            ))
        self._update_summary()

    def _update_summary(self):
        t = self.ctx.theme
        last = next((r for r in reversed(self.rows) if r["over_ms"] is not None), None)
        if not last:
            self.summary.config(text="距離と実測RTTを比較できるホップがまだありません。", fg=t["muted"])
            return
        bogus = [r["hop"] for r in self.rows if r["over_ms"] is not None and r["over_ms"] < 0]
        text = (f"最終ホップ {last['hop']} まで  直線距離 {last['cum_km']:,.0f} km ／ "
                f"光ファイバ往復の物理下限 {last['min_ms']:.1f} ms ／ 実測 {last['avg_ms']:.0f} ms\n")
        if last["over_ms"] >= 0:
            ratio = last["min_ms"] / last["avg_ms"] * 100 if last["avg_ms"] else 0
            text += (f"→ 距離由来 {last['min_ms']:.1f} ms ({ratio:.0f}%) ・ "
                     f"機器の処理/キューイング由来 {last['over_ms']:+.1f} ms")
        else:
            text += "→ 実測が物理下限より速い。この距離は物理的にありえないので測位が実態と違う"
        if bogus:
            text += f"\n⚠ ホップ {format_hop_numbers(bogus)} は光速超え = 測位が実態と違う(anycast等)"
        self.summary.config(text=text, fg=t["bad"] if bogus else t["fg"])

    def _on_select(self, _event=None):
        sel = self.tree.selection()
        self.sel_hop = int(sel[0]) if sel else None
        self.draw()

    # ---- 視野操作 ----

    def fit(self):
        self.auto = True
        self.view = auto_view([(c["lon"], c["lat"]) for c in self.clusters])
        self.draw()

    def reset_view(self):
        self.auto = False
        self.view = WORLD
        self.draw()

    def zoom(self, factor, focus=None):
        self.auto = False
        self.view = zoom_view(self.view, factor, focus)
        self.draw()

    def _on_wheel(self, e):
        proj = projector(self.view, *self._size())
        self.zoom(0.8 if e.delta > 0 else 1 / 0.8, proj.inverse(e.x, e.y))

    def _on_press(self, e):
        self._drag = (e.x, e.y, self.view)

    def _on_drag(self, e):
        if not self._drag:
            return
        x0, y0, view = self._drag
        scale = projector(view, *self._size()).scale
        dlon, dlat = (x0 - e.x) / scale, (e.y - y0) / scale
        self.auto = False
        self.view = (view[0] + dlon, view[1] + dlat, view[2] + dlon, view[3] + dlat)
        self.draw()

    def _size(self):
        w, h = self.canvas.winfo_width(), self.canvas.winfo_height()
        return (w if w > 10 else 720), (h if h > 10 else 360)   # 初回描画時は 1 が返る

    # ---- 描画 ----

    def draw(self):
        c = self.canvas
        c.delete("all")
        w, h = self._size()
        t = self.ctx.theme
        land = mix(t["graph_bg"], t["graph_grid"], 0.75)
        coast = mix(t["graph_grid"], t["fg"], 0.30)
        grid = mix(t["graph_bg"], t["graph_grid"], 0.55)
        proj = projector(self.view, w, h)
        # view はキャンバス内に等倍で収めるので、実際に見えている範囲は view より広い(レターボックス分)。
        # 罫線も陸地の視野外カリングもこちらを使わないと余白側の大陸が消える。
        lon0, lat1 = proj.inverse(0, 0)
        lon1, lat0 = proj.inverse(w, h)
        self.summary.config(wraplength=max(240, w - 16))

        step = next((s for s in (30, 15, 10, 5, 2, 1, 0.5, 0.2, 0.1) if (lon1 - lon0) / s >= 4), 0.05)
        for lon in _ticks(lon0, lon1, step):
            x, _ = proj(lon, 0)
            c.create_line(x, 0, x, h, fill=grid)
            c.create_text(x + 3, h - 4, text=_fmt_deg(lon, "EW"), anchor="sw", fill=grid,
                          font=(self.ctx.font, 7))
        for lat in _ticks(lat0, lat1, step):
            _, y = proj(0, lat)
            c.create_line(0, y, w, y, fill=grid)
            c.create_text(3, y - 2, text=_fmt_deg(lat, "NS"), anchor="sw", fill=grid,
                          font=(self.ctx.font, 7))

        for (bx0, by0, bx1, by1), pts in LAND_RINGS:
            if bx1 < lon0 or bx0 > lon1 or by1 < lat0 or by0 > lat1:
                continue                       # 視野外は投影も生成もしない(拡大時の描画コスト対策)
            flat = []
            for lon, lat in pts:
                flat.extend(proj(lon, lat))
            c.create_polygon(flat, fill=land, outline=coast, width=1)

        self._draw_route(c, proj, t)

    def _draw_route(self, c, proj, t):
        if not self.clusters:
            c.create_text(self._size()[0] / 2, 18, text="経路未測定", fill=t["muted"],
                          font=(self.ctx.font, 10))
            return
        pts = [proj(cl["lon"], cl["lat"]) for cl in self.clusters]
        for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
            c.create_line(x0, y0, x1, y1, fill=t["warn"], width=2, arrow="last",
                          arrowshape=(9, 11, 3))
        for cl, (x, y) in zip(self.clusters, pts):
            worst = max((r["over_ms"] for r in cl["rows"] if r["over_ms"] is not None), default=None)
            col = t.get({"good": "good", "warn": "warn", "bad": "bad"}.get(over_tag(worst), "muted"),
                        t["muted"])
            if self.sel_hop is not None and self.sel_hop in cl["hops"]:
                c.create_oval(x - 13, y - 13, x + 13, y + 13, outline=t["fg"], width=2)
            c.create_oval(x - 6, y - 6, x + 6, y + 6, fill=col, outline=t["graph_bg"], width=2)
            label = format_hop_numbers(cl["hops"])
            c.create_text(x + 10, y - 10, text=label, anchor="w", fill=t["fg"],
                          font=(self.ctx.font, 9, "bold"))
            place = cl["rows"][0]["city"] or cl["rows"][0]["country"]
            if place:
                c.create_text(x + 10, y + 3, text=place, anchor="w", fill=t["muted"],
                              font=(self.ctx.font, 8))


def _ticks(lo, hi, step):
    n = math.floor(lo / step) + 1
    while n * step <= hi:
        yield n * step
        n += 1


def _fmt_deg(v, axis):
    hemi = axis[0] if v >= 0 else axis[1]
    return f"{abs(v):g}°{hemi}"


# ---------- 自己テスト ----------

def _selftest():
    # 投影: WORLD かつ 2:1 のキャンバスなら仕様どおりの式に一致する
    w, h = 720, 360
    proj = projector(WORLD, w, h)
    for lon, lat in [(0, 0), (139.6917, 35.6895), (-74.0, 40.7), (180, -90), (-180, 90)]:
        x, y = proj(lon, lat)
        assert abs(x - (lon + 180) / 360 * w) < 1e-9, (lon, x)
        assert abs(y - (90 - lat) / 180 * h) < 1e-9, (lat, y)
    assert proj(0, 0) == (360.0, 180.0)
    tx, ty = proj(139.6917, 35.6895)                      # 東京は右上寄り(日本の位置)
    assert 630 < tx < 650 and 100 < ty < 115, (tx, ty)
    assert proj(-0.1278, 51.5074)[0] < tx                 # ロンドンは東京より左
    assert proj(151.2, -33.9)[1] > ty                     # シドニーは東京より下
    ix, iy = proj.inverse(tx, ty)
    assert abs(ix - 139.6917) < 1e-9 and abs(iy - 35.6895) < 1e-9

    # 正方キャンバスでも等倍(レターボックス)。1度が縦横同じピクセル数
    sq = projector(WORLD, 400, 400)
    assert abs((sq(1, 0)[0] - sq(0, 0)[0]) - (sq(0, 0)[1] - sq(0, 1)[1])) < 1e-9
    # どんな縦横比のキャンバスでも view の四隅が画面内に収まる(=ホップが画面外に出ない)
    for cw, ch in [(400, 900), (900, 400), (500, 500), (1200, 200), (120, 700)]:
        p = projector((139.0, -30.0, 153.0, 36.0), cw, ch)
        for lon, lat in [(139.0, -30.0), (153.0, 36.0), (139.0, 36.0), (153.0, -30.0), (146, 3)]:
            x, y = p(lon, lat)
            assert -0.01 <= x <= cw + 0.01 and -0.01 <= y <= ch + 0.01, (cw, ch, lon, lat, x, y)

    zoomed = projector((139.0, 35.0, 141.0, 37.0), 400, 400)
    assert abs(zoomed(140.0, 36.0)[0] - 200) < 1e-9 and abs(zoomed(140.0, 36.0)[1] - 200) < 1e-9
    assert zoomed.scale > sq.scale * 100                  # 2度幅まで寄れば桁違いに拡大される

    # Haversine
    tokyo, london = (35.6895, 139.6917), (51.5074, -0.1278)
    d = haversine_km(*tokyo, *london)
    assert 9500 < d < 9620, d                             # 実距離 約9,560km
    assert haversine_km(*tokyo, *tokyo) == 0.0
    assert abs(haversine_km(0, 0, 0, 1) - 111.19) < 0.1   # 赤道上の経度1度
    assert abs(haversine_km(0, 0, 1, 0) - 111.19) < 0.1
    assert abs(haversine_km(0, 0, 0, 180) - math.pi * EARTH_R_KM) < 0.1   # 対蹠点
    assert abs(haversine_km(35.6895, 139.6917, 34.6937, 135.5023) - 397) < 5  # 東京-大阪 約400km

    # 理論最小RTT: 光ファイバ内では往復およそ 1ms / 100km
    assert abs(min_rtt_ms(100) - 1.0) < 0.01, min_rtt_ms(100)
    assert abs(min_rtt_ms(1000) - 10.01) < 0.05
    assert abs(min_rtt_ms(d) - 95.7) < 1.0, min_rtt_ms(d)  # 東京-ロンドンは片道約48ms
    assert min_rtt_ms(0) == 0.0
    assert min_rtt_ms(1) > 1 * 2 / LIGHT_KM_S * 1000            # ファイバ内は真空より遅い

    # 自動ズーム
    v = auto_view([(139.7, 35.7), (135.5, 34.7)])
    assert v[0] < 135.5 and v[2] > 139.7 and v[1] < 34.7 and v[3] > 35.7, v
    assert abs((v[0] + v[2]) / 2 - 137.6) < 1e-6, v
    one = auto_view([(139.6917, 35.6895)])                # 1点でも潰れない
    assert one[2] - one[0] >= MIN_SPAN_DEG and one[3] - one[1] >= MIN_SPAN_DEG, one
    assert one[0] < 139.6917 < one[2] and one[1] < 35.6895 < one[3], one
    same = auto_view([(139.6917, 35.6895)] * 5)           # 全部同一地点でも同じ
    assert same == one
    assert auto_view([]) == WORLD
    wide = auto_view([(-122.4, 37.8), (139.7, 35.7)])     # 太平洋横断はほぼ世界規模
    assert wide[2] - wide[0] > 262, wide

    z = zoom_view((0, 0, 10, 10), 0.5)
    assert z == (2.5, 2.5, 7.5, 7.5), z
    z2 = zoom_view((0, 0, 10, 10), 0.5, focus=(0, 0))     # 固定点まわりに寄る
    assert z2 == (0.0, 0.0, 5.0, 5.0), z2

    # プライベート/CGNAT判定
    for ip in ("192.168.3.1", "10.0.0.1", "172.20.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1",
               "100.127.255.254", "not-an-ip"):
        assert is_private(ip), ip
    for ip in ("1.1.1.1", "8.8.8.8", "100.128.0.1", "150.100.9.9"):
        assert not is_private(ip), ip
    assert private_label("100.64.0.1").startswith("ISP") and private_label("192.168.3.1") == "宅内"

    assert parse_loc("35.6895,139.6917") == (35.6895, 139.6917)
    assert parse_loc(None) == (None, None) and parse_loc("") == (None, None)
    assert parse_loc("abc,1") == (None, None) and parse_loc("999,0") == (None, None)

    # 経路の組み立て: プライベート -> 測位済み -> 測位できず -> 測位済み
    hops = [{"hop": 1, "ip": "192.168.3.1", "avg_ms": 1.0}, {"hop": 2, "ip": "100.64.0.1", "avg_ms": 4.0},
            {"hop": 3, "ip": "150.100.1.1", "avg_ms": 8.0}, {"hop": 4, "ip": None, "avg_ms": None,
                                                             "timeout": True},
            {"hop": 5, "ip": "80.80.80.7", "avg_ms": 120.0}]
    geo = {"150.100.1.1": {"lat": 35.6895, "lon": 139.6917, "org": "AS1 JP", "city": "Tokyo",
                           "country": "JP"},
           "80.80.80.7": {"lat": 51.5074, "lon": -0.1278, "org": "AS2 UK", "city": "London",
                            "country": "GB"}}
    rows = build_route(hops, geo)
    assert [r["private"] for r in rows] == [True, True, False, False, False]
    assert rows[0]["cum_km"] is None and rows[2]["cum_km"] == 0.0
    assert rows[2]["seg_km"] is None                      # 最初の測位点に区間はない
    assert rows[3]["lat"] is None and rows[3]["cum_km"] is None
    assert abs(rows[4]["seg_km"] - d) < 1                 # 無応答ホップを飛ばして東京-ロンドンで結ぶ
    assert abs(rows[4]["cum_km"] - d) < 1
    assert abs(rows[4]["over_ms"] - (120.0 - rows[4]["min_ms"])) < 1e-9
    assert 20 < rows[4]["over_ms"] < 30, rows[4]["over_ms"]   # 実測120ms - 物理下限95.7ms
    assert rows[2]["over_ms"] == 8.0                      # 距離0の起点なので全部が機器由来

    # 起点(自分のグローバルIP)を hop 0 として足した場合
    with_origin = build_route([{"hop": 0, "ip": "150.100.9.9", "avg_ms": None}] + hops,
                              dict(geo, **{"150.100.9.9": {"lat": 34.6937, "lon": 135.5023,
                                                           "org": "", "city": "Osaka",
                                                           "country": "JP"}}))
    assert abs(with_origin[3]["seg_km"] - 397) < 5        # 大阪 -> 東京
    assert with_origin[3]["over_ms"] < 8.0                # 距離分が差し引かれる

    # anycast等で測位が嘘のとき: 実測が物理下限を下回る
    bogus = build_route([{"hop": 1, "ip": "150.100.1.1", "avg_ms": None},
                         {"hop": 2, "ip": "80.80.80.7", "avg_ms": 12.0}], geo)
    assert bogus[1]["over_ms"] < 0 and over_tag(bogus[1]["over_ms"]) == "bogus"
    assert (over_tag(None), over_tag(0.0), over_tag(9.9), over_tag(11.0), over_tag(99.0)) == \
           ("", "good", "good", "warn", "bad")

    # 同一座標のホップをまとめる(国内経路で全ホップが同じ都市重心になる問題)
    cl = cluster_rows(build_route(
        [{"hop": i, "ip": "150.100.1.1", "avg_ms": 5.0} for i in (1, 2, 3)] +
        [{"hop": 4, "ip": "80.80.80.7", "avg_ms": 120.0}], geo))
    assert len(cl) == 2 and cl[0]["hops"] == [1, 2, 3] and cl[1]["hops"] == [4]
    assert cluster_rows(build_route([{"hop": 1, "ip": "192.168.3.1", "avg_ms": 1.0}], {})) == []
    assert format_hop_numbers([2, 3, 4, 7]) == "2-4,7"
    assert format_hop_numbers([5]) == "5" and format_hop_numbers([1, 2]) == "1-2"
    assert format_hop_numbers([1, 3, 5]) == "1,3,5"

    assert mix("#000000", "#ffffff", 0.5) == "#808080"
    assert mix("#102030", "#102030", 1.0) == "#102030"

    # 地図データの健全性(座標が壊れていると大陸が破綻する)
    assert len(LAND_RINGS) > 50
    for (x0, y0, x1, y1), pts in LAND_RINGS:
        assert len(pts) >= 4 and -180 <= x0 <= x1 <= 180 and -90 <= y0 <= y1 <= 90
    assert sum(len(p) for _, p in LAND_RINGS) > 1500
    # 日本(本州)が含まれていて、かつ細かく残っている
    honshu = [p for b, p in LAND_RINGS if 130 < b[0] and b[2] < 143 and 33 < b[1] and b[3] < 42]
    assert honshu and len(honshu[0]) > 100, [len(p) for p in honshu]
    # 東京・ロンドン・シドニーがそれぞれ陸地環のbbox内にある(投影と地図の整合)
    for lon, lat in [(139.69, 35.68), (-0.13, 51.51), (151.2, -33.87), (-74.0, 40.7)]:
        assert any(b[0] <= lon <= b[2] and b[1] <= lat <= b[3] for b, _ in LAND_RINGS), (lon, lat)
    assert not any(b[0] <= -30 <= b[2] and b[1] <= 0 <= b[3] for b, _ in LAND_RINGS)  # 大西洋上は陸なし

    assert list(_ticks(-180, 180, 30))[:2] == [-150, -120]
    assert _fmt_deg(139.5, "EW") == "139.5°E" and _fmt_deg(-33, "NS") == "33°S"
    print("geomap selftest: OK")


# ---------- 地図データ (Natural Earth 1:50m land を簡略化して埋め込み) ----------

LAND = [
    "17.98,59.33,16.21,58.64,16.92,58.49,16,56.22,12.89,55.41,12.88,56.62,10.6,59.76,8.17,58.15,5.59,58.62,6.42,59.55,5.24,59.56,7,60.51,5.15,59.64,5.65,60.69,5.01,61.04,7.6,61.21,5.32,61.11,4.93,61.88,6.73,61.87,5.14,62.16,8.62,62.85,8.58,63.6,11.37,63.8,9.61,63.79,18.26,69.47,23.35,69.98,24.66,71,25.77,70.85,25.04,70.11,28.14,71.04,28.19,70.25,28.83,70.86,30.93,70.4,28.78,70.15,29.69,69.74,31.98,69.95,33.14,69.07,35.86,69.19,40.97,67.71,41.19,66.83,38.65,66.07,31.9,67.16,34.69,65.95,35.04,64.44,37.44,63.81,38.06,64.09,36.88,65.17,39.76,64.58,40.44,64.78,39.82,65.6,42.21,66.52,44.1,66.01,44.2,68.25,43.33,68.67,45.89,68.48,46.69,67.85,44.9,67.41,46.49,66.8,53.8,69,54.49,68.99,53.26,68.27,59.06,69.01,59.73,68.35,60.93,68.99,60.17,69.59,60.91,69.85,68.5,68.35,69.14,68.95,66.9,69.55,67.28,70.74,66.64,71.08,69.39,72.96,71.62,72.9,72.81,72.69,71.87,71.46,72.7,70.96,72.58,68.97,73.59,68.48,71.54,66.68,69.01,66.79,72.07,66.25,74.77,67.77,74.39,68.42,75.12,68.86,78.92,67.59,77.59,67.75,77.65,68.9,73.78,69.2,74.34,70.58,73.09,71.44,74.99,72.14,74.79,72.81,75.6,72.58,75.73,71.27,79.02,70.95,76.03,71.91,78.48,72.39,83.11,71.72,82.16,70.6,83.01,70.9,83.08,70.09,83.53,71.68,80.83,72.49,80.58,73.57,86.89,73.89,85.79,73.44,86.68,73.11,85.94,73.46,87.57,73.81,85.79,74.65,87.01,75.17,93.26,76.1,99.54,75.8,98.87,76.51,101.6,76.44,100.99,76.99,104.01,77.73,106.06,77.39,104.2,77.1,107.43,76.93,106.41,76.51,111.11,76.72,113.86,75.92,105.14,72.78,110.26,74.02,113.03,73.91,113.66,72.63,114.06,73.58,122.54,72.88,124.54,73.75,129.1,73.11,128.42,72.54,129.28,72.09,127.73,72.41,131.02,70.75,132.65,71.93,139.98,71.49,139.36,71.95,140.19,72.19,139.14,72.33,140.81,72.89,146.83,72.3,145.19,71.7,149.5,72.16,148.97,71.69,152.51,70.83,158.7,70.94,160.91,69.61,160.86,68.54,163.2,69.71,167.86,69.73,170.54,68.83,170.49,70.11,180,68.98,180,65.07,174.55,64.68,178.23,64.36,179.57,62.77,179.12,62.32,177.02,62.78,170.35,59.97,169.23,60.6,163.74,60.03,161.96,58.08,163.23,57.79,163.34,56.23,162.08,56.09,162.11,54.75,160.07,54.19,160.03,53.13,158.47,53.03,156.75,50.97,155.56,55.2,155.98,56.7,163.71,60.92,164.21,62.29,165.42,62.45,164.42,62.7,160.17,60.64,160.31,61.89,157.08,61.68,154.29,59.83,155.16,59.19,151.33,58.88,152.17,59.28,149.64,59.77,142.58,59.24,135.26,54.94,136.8,54.62,136.72,53.8,137.67,54.28,137.25,53.55,139.8,54.26,141.37,53.29,140.84,53.09,141.49,52.18,140.11,48.42,135.48,43.84,133.16,42.7,131.79,43.26,127.57,39.78,129.42,37.06,129.21,35.18,126.53,34.31,126.63,37.78,124.69,38.13,125.55,38.69,124.35,40.01,121.16,38.73,121.83,40.97,117.78,39.13,119.29,37.14,120.75,37.83,122.67,37.4,119.17,34.85,121.86,31.82,120.04,31.94,121.88,30.92,120.19,30.24,122.08,29.87,121.61,28.29,119.14,26.12,119.62,25.39,116.47,22.95,114.27,22.3,113.52,23.1,113.55,22.22,110.41,21.34,110.34,20.29,109.93,21.48,108.59,21.9,106.68,21,105.62,18.97,108.82,15.38,109.44,12.6,108.99,11.34,106.14,10.22,106.57,9.64,105.83,10,106.17,9.4,105.11,8.63,105.03,10.07,100.9,12.65,100.96,13.43,100.02,13.35,99.25,9.27,100.42,7.19,103.2,5.26,104.18,1.36,101.3,2.89,100.12,6.44,98.31,8.23,98.88,11.72,97.73,16.57,96.85,17.4,95.39,15.72,94.7,16.51,94.22,16.02,94,19.44,90.6,23.59,90.23,21.83,89.99,22.47,88.12,21.64,87.94,22.37,86.75,20.31,80.29,15.71,79.84,10.32,77.52,8.08,73.34,16.46,72.81,22.23,70.49,20.84,68.97,22.29,70.49,23.09,68.82,23.05,66.43,25.58,57.8,25.65,56.73,27.13,54.64,26.51,51.59,27.86,50.07,30.2,47.98,30.01,50.73,24.87,51.54,25.9,51.31,24.34,54.15,24.17,56.41,26.35,56.64,24.47,59.82,22.31,57.86,20.24,57.81,19.02,55.06,17.04,43.93,12.62,42.29,17.43,39.28,20.97,38.46,23.71,34.62,28.06,34.97,29.56,34.22,27.76,32.47,29.93,39.51,15.53,43.35,12.37,42.54,11.5,44.94,10.44,50.79,11.98,51.38,10.39,47.98,4.5,40.28,-2.63,39.23,-4.67,38.8,-6.07,39.73,-10,40.61,-10.66,40.84,-14.79,39.84,-16.44,34.65,-19.7,35.44,-24.17,32.79,-25.64,32.38,-28.5,27.86,-33.05,20.02,-34.79,18.35,-34.19,18.21,-31.74,14.97,-26.32,14.46,-22.45,11.78,-18,11.75,-15.83,13.85,-11.05,12.28,-6.12,13.07,-5.86,12.24,-5.81,8.7,-0.59,10,0.19,9.32,0.55,9.69,4.06,8.25,4.92,6.08,4.29,3.72,6.6,-2,4.76,-3.2,5.35,-8.26,4.59,-12.49,7.39,-13.69,9.93,-15.39,11.22,-15.08,11.97,-16.78,12.47,-16.75,13.43,-15.43,13.47,-16.44,13.35,-17.54,14.76,-16.08,17.55,-16.21,20.23,-17.1,20.86,-15.9,23.84,-12.95,27.91,-10.2,29.38,-9.25,32.57,-6.9,33.97,-5.92,35.79,-1.91,35.09,1.26,36.52,9.69,37.34,11.13,36.87,10.31,33.73,15.18,32.39,15.71,31.43,18.94,30.29,21.64,32.94,29.07,30.83,34.48,31.59,36.18,36.81,32.79,36.04,31.24,36.82,29.69,36.16,27.54,36.68,28.24,37.03,27.26,36.98,27.23,37.98,26.29,38.28,27.14,38.45,26.18,39.99,33.38,42.02,38.38,40.92,41.41,41.42,41.42,42.74,36.63,45.15,39.2,47.27,35.23,46.44,35.02,45.7,36.39,45.07,33.91,44.39,32.51,45.4,33.59,46.1,31.83,46.28,32.58,46.62,31.76,47.21,28.93,44.97,27.48,42.47,28.96,41.01,26.2,40.08,26.79,40.63,25.1,40.99,23.76,40.75,23.95,39.97,22.63,40.5,23.33,39.17,22.57,38.87,24.02,38.14,22.73,37.54,23.16,36.45,21.12,37.89,23.15,38.18,21.18,38.35,19.4,40.28,19.58,41.79,15.99,43.52,14.55,45.3,13.86,44.84,13.63,45.77,12.27,45.45,12.4,44.22,18.46,40.22,16.93,40.46,17.17,39,16.06,37.94,15.69,39.99,8.77,44.42,6.12,43.07,3.26,43.19,3.25,41.94,0.71,40.82,-0.33,39.52,0.2,38.76,-2.11,36.78,-5.63,36.03,-6.86,37.28,-9,37.03,-9.18,43.17,-7.7,43.76,-1.99,43.35,-1.08,45.53,-0.55,45,-1.74,47.22,-4.72,48.54,-1.38,48.65,-1.86,49.68,0.42,49.45,1.77,50.94,4.23,51.39,3.45,51.54,4.27,51.47,5.53,53.27,9.78,53.55,8.13,55.6,8.16,56.61,9.2,56.7,8.62,57.11,10.61,57.74,10.28,56.62,10.93,56.44,9.59,55.49,9.87,54.47,14.58,53.64,13.83,54.13,19.41,54.39,21.11,55.62,20.59,54.98,21.19,54.94,21.73,57.57,24.38,57.25,24.53,58.35,23.49,59.2,30.12,59.87,28.51,60.68,23.02,59.82,21.44,60.6,21.55,63.2,25.37,65.01,24.63,65.86,22.4,65.86,20.76,63.87,17.38,62.46,17.25,60.7,18.99,59.83,17.98,59.33",
    "-94.31,71.76,-91.56,70.18,-92.89,69.67,-90.42,69.46,-91.24,69.29,-90.25,68.27,-89.28,69.26,-88.04,68.81,-88.31,67.95,-87.36,67.18,-84.87,68.77,-85.51,69.85,-82.37,69.64,-81.25,68.74,-82.55,68.45,-81.47,67.07,-83.41,66.37,-85.11,66.91,-83.87,66.21,-86.71,66.52,-85.96,66.12,-87.45,65.34,-91.41,65.96,-87.03,65.2,-88.11,64.18,-90.81,63.58,-93.7,64.15,-90.71,63.3,-93.21,62.36,-94.76,60.5,-94.96,59.07,-94.33,58.3,-93.18,58.73,-92.8,56.92,-90.59,57.22,-85.37,55.08,-82.39,55.07,-81.83,52.22,-79.35,50.76,-79.69,51.35,-78.9,51.2,-78.45,52.26,-79.71,54.67,-76.53,56.5,-76.89,57.76,-78.51,58.65,-77.29,60.02,-78.18,60.82,-77.51,61.56,-78.13,62.28,-73.71,62.47,-69.47,61.01,-69.67,60.08,-70.65,60.03,-69.34,59.3,-70.15,58.76,-68.38,58.74,-69.04,57.9,-66,58.43,-64.5,60.27,-62.87,58.67,-63.54,58.33,-62.59,58.47,-63.26,58.01,-61.33,57.01,-62.5,56.8,-60.34,55.78,-60.62,55.06,-57.4,54.59,-60.33,53.27,-57.42,54.16,-57.33,53.47,-55.97,53.47,-56.32,52.54,-55.67,52.19,-60.08,50.25,-66.5,50.21,-69.67,48.2,-71.02,48.46,-69.99,47.74,-74.32,45.53,-65.52,49.27,-64.35,48.42,-66.7,48.02,-64.7,47.72,-65.32,47.1,-64.54,46.24,-61.03,45.29,-65.48,43.52,-66.09,44.5,-63.37,45.36,-64.87,45.35,-64.63,45.95,-68.76,44.57,-71.05,42.33,-69.95,41.68,-73.97,41.25,-74.92,38.94,-75.46,39.78,-75.04,38.43,-75.93,37.15,-75.87,39.51,-76.57,39.27,-76.34,38.09,-77.03,38.89,-76.28,37.05,-77.25,37.33,-75.53,35.82,-75.95,36.66,-76.73,36.23,-75.76,35.84,-77.04,35.53,-76.44,34.84,-80.8,32.45,-81.46,31.13,-80.05,26.81,-80.48,25.23,-81.11,25.14,-82.71,27.5,-82.65,28.89,-84.04,30.1,-85.32,29.68,-88.01,30.69,-90.33,30.28,-89.16,29.02,-93.84,29.98,-96.64,28.71,-97.77,27.46,-97.14,26.03,-97.86,22.62,-95.92,18.82,-91.53,18.46,-90.35,21.01,-87.03,21.59,-88.89,15.89,-84.97,15.99,-83.37,15.24,-83.87,11.3,-82.08,8.93,-79.11,9.54,-76.79,7.93,-75.25,10.78,-71.6,12.43,-71.62,9.05,-71.47,10.96,-69.8,11.47,-70,12.18,-68.14,10.49,-61.88,10.74,-62.74,10.06,-60.79,9.36,-61.3,8.41,-58.81,7.74,-58.67,6.39,-57.98,6.79,-57.18,5.53,-53.85,5.78,-51.22,4.09,-49.9,1.16,-52.66,-1.55,-50.89,-0.94,-50.4,-2.02,-49.31,-1.73,-49.64,-2.66,-47.4,-0.63,-44.65,-1.75,-44.72,-3.2,-43.38,-2.38,-39.96,-2.86,-35.48,-5.17,-34.83,-7.02,-35.34,-9.23,-38.85,-12.79,-39.15,-17.7,-41,-22,-48.73,-25.37,-48.8,-28.58,-52.04,-32.11,-50.58,-30.44,-51.3,-30.03,-54.17,-34.67,-57.83,-34.48,-58.2,-32.47,-58.53,-34.3,-56.73,-36.96,-58.18,-38.44,-62.33,-38.8,-62.4,-40.89,-65.07,-40.81,-64.99,-42.1,-63.62,-42.7,-64.97,-42.67,-64.32,-42.97,-65.64,-45.01,-67.6,-46.05,-65.81,-47.94,-67.91,-49.98,-68.98,-50,-68.42,-50.16,-69.47,-51.58,-68.39,-52.31,-70.8,-52.77,-71.3,-53.88,-72.41,-53.35,-71.23,-52.81,-73.05,-53.24,-71.51,-52.61,-74.01,-52.64,-74.26,-52.1,-72.52,-52.26,-75.09,-50.68,-73.81,-50.94,-74.63,-50.19,-73.84,-49.61,-74.58,-48,-73.39,-48.15,-74.65,-47.7,-74.31,-46.79,-75.71,-46.71,-73.96,-45.4,-73.85,-46.57,-72.68,-44.59,-73.27,-44.17,-72.32,-41.5,-73.62,-41.77,-73.97,-41.12,-73.23,-39.22,-73.66,-37.34,-71.45,-32.66,-70.36,-18.4,-75.93,-14.63,-81.34,-4.67,-79.73,-2.58,-80.96,-2.19,-80.09,0.78,-78.9,1.21,-77.08,3.91,-78.42,8.06,-77.76,8.13,-79.44,9.01,-80.85,7.22,-85.62,9.9,-87.49,13.35,-91.38,13.99,-94.37,16.28,-96.51,15.65,-103.44,18.33,-105.48,19.98,-105.79,22.63,-109.3,25.63,-109.28,26.53,-113.76,31.56,-114.93,31.9,-114.63,30.16,-109.42,23.48,-110.01,22.89,-112.07,24.84,-112.38,26.21,-114.99,27.74,-114.07,27.68,-114.05,28.43,-115.67,29.76,-117.47,33.3,-120.64,34.58,-122.5,37.54,-121.53,38.06,-123,37.99,-123.7,38.91,-124.54,42.81,-123.99,46.22,-123.22,46.15,-124.07,46.28,-124.71,48.38,-122.78,48.14,-122.63,47.14,-122.88,49.4,-124.7,49.96,-124.86,50.87,-127.71,51.15,-126.69,51.7,-127.85,51.67,-126.71,52.06,-127.01,52.84,-128.1,51.79,-128.05,52.91,-129.17,53.53,-127.93,53.27,-128.53,53.86,-130.34,53.72,-129.56,55.46,-130.05,55.06,-130.03,55.89,-130.54,54.75,-131.03,56.09,-132.12,55.57,-131.55,56.21,-133.47,57.17,-133.88,58.52,-135.36,59.42,-135.09,58.25,-136.15,59.05,-137,59.02,-136.06,58.45,-136.61,58.24,-139.77,59.53,-139.43,60.01,-144.15,60.02,-147.75,61.22,-148.43,59.99,-151.74,59.19,-151.36,60.72,-149.08,60.88,-149.63,61.49,-153.03,60.3,-154.18,59.16,-153.44,58.75,-158.48,56.08,-163.34,54.84,-157.46,57.51,-156.81,59.13,-162.14,58.64,-161.95,60.68,-163.91,59.81,-165.35,60.54,-163.59,60.9,-166.17,61.65,-164.41,63.22,-160.93,63.66,-161.49,64.43,-160.89,64.8,-166.14,64.58,-166.93,65.16,-166.16,65.29,-168.09,65.66,-164.46,66.59,-161.03,66.19,-162.36,66.95,-160.23,66.42,-166.79,68.36,-156.47,71.41,-135.26,68.68,-135.91,69.11,-134.41,69.68,-129.62,70.17,-133.14,68.75,-127.99,70.57,-125.52,69.35,-124.56,70.15,-124.34,69.36,-122.07,69.82,-114.99,68.85,-113.96,68.4,-115.13,67.82,-110.07,67.99,-107.26,66.4,-107.96,67.82,-105.75,68.59,-108.31,68.61,-97.45,67.62,-98.65,68.36,-97.83,68.53,-95.97,68.25,-96.37,67.51,-95.42,67.01,-96.42,67.05,-95.79,66.62,-95.46,68.02,-93.45,68.62,-94.6,68.8,-93.43,69.38,-96.05,69.83,-96.52,71.13,-94.31,71.76",
    "-57.02,-63.37,-61.7,-64.99,-62.29,-65.92,-61.03,-66.34,-63.75,-66.28,-65.5,-67.38,-65.16,-68.62,-62.93,-68.44,-63.75,-68.7,-60.96,-71.24,-62.26,-72.02,-60.72,-72.07,-61.29,-72.6,-59.96,-73.03,-62.01,-73.15,-60.79,-73.71,-61.84,-74.03,-61.01,-74.48,-70.21,-76.67,-77.19,-76.63,-72.88,-77.69,-81.58,-77.85,-77.87,-78.75,-83.78,-77.98,-80.89,-79.5,-76.22,-79.39,-79.66,-80,-75.08,-80.86,-62.35,-81.58,-66.13,-81.95,-60.53,-82.2,-62.74,-82.53,-61.43,-83.4,-23.57,-79.96,-36.18,-78.47,-28.93,-76.37,-18.3,-75.43,-17.44,-74.38,-14.57,-73.94,-16.44,-73.43,-11.5,-72.41,-11.01,-71.76,-12.35,-71.39,-10.27,-70.94,-8.65,-71.67,-5.94,-70.71,-6.12,-71.33,-0.54,-71.71,13.07,-70.05,26.5,-71.02,32.62,-70,32.64,-68.87,33.47,-68.67,38.89,-70.17,40.22,-68.8,46.56,-67.27,48.37,-67.99,49.22,-67.23,48.47,-67.04,50.55,-67.19,50.33,-66.44,53.67,-65.86,57,-66.47,56.15,-67.26,69.56,-67.76,69.98,-68.46,69.08,-69.87,67.27,-70.27,69.25,-70.43,66.5,-73.13,67.32,-73.3,73.32,-69.85,84.49,-67.11,99.37,-66.65,102.67,-65.87,109.46,-66.91,113.1,-65.8,115.64,-66.77,114.03,-67.44,119.13,-67.37,135.35,-66.13,143.73,-66.88,144.62,-67.14,143.98,-67.86,145.98,-67.62,147.09,-68.37,153.91,-68.32,159.78,-69.52,162.19,-71.04,162.67,-70.3,170.44,-71.42,170.21,-72.57,168.43,-72.38,169.55,-73.05,166.45,-72.94,167.71,-73.39,164.81,-73.4,165.41,-74.56,160.91,-75.33,162.82,-75.85,162.45,-76.96,163.98,-78.22,167.05,-78.69,161.67,-78.54,161.95,-79.03,159.98,-79.59,160.56,-80.01,158.57,-80.42,160.64,-80.45,160.47,-81.34,163.6,-82.12,161.28,-82.49,180,-84.35,180,-90,-180,-90,-180,-84.35,-156.46,-85.19,-174.24,-82.79,-159.44,-83.54,-153.01,-82.45,-156.53,-81.16,-148.12,-80.9,-150.58,-80.35,-148.18,-79.78,-156.11,-78.74,-154.29,-78.26,-158.29,-77.95,-158,-77.09,-149.72,-77.8,-145.52,-77.2,-149.65,-76.37,-145.44,-76.41,-146.32,-76.02,-143.57,-75.56,-114.62,-73.9,-113.33,-74.45,-114.11,-74.98,-111.18,-74.19,-110.23,-74.54,-111.36,-75.22,-98.75,-75.32,-102.86,-73.78,-98.9,-73.61,-103.11,-72.72,-90.92,-73.32,-88.78,-72.68,-82.18,-73.86,-80.44,-72.94,-77.05,-73.84,-69.28,-73.17,-66.83,-72.09,-68.71,-69.43,-66.97,-69.16,-66.68,-67.56,-67.49,-67.11,-66.5,-67.29,-63.76,-65.03,-57.02,-63.37",
    "141.229,41.373,141.455,41.405,141.4,41.096,141.43,40.723,141.463,40.611,141.797,40.291,141.991,39.792,141.977,39.429,141.901,39.111,141.659,38.975,141.546,38.763,141.467,38.404,141.108,38.338,140.962,38.149,140.928,37.95,141.036,37.467,141.002,37.115,140.968,37.002,140.73,36.732,140.574,36.231,140.622,36.059,140.874,35.725,140.639,35.661,140.457,35.51,140.417,35.267,140.355,35.181,140.059,35.038,139.92,34.9,139.844,34.915,139.799,34.957,139.843,35.01,139.826,35.297,140.097,35.585,139.988,35.668,139.835,35.658,139.768,35.495,139.65,35.409,139.666,35.319,139.744,35.252,139.675,35.149,139.474,35.299,139.249,35.278,139.134,35.155,139.086,34.839,138.983,34.698,138.838,34.619,138.761,34.699,138.803,34.975,138.904,35.025,138.72,35.124,138.577,35.086,138.253,34.733,138.189,34.596,137.543,34.664,137.062,34.583,137.288,34.704,137.275,34.773,137.032,34.766,136.963,34.835,136.944,34.722,136.871,34.733,136.853,34.979,136.897,35.036,136.804,35.05,136.69,34.984,136.533,34.678,136.88,34.434,136.854,34.324,136.33,34.177,135.916,33.562,135.695,33.487,135.453,33.553,135.128,34.007,135.1,34.288,135.309,34.417,135.416,34.617,135.355,34.654,135.042,34.631,134.74,34.765,134.247,34.714,133.968,34.527,133.445,34.433,133.142,34.302,133.019,34.33,132.657,34.246,132.421,34.353,132.313,34.325,132.238,34.227,132.146,33.839,131.741,34.052,131.233,33.948,131.072,34.021,130.919,33.976,130.889,34.262,131.004,34.393,131.354,34.413,132.26,35.022,132.698,35.418,132.923,35.511,133.267,35.557,133.376,35.459,133.615,35.511,133.981,35.507,135.174,35.747,135.265,35.722,135.232,35.592,135.327,35.526,135.68,35.503,135.903,35.607,136.095,35.768,136.006,35.991,136.067,36.117,136.359,36.362,136.698,36.742,136.749,36.951,136.719,37.198,136.843,37.382,137.323,37.522,137.338,37.437,136.9,37.118,136.994,37.027,137.017,36.837,137.246,36.753,137.343,36.77,137.514,36.952,138.32,37.218,138.633,37.472,138.885,37.844,139.364,38.099,139.521,38.503,139.802,38.882,139.912,39.229,140.037,39.411,140.065,39.624,139.995,39.855,139.742,39.921,139.908,40.022,140.011,40.26,139.924,40.534,139.967,40.673,140.281,40.846,140.344,41.006,140.315,41.161,140.386,41.23,140.628,41.195,140.679,40.893,140.749,40.83,140.936,40.941,141.119,40.882,141.225,40.988,141.244,41.206,141.2,41.244,140.801,41.139,140.802,41.254,140.86,41.425,140.937,41.506,141.229,41.373",
    "-29.95,83.56,-25.8,83.26,-32.03,82.98,-21.69,82.68,-29.89,82.05,-21.34,82.07,-23.12,80.78,-19.63,81.64,-11.43,81.46,-20.15,80.01,-18.99,79.18,-21.13,78.66,-21.73,77.71,-18.34,76.92,-22.61,76.68,-19.86,76.12,-19.53,75.18,-22.23,75.12,-19.27,74.34,-21.98,74.57,-22.34,74.06,-20.64,73.46,-25.52,73.85,-24.79,73.51,-27.56,73.14,-22.04,72.92,-22.29,72.12,-24.63,73.04,-26.66,72.72,-24.81,72.9,-25.12,72.35,-21.96,71.74,-22.48,71.38,-21.75,71.48,-21.52,70.53,-27.09,71.63,-25.74,71.18,-29.07,70.44,-22.29,70.03,-26.48,68.68,-32.33,68.44,-34.63,66.43,-40.17,65.56,-41.09,65.04,-40.18,64.48,-41.58,64.3,-40.55,63.73,-42.94,62.72,-42.11,61.86,-43.91,59.82,-46.05,60.62,-45.87,61.22,-48.18,60.77,-49.29,61.59,-48.83,62.08,-50.32,62.47,-49.79,63.04,-51.55,64.01,-50.26,64.21,-51.71,64.21,-50.12,64.7,-50.96,65.2,-51.92,64.22,-52.54,65.33,-51.09,65.78,-53.39,66.05,-51.23,66.88,-53.61,66.15,-52.39,66.88,-53.8,67.42,-50.61,67.53,-53.74,67.55,-51.21,68.33,-53.04,68.61,-50.3,69.17,-51.08,69.21,-50.32,70.03,-54.53,70.7,-50.68,70.4,-53.01,71.18,-51.78,71.68,-53.44,71.58,-53.65,72.36,-53.96,71.46,-55.59,71.55,-54.74,72.87,-58.52,75.69,-68.32,76.09,-69.48,76.4,-68.11,76.65,-71.15,77.07,-66.31,77.56,-72.82,78.19,-65.83,79.17,-64.18,80.1,-67,80.41,-60.43,81.92,-56.62,81.36,-59.26,82.01,-54.55,82.35,-53.56,81.65,-53.02,82.32,-49.54,81.92,-50.94,82.38,-50.04,82.47,-44.73,81.78,-44.33,82.47,-45.56,82.75,-41.37,82.75,-46.17,83.06,-29.95,83.56",
    "143.824,44.117,144.101,44.102,144.482,43.95,144.715,43.928,144.872,43.982,145.37,44.327,145.352,44.23,145.126,43.869,145.101,43.765,145.14,43.663,145.341,43.303,145.488,43.28,145.674,43.389,145.833,43.386,145.624,43.291,145.505,43.174,145.347,43.177,144.921,43.001,144.631,42.947,144.197,42.974,143.969,42.881,143.581,42.599,143.429,42.419,143.314,42.084,143.237,42,142.508,42.258,141.851,42.579,141.407,42.547,140.986,42.342,140.71,42.556,140.48,42.559,140.351,42.435,140.327,42.293,140.528,42.132,140.734,42.116,141.151,41.805,141,41.737,140.66,41.816,140.385,41.519,140.27,41.456,140.149,41.423,140.037,41.474,139.995,41.576,140.108,41.913,140.057,42.067,139.835,42.278,139.86,42.582,139.891,42.649,140.115,42.733,140.432,42.954,140.486,43.05,140.397,43.167,140.392,43.303,140.487,43.338,140.819,43.205,141.138,43.18,141.296,43.2,141.374,43.28,141.412,43.381,141.398,43.643,141.645,44.019,141.661,44.264,141.761,44.483,141.782,44.716,141.719,44.941,141.583,45.156,141.668,45.401,141.938,45.51,142.885,44.67,143.289,44.397,143.824,44.117",
    "131.175,33.603,131.366,33.571,131.583,33.652,131.696,33.603,131.711,33.502,131.537,33.274,131.897,33.255,131.848,33.118,131.949,33.047,131.91,32.974,132.009,32.919,132.002,32.882,131.66,32.466,131.46,31.883,131.46,31.671,131.337,31.405,131.071,31.437,131.035,31.378,131.098,31.256,130.686,31.015,130.79,31.269,130.704,31.577,130.796,31.624,130.776,31.706,130.655,31.718,130.556,31.563,130.54,31.403,130.645,31.267,130.589,31.179,130.201,31.292,130.147,31.408,130.294,31.451,130.322,31.601,130.188,31.769,130.194,32.091,130.395,32.219,130.641,32.619,130.498,32.657,130.569,32.734,130.547,32.832,130.382,33.093,130.238,33.178,130.127,33.105,130.175,32.851,130.326,32.853,130.34,32.702,130.246,32.677,130.054,32.771,129.769,32.571,129.827,32.725,129.69,32.875,129.679,33.06,129.828,32.893,129.992,32.852,129.897,33.022,129.58,33.236,129.61,33.344,129.844,33.322,129.826,33.437,130.168,33.598,130.365,33.634,130.484,33.835,130.716,33.928,130.953,33.872,131.058,33.673,131.175,33.603",
    "-86.59,71.01,-84.82,71.03,-85.91,71.99,-84.28,72.04,-85.65,72.72,-84.26,72.8,-85.45,73.11,-81.61,73.7,-80.28,72.77,-80.93,71.91,-76.89,72.72,-75.12,72.38,-75.92,71.72,-74.27,72.04,-75,71.22,-71.64,71.52,-72.63,70.83,-70.67,71.05,-71.43,70.13,-69.17,70.76,-68.36,70.48,-70.06,70.04,-67.17,69.8,-69.25,69.51,-66.69,69.29,-69.32,68.86,-61.3,66.65,-63.46,65.85,-63.61,64.93,-65.4,65.76,-64.45,66.32,-68.75,66.2,-64.41,63.71,-65.19,63.76,-65.11,62.63,-68.91,63.7,-66.32,61.87,-71.35,63.07,-73.27,64.58,-78.05,64.5,-77.33,65.45,-75.45,64.84,-73.55,65.49,-74.42,66.17,-72.22,67.25,-74.72,69.05,-76.59,68.7,-75.65,69.21,-76.23,69.66,-79.07,70.6,-78.82,70.01,-80.92,69.73,-88.85,70.52,-89.46,71.06,-87.14,71.01,-89.85,71.49,-89.23,73.11,-85.01,73.78,-86.67,72.76,-85.02,71.35,-86.59,71.01",
    "143.18,-11.95,143.76,-14.35,145.29,-14.94,146.38,-18.98,148.76,-20.29,149.7,-22.44,150.62,-22.37,153.16,-25.96,153.62,-28.67,152.94,-31.43,149.93,-37.53,146.4,-39.15,144.89,-37.9,143.54,-38.82,141.42,-38.36,139.78,-37.25,139.28,-35.38,138.18,-35.61,138.09,-34.17,136.88,-35.24,137.78,-32.58,135.65,-34.94,134.23,-32.55,131.14,-31.5,125.92,-32.3,123.51,-33.92,119.85,-33.97,117.86,-35.05,115.01,-34.26,115.7,-31.69,113.18,-26.18,113.84,-26.5,113.45,-25.6,114.22,-26.29,113.42,-24.44,114.02,-21.88,114.14,-22.48,116.71,-20.65,121,-19.6,122.26,-17.14,122.97,-16.44,123.56,-17.52,123.61,-16.22,124.77,-16.4,124.44,-15.49,126.05,-13.98,127.46,-14.03,128.07,-15.33,129.63,-15.14,130.62,-12.43,132.71,-12.12,131.96,-11.18,136.54,-11.96,135.45,-14.92,140.51,-17.62,142.17,-10.95,143.18,-11.95",
    "-69.49,83.02,-61.27,82.28,-68.69,81.29,-64.83,81.44,-70.71,80.54,-72.06,80.12,-70.57,80.09,-71.39,79.76,-76.9,79.51,-74.53,79.05,-78.58,79.08,-74.43,78.72,-78.49,77.37,-81.66,77.53,-78,76.85,-80.69,76.18,-89.5,76.83,-86.81,77.18,-87.76,77.84,-82.66,77.89,-87.55,78.18,-81.75,78.98,-84.41,79,-86.5,80.26,-80.48,79.61,-82.99,80.32,-76.86,80.86,-78.72,80.95,-76.89,81.43,-85.15,80.52,-86.44,80.73,-83.29,81.15,-87.71,80.66,-89.17,80.94,-84.94,81.29,-91.68,81.64,-84.9,82.45,-79.42,81.85,-82.45,82.4,-79.89,82.94,-69.49,83.02",
    "134.357,34.256,134.637,34.227,134.675,33.848,134.739,33.821,134.377,33.608,134.243,33.439,134.182,33.247,133.959,33.448,133.632,33.511,133.286,33.36,133.146,33.083,133.016,32.984,132.977,32.842,132.804,32.752,132.642,32.762,132.709,32.902,132.495,32.917,132.493,33.008,132.428,33.059,132.511,33.293,132.405,33.331,132.413,33.43,132.033,33.34,132.643,33.69,132.784,33.992,132.935,34.095,132.99,34.088,133.134,33.927,133.193,33.933,133.582,34.017,133.643,34.135,133.603,34.244,133.706,34.237,133.948,34.348,134.076,34.358,134.357,34.256",
    "133.47,-0.73,135.09,-3.35,137.91,-1.48,144.48,-3.83,147.8,-6.32,146.96,-6.93,148.58,-9.05,150.85,-10.24,147.77,-10.07,144.51,-7.57,142.21,-8.2,143.38,-8.76,142.65,-9.33,141.13,-9.22,140.12,-7.92,138.93,-8.26,138.34,-5.68,133.97,-3.82,133.84,-3.05,132.97,-4.09,132.01,-2.86,133.92,-2.1,132.31,-2.24,131,-1.42,131.26,-0.86,133.47,-0.73",
    "-3.11,58.52,-4.13,57.58,-1.78,57.47,-3.79,56.1,-1.66,55.57,0.05,52.91,1.66,52.75,0.42,51.47,1.4,51.18,-5.62,50.05,-2.43,51.74,-5.17,51.74,-3.98,52.54,-4.27,53.14,-2.75,53.31,-2.85,54.14,-3.59,54.56,-3.04,54.95,-5.03,54.76,-4.58,55.94,-5.73,55.33,-5.19,56.76,-6.13,56.71,-5.02,58.57,-3.11,58.52",
    "148.6,45.318,148.262,45.217,147.914,44.99,147.658,44.977,147.563,44.836,147.31,44.678,147.207,44.554,146.897,44.404,146.933,44.513,147.141,44.663,147.155,44.766,147.247,44.856,147.886,45.226,147.873,45.3,147.924,45.383,148.056,45.262,148.324,45.282,148.612,45.485,148.773,45.526,148.826,45.486,148.837,45.363,148.6,45.318",
    "-114.52,72.59,-110.01,72.98,-107.81,71.63,-107.31,71.89,-108.24,73.15,-106.48,73.2,-104.51,71.06,-100.91,69.81,-103.43,69.67,-101.79,69.18,-102.9,68.82,-106.66,69.44,-113.13,68.49,-117.2,70.05,-111.63,70.31,-117.59,70.63,-118.27,71.03,-115.3,71.49,-118.99,71.76,-116.57,73.05,-114.3,73.33,-114.52,72.59",
    "-55.46,51.54,-56.82,49.61,-56.18,50.11,-55.35,49.08,-53.62,49.32,-54.11,48.39,-53.03,48.63,-53.87,48.02,-52.87,48.11,-53.07,46.68,-54.17,46.88,-54.19,47.86,-55.79,46.87,-54.78,47.66,-59.26,47.63,-57.04,51.01,-55.46,51.54",
    "-91.89,81.13,-85.04,79.28,-88.04,79,-88.82,78.19,-92.68,78.39,-94.16,78.99,-91.3,79.37,-95.1,79.29,-94.4,79.74,-96.77,80.14,-94.26,80.19,-96.39,80.32,-93.93,80.56,-95.51,80.84,-94.18,81.34,-91.89,81.13",
    "-108.29,76.06,-105.63,75.95,-105.97,75.13,-112.52,74.42,-114.31,74.72,-111.09,75.26,-117.6,75.27,-115.14,75.68,-117.16,75.64,-114.99,75.9,-116.66,75.96,-115,76.5,-109.09,75.51,-110.31,76.4,-108.83,76.82,-108.29,76.06",
    "121.1,18.62,122.27,18.46,122.52,17.12,121.39,15.32,121.77,14.17,123.82,13.84,124.06,12.57,122.6,13.91,122.6,13.19,120.64,13.8,120.94,14.65,120.08,14.85,119.77,16.26,120.37,16.11,121.1,18.62",
    "124.89,1,120.19,0.27,120.67,-1.37,123.43,-0.78,121.36,-1.88,122.87,-4.39,121.59,-4.76,120.65,-2.67,120.43,-5.59,119.56,-5.61,118.78,-2.72,120.27,0.97,123.93,0.85,124.99,1.7,124.89,1",
    "116.81,6.69,119.26,5.37,117.06,3.62,118.98,0.98,117.91,1.1,115.96,-3.6,114.69,-4.17,114.34,-3.24,110.26,-2.97,109.08,1.5,109.63,2.03,111.22,1.4,111.51,2.74,115.43,4.97,116.81,6.69",
    "-15.54,66.23,-14.6,66.38,-15.12,66.1,-13.6,65.04,-18.65,63.41,-22.65,63.83,-21.59,64.63,-24.03,64.86,-21.84,65.45,-24.48,65.53,-22.44,65.91,-22.89,66.44,-21.13,65.27,-20.21,66.1,-15.54,66.23",
    "128.259,26.653,127.867,26.442,127.905,26.328,127.79,26.255,127.804,26.153,127.653,26.095,127.729,26.434,127.946,26.594,127.891,26.631,127.907,26.694,128.047,26.643,128.098,26.668,128.255,26.882,128.332,26.812,128.259,26.653",
    "96.49,5.23,97.55,5.21,102.95,0.66,102.55,0.22,103.67,0.29,104.65,-2.6,106.04,-3.11,105.75,-5.82,104.6,-5.9,101.58,-3.17,98.6,1.86,95.43,4.87,95.28,5.59,96.49,5.23",
    "16.79,79.91,21.39,78.74,19.15,78.38,16.7,76.58,14,77.51,16.91,77.9,13.68,78.03,16.78,78.66,13.15,78.24,10.68,79.76,14.83,79.77,16.34,78.98,15.83,79.71,16.79,79.91",
    "-179.8,68.94,-175.35,67.68,-174.07,66.23,-174.55,67.09,-173.68,67.14,-169.73,66.06,-172.78,65.68,-172.21,65.05,-173.16,64.28,-178.41,65.5,-178.53,66.4,-179.68,66.18,-180,65.07,-179.8,68.94",
    "146.208,44.498,146.356,44.425,146.568,44.44,146.516,44.375,146.112,44.246,145.914,44.104,145.767,43.941,145.587,43.845,145.556,43.665,145.439,43.737,145.462,43.871,145.748,44.072,146.112,44.5,146.208,44.498",
    "173.12,-41.28,174.3,-41.02,174.28,-41.74,172.62,-43.27,173.07,-43.87,171.24,-44.26,170.78,-45.87,169.1,-46.63,166.49,-45.96,171.04,-42.86,172.27,-40.76,172.94,-40.52,173.12,-41.28",
    "49.54,-12.43,50.4,-15.63,49.66,-15.52,47.18,-24.79,45.12,-25.54,44.04,-25,43.26,-22.38,44.4,-19.92,43.98,-17.39,44.48,-16.22,47.96,-14.67,47.94,-13.66,49.54,-12.43",
    "126.01,9.32,126.58,7.25,126.19,6.31,125.69,7.26,125.35,5.6,123.67,7.82,121.96,6.97,123.43,8.7,123.8,8.05,125.47,9.76,126.01,9.32",
    "-7.18,55.06,-5.47,54.5,-6.35,53.99,-6.33,52.25,-10.34,51.8,-8.78,52.68,-9.92,52.57,-8.93,53.21,-10.09,53.41,-10.06,54.26,-7.18,55.06",
    "138.344,37.822,138.225,37.829,138.283,37.854,138.322,37.97,138.246,37.995,138.25,38.078,138.504,38.316,138.454,38.076,138.575,38.066,138.497,37.904,138.344,37.822",
    "67.77,76.24,61.36,75.31,56.63,73.3,53.76,73.77,56.14,74.5,55.92,75.17,61.2,76.28,67.65,77.01,68.94,76.71,67.77,76.24",
    "-45.22,-78.81,-43.54,-78.9,-42.94,-79.58,-43.53,-80.19,-54.35,-80.76,-50.4,-79.51,-49.08,-78.05,-44.59,-78.04,-43.85,-78.53,-45.22,-78.81",
    "-70.05,-69.19,-68.31,-70.91,-69.21,-72.53,-75.38,-71.83,-69.87,-71.13,-71.19,-70.66,-69.62,-70.4,-71.73,-70.05,-72.14,-69.18,-70.05,-69.19",
    "-69.17,-52.67,-65.18,-54.68,-71.9,-54.6,-70.31,-54.53,-70.53,-53.63,-69.05,-54.43,-70.15,-53.89,-69.39,-53.37,-70.46,-53.21,-69.17,-52.67",
    "149.688,45.642,149.447,45.593,149.666,45.84,149.796,45.876,149.962,46.022,150.309,46.2,150.553,46.209,150.235,46.012,150.195,45.933,149.688,45.642",
    "126.327,33.224,126.24,33.215,126.166,33.312,126.338,33.46,126.696,33.549,126.901,33.515,126.931,33.444,126.873,33.341,126.582,33.238,126.327,33.224",
    "-100,73.95,-97.11,73.79,-98.43,72.96,-96.54,72.7,-96.61,71.83,-99.17,71.37,-102.66,72.72,-100.13,72.91,-101.52,73.49,-100,73.95",
    "-94.29,76.91,-89.28,76.3,-91.41,76.22,-88.92,75.45,-82.15,75.83,-79.4,74.92,-91.55,74.66,-93.09,76.35,-96.88,76.74,-94.29,76.91",
    "127.73,0.85,128.69,1.57,128.26,0.73,128.9,0.22,127.89,0.3,128.43,-0.89,127.43,1.14,128.04,2.2,127.73,0.85",
    "140.05,75.83,145.36,75.53,144.02,75.04,142.31,75.69,143.13,74.97,139.1,74.66,137.01,75.24,137.27,75.75,140.05,75.83",
    "173.27,-34.93,176.11,-37.65,178.54,-37.69,175.31,-41.61,174.64,-41.29,175.16,-40.11,173.76,-39.32,174.93,-37.08,173.27,-34.93",
    "142.76,54.39,144.71,48.64,143.1,49.2,142.56,47.74,143.58,46.36,142.58,46.7,142.08,45.92,141.66,52.27,142.76,54.39",
    "-71.95,19.72,-69.96,19.67,-68.36,18.54,-71.44,17.64,-73.88,18.04,-74.39,18.62,-72.35,18.62,-73.4,19.81,-71.95,19.72",
    "55.32,73.31,56.43,73.2,55.3,71.94,57.63,70.73,53.72,70.81,51.44,71.78,53.25,73.18,55.32,73.31",
    "152.002,46.897,151.816,46.787,151.754,46.788,151.715,46.853,151.864,46.869,152.166,47.11,152.289,47.142,152.002,46.897",
    "121.863,31.492,121.78,31.464,121.52,31.55,121.336,31.644,121.211,31.805,121.464,31.756,121.577,31.637,121.863,31.492",
    "-119.74,74.11,-115.39,73.5,-120.62,71.51,-123.1,71.09,-125.85,71.98,-123.8,73.77,-124.7,74.35,-119.74,74.11",
    "-98.09,-71.91,-96.12,-71.9,-96.98,-72.22,-95.61,-72.07,-96.05,-72.58,-102.31,-72.08,-98.09,-71.91",
    "107.37,-6.01,112.54,-6.93,114.41,-7.79,114.58,-8.77,106.46,-7.37,105.27,-6.73,107.37,-6.01",
    "-81.84,23.16,-74.15,20.17,-77.72,19.86,-77.23,20.64,-81.84,22.67,-84.84,21.83,-81.84,23.16",
    "-127.2,50.64,-125.48,50.32,-123.28,48.46,-127.86,50.13,-127.47,50.58,-128.3,50.79,-127.2,50.64",
    "129.453,28.209,129.366,28.128,129.165,28.25,129.69,28.517,129.71,28.432,129.457,28.272,129.453,28.209",
    "-97.7,76.47,-97.34,75.42,-97.99,75.05,-102.8,75.6,-100.97,75.8,-101.79,76.45,-97.7,76.47",
    "21.61,78.6,24.9,77.76,20.93,77.46,21.65,77.92,20.23,78.48,21.61,78.6",
    "151.92,-4.3,152.08,-5.46,150.47,-6.26,148.34,-5.67,150.9,-5.45,151.92,-4.3",
    "97.67,80.16,100.06,79.78,99.04,79.29,99.44,78.83,93.07,79.5,97.67,80.16",
    "-49.63,-0.23,-48.39,-0.3,-48.83,-1.39,-50.51,-1.79,-50.65,-0.27,-49.63,-0.23",
    "-103.43,79.32,-99,78,-104.76,78.35,-103.37,78.74,-105.44,79.3,-103.43,79.32",
    "-152.9,57.82,-152.22,57.58,-153.97,56.77,-154.71,57.34,-152.9,57.82",
    "-63.81,46.47,-62.02,46.42,-63.64,46.23,-63.99,47.06,-63.81,46.47",
    "145.04,-40.79,148.22,-40.85,147.98,-43.16,146.04,-43.55,145.04,-40.79",
    "96.53,81.08,97.87,80.76,97.18,80.24,91.52,80.36,96.53,81.08",
    "121.01,22.62,120.74,21.96,120.13,23.65,121.59,25.28,121.01,22.62",
    "110.89,19.99,110.07,18.45,108.7,18.54,109.26,19.88,110.89,19.99",
    "79.98,9.81,81.87,7.29,80.72,5.98,79.86,6.83,79.98,9.81",
    "-59.73,-80.34,-60.58,-80.95,-66.77,-80.29,-60.58,-79.74,-59.73,-80.34",
    "20.9,80.25,27.2,79.91,22.9,79.23,18.32,79.86,20.9,80.25",
    "9.63,40.88,9.56,39.17,8.65,38.93,8.22,40.91,9.63,40.88",
    "-52.73,69.94,-51.9,69.6,-53.58,69.26,-54.92,69.71,-52.73,69.94",
    "-84.92,65.26,-80.26,63.8,-87.15,63.59,-85.81,65.83,-84.92,65.26",
    "-79.54,73.65,-76.09,72.88,-79.82,72.83,-80.85,73.72,-79.54,73.65",
    "-96.2,78.53,-94.93,78.08,-96.99,77.81,-98.34,78.75,-96.2,78.53",
    "-110.46,78.1,-109.62,78.06,-110.68,77.45,-113.28,77.81,-110.46,78.1",
    "-93.17,74.16,-90.38,73.82,-95.19,72.03,-95.63,73.7,-93.17,74.16",
    "117.31,8.44,119.55,11.31,119.69,10.5,117.31,8.44",
    "129.75,-2.87,130.81,-3.86,127.9,-3.5,129.75,-2.87",
    "106.05,-1.67,106.67,-3.07,105.13,-2.04,106.05,-1.67",
    "-126.33,-73.29,-123.84,-74.23,-127.21,-73.72,-126.33,-73.29",
    "127.3,-8.42,123.6,-10.27,125.18,-8.65,127.3,-8.42",
    "102.88,79.25,105.31,78.5,99.29,78.04,102.88,79.25",
    "142.18,73.9,143.45,73.23,139.69,73.43,142.18,73.9",
    "-159.05,-79.81,-164.28,-79.25,-162.39,-78.76,-159.05,-79.81",
    "-70.33,-79.68,-71.45,-79.13,-66.73,-78.38,-70.33,-79.68",
    "15.58,38.22,15.11,36.69,12.44,37.82,15.58,38.22",
    "-93.54,75.03,-96.6,75.03,-94.88,75.63,-93.54,75.03",
    "-115.55,77.36,-117.23,76.28,-122.9,76.13,-115.55,77.36",
    "-97.44,69.64,-95.27,68.83,-99.44,68.92,-97.44,69.64",
    "15.76,68.56,14.26,68.19,15.97,69.3,15.76,68.56",
]


def _load_rings():
    rings = []
    for s in LAND:
        v = [float(x) for x in s.split(",")]
        pts = list(zip(v[0::2], v[1::2]))
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        rings.append(((min(xs), min(ys), max(xs), max(ys)), pts))
    return rings


LAND_RINGS = _load_rings()


if __name__ == "__main__":
    import sys

    if "--selftest" in sys.argv:
        _selftest()
        sys.exit()

    import sv_ttk

    root = tk.Tk()
    root.geometry("1200x700")
    root.title("経路の地理可視化")
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
    tab = GeoMapTab(frame, ctx)
    for i, arg in enumerate(sys.argv):
        if arg == "--host" and i + 1 < len(sys.argv):
            tab.host_var.set(sys.argv[i + 1])
    if "--auto" in sys.argv:
        root.after(400, tab.start)
    root.protocol("WM_DELETE_WINDOW", lambda: (tab.on_close(), root.destroy()))
    root.mainloop()
