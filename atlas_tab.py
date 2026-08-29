#!/usr/bin/env python3
"""RIPE Atlas タブ: 世界中のプローブから見た「自宅回線の外側」を測る。

このアプリの他の測定はすべて「自宅PC -> 外」の一方向。ここだけは逆方向、
つまり「世界中の観測点 -> 自分のISP(AS)」を見る。上り方向の疑いがある回線では
この向きの情報が効く。

■ 認証まわり (2026-08-24 に実機で確認した結果。推測ではない)
  GET  /api/v2/probes/                 -> 200 (認証不要)
  GET  /api/v2/measurements/           -> 200 (認証不要)
  GET  /api/v2/measurements/{id}/results/ -> 200 (認証不要。公開計測なら誰でも読める)
  GET  /api/v2/credits/                -> 401 {"detail":"Authentication credentials were not provided."}
  POST /api/v2/measurements/           -> 401 (同上)
  認証は Authorization: Key <uuid> ヘッダのみ。?key=<uuid> のクエリ形式は
  「credentials were not provided」になり現在は通らない(実機確認済み)。
  不正なキーだと detail が "The provided API key does not exist" に変わるので
  「キー未指定」と「キーが間違っている」は区別できる。

■ 逆方向をどう取るか
  measurements?target_asn=<ASN> で「そのASを宛先にした公開計測」が引ける
  (AS17676 で 47,000 件以上ヒットする)。これは世界中のプローブから自分のISPへ
  撃たれた ping であり、まさに外から見た自分側の姿になる。個々の結果は
  /measurements/{id}/results/ から認証なしで読める。
  target_ip=<自宅IP> は 0 件 — 個人回線のIPを狙った公開計測は当然存在しない。
  自宅IPそのものを測るには APIキー + クレジットで one-off 計測を作るしかない。

■ 断定しないこと
  外から応答が無い = 回線が悪い、ではない。ICMPフィルタ、プローブ側の障害、
  計測自体の失敗など別解釈が常にある。画面の文言もそのように書いてある。
"""
import http.client
import json
import re
import statistics
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk

import network_diag as nd
from settings_store import app_dir as _app_dir
from settings_store import settings

API_HOST = "atlas.ripe.net"
KEY_PATH = _app_dir() / "atlas_key.txt"  # settings.json とは別ファイル。平文JSONに混ぜない
UA = "network-diag/1.0 (+atlas_tab)"
HTTP_TIMEOUT = 30
MAX_RESULT_BYTES = 2_000_000   # 1計測の結果が巨大なことがある(実測: msm 1001 の15分ぶんで20MB)
INTER_REQ_SLEEP = 0.15         # 連続リクエストの間隔。429 回避
DEFAULT_MSM_COUNT = 20

# 公開計測の credits_per_result を実測して逆算した単価(2026-08 時点)。
# ping: 1pkt=2 / 3pkt=6 / 16pkt=32 -> 2 * packets
# traceroute: 3pkt=60 / 5pkt=100 -> 20 * packets
# APIは事前見積りを返さないので、あくまで「概算」として表示する。
CREDIT_PER_PACKET = {"ping": 2, "traceroute": 20}

DISCLAIMER = (
    "※この結果は「外から見た姿」の一部でしかありません。応答が無い/少ない場合でも回線の問題とは限らず、"
    "自宅や上流のICMPフィルタ、プローブ側の障害、公開計測そのものの失敗など別の解釈が常にあります。"
    "ここの数字だけで回線の良し悪しを断定しないでください。"
)


# ---------- API ----------

class ApiError(Exception):
    pass


def _request(method, path, key=None, payload=None, max_bytes=None):
    """RIPE Atlas REST API を叩く。-> パース済みJSON。nd.lookup_ip_info と同じ http.client 流儀。"""
    headers = {"User-Agent": UA, "Accept": "application/json"}
    if key:
        headers["Authorization"] = f"Key {key}"   # 実機確認済みの唯一の認証形式
    body = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    conn = http.client.HTTPSConnection(API_HOST, timeout=HTTP_TIMEOUT)
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        if max_bytes is not None:
            try:
                length = int(resp.getheader("Content-Length") or 0)
            except ValueError:
                length = 0
            if length > max_bytes:
                raise ApiError(f"__toobig__:{length}")
        raw = resp.read()
        status = resp.status
    finally:
        conn.close()
    if status == 429:
        raise ApiError("APIのレート制限(429)に当たりました。数分おいてから再実行してください。")
    try:
        data = json.loads(raw.decode("utf-8", "replace")) if raw else {}
    except ValueError:
        raise ApiError(f"APIの応答をJSONとして解釈できませんでした (HTTP {status})")
    if status >= 400:
        raise ApiError(f"HTTP {status}: {api_error_detail(data)}")
    return data


def api_error_detail(data):
    """RIPE Atlas のエラーJSONから人間向けの一行を取り出す。"""
    err = data.get("error") if isinstance(data, dict) else None
    if not isinstance(err, dict):
        return str(data)[:200]
    detail = err.get("detail")
    if isinstance(detail, list):
        detail = " / ".join(str(x) for x in detail)
    sub = err.get("errors")
    if not detail and isinstance(sub, list) and sub:
        detail = "; ".join(str(e.get("detail")) for e in sub if isinstance(e, dict))
    return detail or err.get("title") or str(err)[:200]


# ---------- パース / 集計 (純粋関数。--selftest の対象) ----------

def parse_asn(org):
    """ipinfo の org 文字列 'AS17676 SoftBank Corp.' -> 17676。取れなければ None。"""
    if not org:
        return None
    m = re.search(r"\bAS(\d+)\b", str(org))
    return int(m.group(1)) if m else None


def parse_ping_result(rec):
    """RIPE Atlas の ping 結果 1件 -> 表示用dict。

    実物のレスポンスで確認した形:
      応答あり: {"rcvd":5,"sent":5,"min":19.3,"avg":19.46,"max":19.7,"result":[{"rtt":19.7},...]}
      全ロス:   {"rcvd":0,"sent":3,"min":-1,"avg":-1,"max":-1,"result":[{"x":"*"},{"x":"*"},{"x":"*"}]}
    未応答時に min/avg/max が -1 で入る点が要注意 (0ms と誤読しない)。
    """
    packets = rec.get("result") or []
    rtts = [p["rtt"] for p in packets if isinstance(p, dict) and isinstance(p.get("rtt"), (int, float))]
    sent = rec.get("sent")
    if not isinstance(sent, int) or sent < 0:
        sent = len(packets)
    rcvd = rec.get("rcvd")
    if not isinstance(rcvd, int) or rcvd < 0:
        rcvd = len(rtts)

    def num(v):
        return round(float(v), 2) if isinstance(v, (int, float)) and v >= 0 else None

    avg = num(rec.get("avg"))
    if avg is None and rtts:
        avg = round(sum(rtts) / len(rtts), 2)
    return {
        "prb_id": rec.get("prb_id"),
        "from": rec.get("from") or rec.get("src_addr") or "",
        "msm_id": rec.get("msm_id"),
        "dst": rec.get("dst_addr") or rec.get("dst_name") or "",
        "sent": sent,
        "rcvd": rcvd,
        "loss_pct": round((sent - rcvd) / sent * 100, 1) if sent else 100.0,
        "min_ms": num(rec.get("min")) if rec.get("min") is not None else (min(rtts) if rtts else None),
        "avg_ms": avg,
        "max_ms": num(rec.get("max")) if rec.get("max") is not None else (max(rtts) if rtts else None),
        "timestamp": rec.get("timestamp"),
    }


def summarize(rows):
    """行の集合 -> 「外から見た自宅回線」のサマリ。0件でも壊れないこと。"""
    responded = [r for r in rows if r["rcvd"] > 0 and r["avg_ms"] is not None]
    rtts = sorted(r["avg_ms"] for r in responded)
    n = len(rows)

    def pct(p):
        if not rtts:
            return None
        i = min(len(rtts) - 1, max(0, int(round((len(rtts) - 1) * p))))
        return rtts[i]

    return {
        "samples": n,
        "probes": len({r["prb_id"] for r in rows if r["prb_id"] is not None}),
        "responded": len(responded),
        "no_reply": n - len(responded),
        "no_reply_pct": round((n - len(responded)) / n * 100, 1) if n else 0.0,
        "median_ms": round(statistics.median(rtts), 1) if rtts else None,
        "p10_ms": pct(0.10),
        "p90_ms": pct(0.90),
        "min_ms": rtts[0] if rtts else None,
        "max_ms": rtts[-1] if rtts else None,
        "loss_pct": round(sum(r["loss_pct"] for r in rows) / n, 1) if n else 0.0,
    }


def histogram(values, nbins=14):
    """-> (edges, counts)。空・全部同値でも破綻しないこと。"""
    if not values:
        return [], []
    lo, hi = min(values), max(values)
    if hi - lo < 1e-9:
        hi = lo + 1.0
    width = (hi - lo) / nbins
    counts = [0] * nbins
    for v in values:
        counts[min(nbins - 1, int((v - lo) / width))] += 1
    return [lo + width * i for i in range(nbins + 1)], counts


def bar_rect(i, count, cmax, nbins, x0, y0, x1, y1, gap=2):
    """ヒストグラムの i 番目の棒の矩形 (bx0, by0, bx1, by1)。プロット枠を絶対にはみ出さない。"""
    bw = (x1 - x0) / max(nbins, 1)
    bx0 = x0 + bw * i + gap
    bx1 = max(bx0 + 1, x0 + bw * (i + 1) - gap)
    h = 0.0 if cmax <= 0 else (y1 - y0) * count / cmax
    return bx0, y1 - h, bx1, y1


def rtt_tag(ms):
    if ms is None:
        return "bad"
    return "good" if ms < 60 else ("warn" if ms < 150 else "bad")


def estimate_credits(kind, n_probes, packets):
    """one-off 計測の消費クレジット概算。公開計測の credits_per_result から逆算した単価を使う。"""
    return CREDIT_PER_PACKET.get(kind, 20) * max(1, packets) * max(1, n_probes)


# ---------- APIキーの保管 ----------

def load_key():
    try:
        return KEY_PATH.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def save_key(key):
    """settings.json ではなく専用ファイルに保存する(results/ の外)。空なら削除。"""
    key = (key or "").strip()
    if not key:
        try:
            KEY_PATH.unlink()
        except OSError:
            pass
        return None
    KEY_PATH.write_text(key + "\n", encoding="utf-8")
    return key


def mask_key(key):
    """画面表示用の伏せ字。先頭4文字と末尾4文字だけ残す。"""
    if not key:
        return "(未設定)"
    if len(key) <= 8:
        return "•" * len(key)
    return f"{key[:4]}{'•' * (len(key) - 8)}{key[-4:]}"


# ---------- タブ本体 ----------

PROBE_COLS = [("id", "ID", 70), ("cc", "国", 44), ("asn", "ASN", 70),
              ("status", "状態", 80), ("desc", "説明", 210)]
RESULT_COLS = [("prb", "プローブ", 64), ("cc", "国", 36), ("asn", "ASN", 60),
               ("src", "送信元IP", 96), ("dst", "宛先(自ISP内)", 96),
               ("sent", "送", 30), ("rcvd", "受", 30), ("loss", "ロス%", 48),
               ("min", "最小", 50), ("avg", "平均", 50), ("max", "最大", 50),
               ("msm", "計測ID", 76)]


def _with_scrollbar(box, tree):
    """Treeview に縦スクロールバーを付けて配置する(100件級の一覧になるため)。"""
    bar = ttk.Scrollbar(box, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=bar.set)
    tree.pack(side="left", fill="both", expand=True)
    bar.pack(side="right", fill="y")


class AtlasTab:
    def __init__(self, parent, ctx):
        self.ctx = ctx
        self.probes = []          # プローブ一覧 (検索結果)
        self.rows = []            # 計測結果の行
        self.summary_data = summarize([])
        self.probe_meta = {}      # prb_id -> {"cc","asn"}
        self.msm_used = []
        self.credits = None
        self.self_info = None
        self._busy = False
        self._stop = threading.Event()
        self._thread = None
        self._msg = ("RIPE Atlas: APIキーなしでもプローブ検索と公開計測の閲覧ができます。", "muted")

        # ---- 操作列 ----
        top = ttk.Frame(parent, padding=(6, 10, 6, 2))
        top.pack(fill="x")
        ttk.Label(top, text="自ASN").grid(row=0, column=0, padx=(0, 4))
        self.asn_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.asn_var, width=8).grid(row=0, column=1, padx=(0, 8))
        ttk.Label(top, text="国").grid(row=0, column=2, padx=(0, 4))
        self.cc_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.cc_var, width=5).grid(row=0, column=3, padx=(0, 8))
        self.scope_var = tk.StringVar(value="ASN")
        ttk.Combobox(top, textvariable=self.scope_var, width=9, state="readonly",
                     values=("ASN", "国", "ASN+国")).grid(row=0, column=4, padx=(0, 8))
        ttk.Button(top, text="🔍  プローブを検索", command=self.search_probes).grid(row=0, column=5, padx=3)
        ttk.Button(top, text="🌏  外から見た結果を取得", style="Accent.TButton",
                   command=self.fetch_public).grid(row=0, column=6, padx=3)
        ttk.Label(top, text="計測数").grid(row=0, column=7, padx=(8, 4))
        self.msm_n_var = tk.IntVar(value=DEFAULT_MSM_COUNT)
        ttk.Spinbox(top, from_=1, to=60, textvariable=self.msm_n_var, width=4).grid(row=0, column=8)
        ttk.Button(top, text="⬇  JSON保存", command=self.export).grid(row=0, column=9, padx=(10, 0))

        key = ttk.Frame(parent, padding=(6, 2, 6, 4))
        key.pack(fill="x")
        ttk.Label(key, text="APIキー").grid(row=0, column=0, padx=(0, 4))
        self.key_var = tk.StringVar(value=load_key() or "")
        ttk.Entry(key, textvariable=self.key_var, width=30, show="•").grid(row=0, column=1, padx=(0, 6))
        ttk.Button(key, text="保存", command=self.on_save_key).grid(row=0, column=2, padx=2)
        self.key_label = ttk.Label(key, text="")
        self.key_label.grid(row=0, column=3, padx=(8, 12))
        ttk.Button(key, text="残クレジット", command=self.fetch_credits).grid(row=0, column=4, padx=2)
        ttk.Label(key, text="自宅IPへ:").grid(row=0, column=5, padx=(14, 4))
        self.kind_var = tk.StringVar(value="ping")
        ttk.Combobox(key, textvariable=self.kind_var, width=10, state="readonly",
                     values=("ping", "traceroute")).grid(row=0, column=6, padx=(0, 6))
        ttk.Label(key, text="プローブ数").grid(row=0, column=7, padx=(0, 4))
        self.nprobe_var = tk.IntVar(value=5)
        ttk.Spinbox(key, from_=1, to=50, textvariable=self.nprobe_var, width=4).grid(row=0, column=8, padx=(0, 8))
        ttk.Button(key, text="⚡  one-off計測を作成", command=self.create_oneoff).grid(row=0, column=9, padx=2)

        self.status = ttk.Label(parent, text="", padding=(8, 3))
        self.status.pack(fill="x")

        # ---- 表とグラフ ----
        paned = ttk.PanedWindow(parent, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=6, pady=(2, 4))

        left = ttk.Frame(paned)
        self.probe_head = ttk.Label(left, text="同じISP / 国のプローブ", padding=(2, 2))
        self.probe_head.pack(fill="x")
        pbox = ttk.Frame(left)
        pbox.pack(fill="both", expand=True)
        self.probe_tree = ttk.Treeview(pbox, columns=[c[0] for c in PROBE_COLS], show="headings", height=8)
        for k, head, wd in PROBE_COLS:
            self.probe_tree.heading(k, text=head)
            self.probe_tree.column(k, width=wd, anchor="w" if k in ("desc", "status") else "e",
                                   stretch=(k == "desc"))
        _with_scrollbar(pbox, self.probe_tree)
        paned.add(left, weight=2)

        right = ttk.Frame(paned)
        self.result_head = ttk.Label(right, text="世界のプローブ → 自ISP (公開計測の結果)", padding=(2, 2))
        self.result_head.pack(fill="x")
        rbox = ttk.Frame(right)
        rbox.pack(fill="both", expand=True)
        self.result_tree = ttk.Treeview(rbox, columns=[c[0] for c in RESULT_COLS], show="headings", height=9)
        for k, head, wd in RESULT_COLS:
            self.result_tree.heading(k, text=head)
            self.result_tree.column(k, width=wd, anchor="w" if k in ("src", "dst") else "e",
                                    stretch=(k in ("src", "dst")))
        _with_scrollbar(rbox, self.result_tree)
        self.canvas = tk.Canvas(right, height=190, highlightthickness=1, bd=0)
        self.canvas.pack(fill="x", pady=(6, 4))
        self.canvas.bind("<Configure>", lambda e: self.draw())
        self.summary_label = tk.Label(right, anchor="w", justify="left", padx=8, pady=6)
        self.summary_label.pack(fill="x")
        paned.add(right, weight=5)

        self.note = ttk.Label(parent, text=DISCLAIMER, padding=(8, 4), wraplength=1120, justify="left")
        self.note.pack(fill="x")

        self.on_theme_changed()
        self._autodetect()

    # ---- テーマ ----

    def on_theme_changed(self):
        t = self.ctx.theme
        self.canvas.config(bg=t["graph_bg"], highlightbackground=t["graph_grid"])
        self.summary_label.config(bg=t["card_bg"], fg=t["fg"], font=(self.ctx.font, 9))
        for tree in (self.probe_tree, self.result_tree):
            for tag in ("good", "warn", "bad", "muted"):
                tree.tag_configure(tag, foreground=t.get(tag, t["fg"]))
        # sv_ttk が style.map に -foreground を入れており、そのままだと行タグ色が無視される。
        # 選択状態以外のマッピングを外してタグ色を優先させる (pathmon_tab.py と同じ対処)。
        style = ttk.Style()
        for opt in ("foreground", "background"):
            style.map("Treeview", **{opt: [s for s in style.map("Treeview", query_opt=opt)
                                           if s[0] in ("selected", "!selected")]})
        self._render_status()
        self._render_summary()
        self.draw()

    # ---- 共通 ----

    def _ui(self, fn, *args):
        """UI更新はメインスレッドへ。mainloop 終了後の after は RuntimeError になるので握り潰す。"""
        try:
            self.ctx.root.after(0, lambda: fn(*args))
        except RuntimeError:
            pass

    def _set_msg(self, text, kind="muted"):
        self._msg = (text, kind)
        self._render_status()

    def _render_status(self):
        text, kind = self._msg
        self.status.config(text=text, foreground=self.ctx.theme.get(kind, self.ctx.theme["muted"]))
        self.key_label.config(text=f"保存済み: {mask_key(load_key())}"
                              + (f"   クレジット: {self.credits:,}" if self.credits is not None else ""))

    def _run(self, fn, *args):
        if self._busy:
            self._set_msg("実行中です。完了までお待ちください。", "warn")
            return False
        self._busy = True
        self._stop.clear()
        self._thread = threading.Thread(target=self._wrap, args=(fn, args), daemon=True)
        self._thread.start()
        return True

    def _wrap(self, fn, args):
        try:
            fn(*args)
        except ApiError as e:
            msg = str(e)
            if msg.startswith("__toobig__"):
                msg = "応答が大きすぎます"
            self._ui(self._set_msg, f"RIPE Atlas API エラー: {msg}", "bad")
        except OSError as e:
            self._ui(self._set_msg, f"通信に失敗しました: {e}", "bad")
        finally:
            self._busy = False

    def _autodetect(self):
        """自分の公開IPとASNを裏で引いて入力欄を埋める。ipinfo無効なら手入力を促す。"""
        if not settings.get("advanced.ipinfo_enabled", True):
            self._set_msg("外部IP照会が設定で無効です。自ASN(例 17676)と国コードを手で入力してください。", "warn")
            return

        def work():
            info = nd.lookup_ip_info() or {}
            self._ui(self._apply_self_info, info)

        threading.Thread(target=work, daemon=True).start()

    def _apply_self_info(self, info):
        self.self_info = info or None
        asn = parse_asn(info.get("org"))
        if asn and not self.asn_var.get():
            self.asn_var.set(str(asn))
        if info.get("country") and not self.cc_var.get():
            self.cc_var.set(info["country"])
        if info.get("ip"):
            self._set_msg(f"自分の公開IP {info['ip']}  /  {info.get('org') or '組織不明'}  "
                          f"/  {info.get('region') or ''} {info.get('country') or ''}", "muted")
        else:
            self._set_msg("公開IPを取得できませんでした。自ASNを手で入力してください。", "warn")

    def _asn(self):
        try:
            return int(self.asn_var.get().strip())
        except ValueError:
            return None

    # ---- 1. プローブ検索 (認証不要) ----

    def search_probes(self):
        asn, cc = self._asn(), self.cc_var.get().strip().upper()
        scope = self.scope_var.get()
        if scope in ("ASN", "ASN+国") and asn is None:
            self._set_msg("自ASNが未入力です (例: 17676)。", "warn")
            return
        if scope in ("国", "ASN+国") and not cc:
            self._set_msg("国コードが未入力です (例: JP)。", "warn")
            return
        q = []
        if scope in ("ASN", "ASN+国"):
            q.append(f"asn_v4={asn}")
        if scope in ("国", "ASN+国"):
            q.append(f"country_code={cc}")
        self._set_msg("プローブを検索中…", "muted")
        self._run(self._search_probes_worker, "&".join(q))

    def _search_probes_worker(self, query):
        data = _request("GET", f"/api/v2/probes/?{query}&page_size=100"
                               "&fields=id,country_code,asn_v4,status,description,is_anchor")
        probes = data.get("results", [])
        self._ui(self._apply_probes, probes, data.get("count", len(probes)))

    def _apply_probes(self, probes, total):
        self.probes = probes
        self.probe_tree.delete(*self.probe_tree.get_children())
        for p in probes:
            st = (p.get("status") or {}).get("name", "?")
            tag = "good" if st == "Connected" else "muted"
            desc = p.get("description") or ""
            if p.get("is_anchor"):
                desc = "⚓ " + desc
            self.probe_tree.insert("", "end", values=(p.get("id"), p.get("country_code") or "",
                                                      p.get("asn_v4") or "", st, desc), tags=(tag,))
        connected = sum(1 for p in probes if (p.get("status") or {}).get("name") == "Connected")
        self.probe_head.config(text=f"同じISP / 国のプローブ — {len(probes)} 件表示 "
                                    f"(全 {total} 件 / うち接続中 {connected} 件)")
        self._set_msg(f"プローブ {len(probes)} 件を取得しました (全 {total} 件)。"
                      + ("  ※ 表示は先頭100件までです。" if total > len(probes) else ""), "good")

    # ---- 2. 公開計測から「外 → 自ISP」を取る (認証不要) ----

    def fetch_public(self):
        asn = self._asn()
        if asn is None:
            self._set_msg("自ASNが未入力です (例: 17676)。", "warn")
            return
        self._set_msg("自ASNを宛先にした公開計測を検索中…", "muted")
        self._run(self._fetch_public_worker, asn, max(1, int(self.msm_n_var.get() or 1)))

    def _fetch_public_worker(self, asn, want):
        listing = _request("GET", f"/api/v2/measurements/?target_asn={asn}&type=ping&is_public=true"
                                  f"&sort=-start_time&page_size={min(want, 60)}")
        msms = listing.get("results", [])[:want]
        if not msms:
            self._ui(self._apply_results, [], [], asn,
                     f"AS{asn} を宛先にした公開ping計測が見つかりませんでした。")
            return
        rows, used, skipped = [], [], 0
        for i, m in enumerate(msms):
            if self._stop.is_set():
                return
            self._ui(self._set_msg, f"公開計測の結果を取得中… {i + 1}/{len(msms)} "
                                    f"(msm {m.get('id')} → {m.get('target_ip') or m.get('target')})", "muted")
            try:
                recs = _request("GET", f"/api/v2/measurements/{m['id']}/results/",
                                max_bytes=MAX_RESULT_BYTES)
            except ApiError as e:
                if str(e).startswith("__toobig__"):
                    skipped += 1
                    continue
                raise
            if isinstance(recs, list) and recs:
                rows.extend(parse_ping_result(r) for r in recs if isinstance(r, dict))
                used.append({"id": m["id"], "target": m.get("target_ip") or m.get("target"),
                             "description": m.get("description"),
                             "start_time": m.get("start_time"), "results": len(recs)})
            time.sleep(INTER_REQ_SLEEP)
        meta = self._fetch_probe_meta({r["prb_id"] for r in rows if r["prb_id"]})
        note = f"{len(msms)} 件の公開計測を確認" + (f" (大きすぎる {skipped} 件はスキップ)" if skipped else "")
        self._ui(self._apply_results, rows, used, asn, note, meta)

    def _fetch_probe_meta(self, prb_ids):
        """結果に出てきたプローブの国/ASNをまとめて引く。1リクエスト100件まで。"""
        meta, ids = {}, sorted(i for i in prb_ids if i is not None)
        for i in range(0, len(ids), 100):
            if self._stop.is_set():
                break
            chunk = ",".join(str(x) for x in ids[i:i + 100])
            try:
                data = _request("GET", f"/api/v2/probes/?id__in={chunk}&page_size=100"
                                       "&fields=id,country_code,asn_v4")
            except (ApiError, OSError):
                break
            for p in data.get("results", []):
                meta[p["id"]] = {"cc": p.get("country_code") or "", "asn": p.get("asn_v4") or ""}
            time.sleep(INTER_REQ_SLEEP)
        return meta

    def _apply_results(self, rows, used, asn, note, meta=None):
        self.rows = sorted(rows, key=lambda r: (r["avg_ms"] is None, r["avg_ms"] or 0))
        self.msm_used = used
        self.probe_meta.update(meta or {})
        self.summary_data = summarize(self.rows)
        self.result_tree.delete(*self.result_tree.get_children())
        for r in self.rows:
            m = self.probe_meta.get(r["prb_id"], {})
            self.result_tree.insert("", "end", tags=(rtt_tag(r["avg_ms"]),), values=(
                r["prb_id"] or "?", m.get("cc", ""), m.get("asn", ""), r["from"], r["dst"],
                r["sent"], r["rcvd"], f"{r['loss_pct']:.0f}",
                *(f"{r[k]:.1f}" if r[k] is not None else "-" for k in ("min_ms", "avg_ms", "max_ms")),
                r["msm_id"] or ""))
        self.result_head.config(text=f"世界のプローブ → AS{asn} (公開計測 {len(used)} 件 / "
                                     f"{self.summary_data['samples']} サンプル)")
        kind = "good" if self.rows else "warn"
        self._set_msg(f"{note}。 サンプル {self.summary_data['samples']} 件 / "
                      f"プローブ {self.summary_data['probes']} 台。", kind)
        self._render_summary()
        self.draw()

    # ---- 3. APIキーが要る操作 ----

    def on_save_key(self):
        try:
            save_key(self.key_var.get())
        except OSError as e:
            self._set_msg(f"APIキーの保存に失敗: {e}", "bad")
            return
        self.credits = None
        self._set_msg(f"APIキーを {KEY_PATH.name} に保存しました (設定JSONには入れていません)。", "good")

    def fetch_credits(self):
        key = load_key()
        if not key:
            self._set_msg("APIキーが未設定です。残クレジットの参照には認証が必要です "
                          "(GET /api/v2/credits/ は認証なしだと 401)。", "warn")
            return
        self._set_msg("残クレジットを照会中…", "muted")
        self._run(self._credits_worker, key)

    def _credits_worker(self, key):
        data = _request("GET", "/api/v2/credits/", key=key)
        self._ui(self._apply_credits, data.get("current_balance"))

    def _apply_credits(self, balance):
        self.credits = balance
        self._set_msg(f"残クレジット: {balance:,}" if isinstance(balance, int)
                      else f"残クレジット: {balance}", "good")

    def create_oneoff(self):
        key = load_key()
        if not key:
            self._set_msg("APIキーが未設定です。計測の作成には認証とクレジットが必要です "
                          "(POST /api/v2/measurements/ は認証なしだと 401)。", "warn")
            return
        target = (self.self_info or {}).get("ip")
        if not target:
            self._set_msg("自分の公開IPが不明なため計測を作成できません。", "warn")
            return
        kind = self.kind_var.get()
        nprobes = max(1, int(self.nprobe_var.get() or 1))
        packets = 3
        cost = estimate_credits(kind, nprobes, packets)
        bal = f"\n現在の残クレジット: {self.credits:,}" if isinstance(self.credits, int) else \
              "\n(残クレジットは未照会です)"
        if not messagebox.askyesno(
                "クレジットを消費します",
                f"RIPE Atlas に one-off 計測を作成します。これはクレジットを消費する操作です。\n\n"
                f"種別: {kind} ({packets} パケット)\n宛先: {target} (あなたの公開IP)\n"
                f"プローブ数: {nprobes} (世界全体からランダム)\n\n"
                f"消費見込み: 約 {cost:,} クレジット\n"
                f"(公開計測の credits_per_result から逆算した概算。実際の請求は結果件数で決まります){bal}\n\n"
                f"作成してよろしいですか?", parent=self.ctx.root):
            self._set_msg("計測の作成をキャンセルしました。", "muted")
            return
        self._set_msg(f"one-off {kind} を作成中… (宛先 {target})", "muted")
        self._run(self._oneoff_worker, key, kind, target, nprobes, packets)

    def _oneoff_worker(self, key, kind, target, nprobes, packets):
        definition = {"target": target, "af": 4, "type": kind, "packets": packets,
                      "description": f"network-diag: {kind} to own line"}
        if kind == "traceroute":
            definition["protocol"] = "ICMP"
        data = _request("POST", "/api/v2/measurements/", key=key, payload={
            "definitions": [definition],
            "probes": [{"requested": nprobes, "type": "area", "value": "WW"}],
            "is_oneoff": True})
        ids = data.get("measurements") or []
        if not ids:
            self._ui(self._set_msg, f"計測IDが返りませんでした: {data}", "bad")
            return
        msm_id = ids[0]
        deadline = time.time() + 300
        recs = []
        while time.time() < deadline and not self._stop.is_set():
            self._ui(self._set_msg, f"計測 {msm_id} の結果を待っています… "
                                    f"({len(recs)}/{nprobes} プローブ, 残り {int(deadline - time.time())}秒)",
                     "muted")
            self._stop.wait(10)
            if self._stop.is_set():
                return
            try:
                recs = _request("GET", f"/api/v2/measurements/{msm_id}/results/",
                                key=key, max_bytes=MAX_RESULT_BYTES)
            except ApiError:
                recs = recs or []
            if isinstance(recs, list) and len(recs) >= nprobes:
                break
        rows = [parse_ping_result(r) for r in recs if isinstance(r, dict)] if isinstance(recs, list) else []
        meta = self._fetch_probe_meta({r["prb_id"] for r in rows if r["prb_id"]})
        used = [{"id": msm_id, "target": target, "description": f"one-off {kind}",
                 "start_time": int(time.time()), "results": len(rows)}]
        note = (f"one-off {kind} (msm {msm_id}) の結果 {len(rows)} 件を取得しました" if rows else
                f"one-off {kind} (msm {msm_id}) は結果0件でした。"
                "自宅側でICMPが遮断されている可能性が高く、回線品質の判断材料にはなりません")
        self._ui(self._apply_results, rows, used, self._asn() or 0, note, meta)

    # ---- サマリ / グラフ ----

    def _render_summary(self):
        s = self.summary_data
        if not s["samples"]:
            self.summary_label.config(text=(
                "外から見た自宅回線: まだデータがありません。\n"
                "「外から見た結果を取得」で、自ASNを宛先にした世界中の公開ping計測を集めます。\n"
                "自宅IPそのものを直接測るには RIPE Atlas の APIキーとクレジットが必要です。"))
            return
        med = f"{s['median_ms']:.1f} ms" if s["median_ms"] is not None else "—"
        rng = (f"{s['p10_ms']:.1f} 〜 {s['p90_ms']:.1f} ms" if s["p10_ms"] is not None else "—")
        span = (f"{s['min_ms']:.1f} 〜 {s['max_ms']:.1f} ms" if s["min_ms"] is not None else "—")
        self.summary_label.config(text=(
            f"外から見た自宅回線 (逆方向)   応答したサンプル {s['responded']} / {s['samples']}"
            f"   プローブ {s['probes']} 台\n"
            f"RTT 中央値 {med}    中央80% {rng}    最小〜最大 {span}    平均ロス率 {s['loss_pct']:.1f}%\n"
            f"応答が無かった割合 {s['no_reply_pct']:.1f}% ({s['no_reply']} サンプル) "
            f"— これは回線障害とは限りません(ICMPフィルタ / プローブ側の事情 / 計測の失敗)。"))

    def _size(self):
        w, h = self.canvas.winfo_width(), self.canvas.winfo_height()
        return (w if w > 10 else 900), (h if h > 10 else 190)

    def draw(self):
        c, t = self.canvas, self.ctx.theme
        c.delete("all")
        w, h = self._size()
        vals = [r["avg_ms"] for r in self.rows if r["avg_ms"] is not None]
        if not vals:
            c.create_text(w / 2, h / 2, justify="center", fill=t["muted"], font=(self.ctx.font, 10),
                          text=("外から見たRTTの分布がまだありません。\n"
                                "結果が空でも回線が悪いとは限りません — ICMPが落とされているだけの場合もあります。"))
            return
        x0, y0, x1, y1 = 46, 24, max(120, w - 96), max(70, h - 30)
        c.create_rectangle(x0, y0, x1, y1, outline=t["graph_grid"], width=1)
        edges, counts = histogram(vals)
        cmax = max(counts)
        for i in range(1, 4):  # 横グリッド
            y = y1 - (y1 - y0) * i / 4
            c.create_line(x0, y, x1, y, fill=t["graph_grid"])
            c.create_text(x0 - 5, y, text=f"{cmax * i / 4:.0f}", anchor="e",
                          fill=t["muted"], font=(self.ctx.font, 8))
        c.create_text(x0 - 5, y1, text="0", anchor="e", fill=t["muted"], font=(self.ctx.font, 8))
        c.create_text(x0 - 5, y0 - 12, text="件数", anchor="e", fill=t["muted"], font=(self.ctx.font, 8))
        for i, n in enumerate(counts):
            bx0, by0, bx1, by1 = bar_rect(i, n, cmax, len(counts), x0, y0, x1, y1)
            if n:
                c.create_rectangle(bx0, by0, bx1, by1,
                                   fill=t[rtt_tag((edges[i] + edges[i + 1]) / 2)], outline="")
        for frac, lab in ((0.0, edges[0]), (0.5, (edges[0] + edges[-1]) / 2), (1.0, edges[-1])):
            c.create_text(x0 + (x1 - x0) * frac, y1 + 11, text=f"{lab:.0f}ms",
                          anchor="n" if frac == 0.5 else ("nw" if frac == 0 else "ne"),
                          fill=t["muted"], font=(self.ctx.font, 8))
        med = self.summary_data["median_ms"]
        if med is not None and edges[-1] > edges[0]:
            mx = x0 + (x1 - x0) * (med - edges[0]) / (edges[-1] - edges[0])
            mx = min(max(mx, x0), x1)
            c.create_line(mx, y0, mx, y1, fill=t["fg"], width=1, dash=(3, 3))
            c.create_text(min(mx + 4, x1 - 4), y0 + 2, text=f"中央値 {med:.0f}ms", anchor="nw",
                          fill=t["fg"], font=(self.ctx.font, 8))
        c.create_text(x0, y0 - 12, text=f"外から見たRTT分布  n={len(vals)}", anchor="w",
                      fill=t["fg"], font=(self.ctx.font, 9))
        s = self.summary_data
        c.create_text(x1 + 8, y0, anchor="nw", fill=t["muted"], font=(self.ctx.font, 8), justify="left",
                      text=(f"応答 {s['responded']}\n無応答 {s['no_reply']}\n"
                            f"({s['no_reply_pct']:.0f}%)\n\nロス平均\n{s['loss_pct']:.1f}%"))

    # ---- 保存 ----

    def export(self):
        if not self.rows and not self.probes:
            self._set_msg("保存するデータがありません。", "warn")
            return
        nd.RESULTS_DIR.mkdir(exist_ok=True)
        path = nd.RESULTS_DIR / f"atlas_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        payload = {
            "label": "atlas",
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "self": self.self_info,
            "asn": self._asn(),
            "country": self.cc_var.get().strip().upper() or None,
            "probes": self.probes,
            "measurements": self.msm_used,
            "results": self.rows,
            "probe_meta": {str(k): v for k, v in self.probe_meta.items()},
            "summary": self.summary_data,
            "caveat": DISCLAIMER,
        }
        try:
            path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError as e:
            self._set_msg(f"保存に失敗: {e}", "bad")
            return
        self._set_msg(f"✓ 保存しました: {path.name}", "good")

    def on_close(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)


# ---------- 自己テスト (ネットワーク不要) ----------

# 実物の RIPE Atlas API レスポンス (2026-08-24 に取得したものをそのまま貼っている)
REAL_PING_OK = json.loads("""
{"fw":5120,"mver":"2.6.4","lts":41,"dst_name":"126.207.0.1","af":4,"dst_addr":"126.207.0.1",
 "src_addr":"172.17.0.2","proto":"ICMP","ttl":54,"size":48,
 "result":[{"rtt":19.725885},{"rtt":19.422504},{"rtt":19.387082},{"rtt":19.470221},{"rtt":19.315099}],
 "dup":0,"rcvd":5,"sent":5,"min":19.315099,"max":19.725885,"avg":19.4641582,"msm_id":203405971,
 "prb_id":1016425,"timestamp":1787451057,"msm_name":"Ping","from":"61.200.81.11","type":"ping",
 "group_id":203405971,"step":null,"stored_timestamp":1787451075}""")

REAL_PING_LOSS = json.loads("""
{"fw":5100,"mver":"2.6.4","lts":5,"dst_name":"193.0.14.129","af":4,"dst_addr":"193.0.14.129",
 "src_addr":"192.168.1.12","proto":"ICMP","size":32,"result":[{"x":"*"},{"x":"*"},{"x":"*"}],
 "dup":0,"rcvd":0,"sent":3,"min":-1,"max":-1,"avg":-1,"msm_id":1001,"prb_id":1009618,
 "timestamp":1787541897,"msm_name":"Ping","from":"190.56.171.134","type":"ping","step":240,
 "stored_timestamp":1787541968}""")

REAL_ERROR_401 = json.loads(
    '{"error":{"detail":"The provided API key does not exist","status":401,'
    '"title":"Unauthorized","code":104}}')


def _selftest():
    # --- 実物レスポンスのパース ---
    ok = parse_ping_result(REAL_PING_OK)
    assert ok["prb_id"] == 1016425 and ok["from"] == "61.200.81.11", ok
    assert (ok["sent"], ok["rcvd"], ok["loss_pct"]) == (5, 5, 0.0), ok
    assert ok["avg_ms"] == 19.46 and ok["min_ms"] == 19.32 and ok["max_ms"] == 19.73, ok
    assert ok["dst"] == "126.207.0.1" and ok["msm_id"] == 203405971, ok

    # 未応答は min/avg/max に -1 が入る。0ms と誤読していないこと(過去に識別子の誤読で3回外している)
    lost = parse_ping_result(REAL_PING_LOSS)
    assert (lost["sent"], lost["rcvd"], lost["loss_pct"]) == (3, 0, 100.0), lost
    assert lost["avg_ms"] is None and lost["min_ms"] is None and lost["max_ms"] is None, lost

    # min/avg/max が欠けていてもパケット配列から復元できること
    partial = parse_ping_result({"prb_id": 7, "sent": 3, "rcvd": 2,
                                 "result": [{"rtt": 10.0}, {"x": "*"}, {"rtt": 20.0}]})
    assert partial["avg_ms"] == 15.0 and partial["min_ms"] == 10.0 and partial["max_ms"] == 20.0, partial
    assert partial["loss_pct"] == 33.3, partial

    # 壊れた/空の結果でも例外を出さないこと
    empty = parse_ping_result({})
    assert empty["sent"] == 0 and empty["loss_pct"] == 100.0 and empty["avg_ms"] is None, empty

    assert api_error_detail(REAL_ERROR_401) == "The provided API key does not exist"
    assert "500" in api_error_detail({"error": {"title": "500"}})

    # --- ASN 抽出 ---
    assert parse_asn("AS17676 SoftBank Corp.") == 17676
    assert parse_asn("AS2914 NTT America, Inc.") == 2914
    assert parse_asn(None) is None and parse_asn("") is None and parse_asn("SoftBank") is None

    # --- 統計集計 ---
    rows = [parse_ping_result(REAL_PING_OK), parse_ping_result(REAL_PING_LOSS),
            parse_ping_result({"prb_id": 3, "sent": 3, "rcvd": 3, "min": 100.0, "avg": 110.0,
                               "max": 120.0, "result": [{"rtt": 110.0}] * 3})]
    s = summarize(rows)
    assert s["samples"] == 3 and s["probes"] == 3, s
    assert s["responded"] == 2 and s["no_reply"] == 1, s
    assert s["no_reply_pct"] == 33.3, s
    assert s["median_ms"] == 64.7, s          # median(19.46, 110.0)
    assert s["min_ms"] == 19.46 and s["max_ms"] == 110.0, s
    assert s["loss_pct"] == 33.3, s          # (0 + 100 + 0) / 3

    # 0件の退化ケース: 例外を出さず None / 0 を返すこと
    z = summarize([])
    assert z["samples"] == 0 and z["probes"] == 0 and z["no_reply_pct"] == 0.0, z
    assert z["median_ms"] is None and z["min_ms"] is None and z["loss_pct"] == 0.0, z

    # 全ロスだけの集合
    allbad = summarize([parse_ping_result(REAL_PING_LOSS)])
    assert allbad["responded"] == 0 and allbad["no_reply_pct"] == 100.0 and allbad["median_ms"] is None

    # --- ヒストグラム / 座標変換 ---
    assert histogram([]) == ([], [])
    edges, counts = histogram([10.0, 10.0, 10.0], nbins=4)   # 全部同値でもゼロ幅にしない
    assert len(counts) == 4 and sum(counts) == 3 and edges[-1] > edges[0], (edges, counts)
    edges, counts = histogram([0.0, 50.0, 100.0], nbins=10)
    assert sum(counts) == 3 and counts[0] == 1 and counts[-1] == 1, counts
    assert abs(edges[0] - 0.0) < 1e-9 and abs(edges[-1] - 100.0) < 1e-9, edges
    # 上限値が最終ビンに入る (int() の切り上げで範囲外にならないこと)
    edges, counts = histogram([1.0, 2.0, 3.0, 3.0], nbins=3)
    assert sum(counts) == 4 and counts[-1] == 2, counts

    X0, Y0, X1, Y1 = 40.0, 20.0, 400.0, 160.0
    n = len(counts)
    cmax = max(counts)
    prev_right = X0
    for i, cnt in enumerate(counts):
        bx0, by0, bx1, by1 = bar_rect(i, cnt, cmax, n, X0, Y0, X1, Y1)
        assert X0 <= bx0 < bx1 <= X1, (i, bx0, bx1)          # 横は必ず枠内
        assert Y0 <= by0 <= by1 == Y1, (i, by0, by1)         # 縦は枠内かつ底辺は y1
        assert bx0 >= prev_right - 1e-9, (i, bx0, prev_right)  # 棒が重ならない
        prev_right = bx1 - 4  # gap ぶん
    # 最大ビンは天井まで、0件のビンは高さ0
    top = bar_rect(counts.index(cmax), cmax, cmax, n, X0, Y0, X1, Y1)
    assert abs(top[1] - Y0) < 1e-9, top
    zero = bar_rect(0, 0, cmax, n, X0, Y0, X1, Y1)
    assert abs(zero[1] - Y1) < 1e-9, zero
    # cmax=0 (全ビン空) でもゼロ除算しない
    assert abs(bar_rect(0, 0, 0, n, X0, Y0, X1, Y1)[1] - Y1) < 1e-9

    assert (rtt_tag(10.0), rtt_tag(59.9), rtt_tag(60.0), rtt_tag(149.9), rtt_tag(150.0), rtt_tag(None)) == \
           ("good", "good", "warn", "warn", "bad", "bad")

    # --- クレジット概算 (公開計測の credits_per_result から逆算した単価) ---
    assert estimate_credits("ping", 1, 1) == 2 and estimate_credits("ping", 1, 3) == 6
    assert estimate_credits("ping", 1, 16) == 32
    assert estimate_credits("ping", 5, 3) == 30
    assert estimate_credits("traceroute", 1, 3) == 60 and estimate_credits("traceroute", 5, 5) == 500

    # --- APIキーが無い場合の分岐 ---
    assert mask_key(None) == "(未設定)" and mask_key("") == "(未設定)"
    assert mask_key("abcd") == "••••"
    masked = mask_key("11112222-3333-4444-5555-666677778888")
    assert masked.startswith("1111") and masked.endswith("8888") and "2222" not in masked, masked
    assert len(masked) == len("11112222-3333-4444-5555-666677778888"), masked

    real_key = KEY_PATH.exists()   # 実キーがあるなら絶対に壊さない
    if not real_key:
        assert load_key() is None
        try:
            assert save_key("  test-key-value  ") == "test-key-value"
            assert load_key() == "test-key-value"
            assert KEY_PATH.read_text(encoding="utf-8").strip() == "test-key-value"
            assert save_key("") is None and load_key() is None
            assert not KEY_PATH.exists()
        finally:
            try:
                KEY_PATH.unlink()
            except OSError:
                pass
    # 設定JSONにキーが混ざっていないこと
    assert settings.get("atlas.api_key") is None
    assert "atlas_key" not in json.dumps(settings.get("advanced", {}) or {})

    print("atlas selftest: OK")


if __name__ == "__main__":
    import sys

    if "--selftest" in sys.argv:
        _selftest()
        sys.exit()

    import sv_ttk

    root = tk.Tk()
    root.geometry("1200x740")
    root.title("RIPE Atlas — 外から見た自宅回線")
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
    tab = AtlasTab(frame, ctx)
    if "--auto" in sys.argv:
        root.after(1500, tab.search_probes)
        root.after(6000, tab.fetch_public)
    root.protocol("WM_DELETE_WINDOW", lambda: (tab.on_close(), root.destroy()))
    root.mainloop()
