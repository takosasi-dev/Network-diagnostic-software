#!/usr/bin/env python3
"""主要サービス・ゲームサーバへの到達性ダッシュボード。

汎用の宛先 (1.1.1.1 / 8.8.8.8) が速くても「Steamだけ遅い」ことはある。
このタブは実際に使うサービスへの体感を数値化して、
「回線全体が悪い」のか「特定サービスへの経路だけが悪い」のかを切り分ける。

ICMP ping ではなく TCP 443 の connect() 時間を測っている理由:
 (1) ICMP を落とす / 優先度を下げるサーバが多く、CDN では特に信用できない
 (2) 実アプリは TCP を張るので体感に近い (SYN -> SYN/ACK の1往復ぶん = 実効RTT)
名前解決の時間は別列に分けてある。「名前解決が遅い」のと「接続が遅い」のは対処が違うため。
"""
import concurrent.futures as cf
import csv
import json
import socket
import statistics
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import ttk

import network_diag as nd
from settings_store import setting

# ---------- 調整用の定数 ----------

PORT = 443
DEFAULT_TRIALS = 5
# 並列度を上げるとローカル側の食い合いでRTTが素直に上振れする。既定リスト22件での実測:
#   1並列 = 全体中央値 9.9ms (2.0秒) / 2並列 = 11.8ms (1.3秒)
#   4並列 = 15.9ms (0.7秒) / 12並列 = 16.4ms / 16並列 = 23.9ms
# 8〜16並列は速いが 1並列比で 1.7〜2.4倍に膨らみ、乖離判定が誤検知を出す
# (12並列の実測で Riot/YouTube/ニコニコ動画 が外れ値として誤って挙がった)。
# 22件なら1〜2並列でも数秒で終わるので、速さより数字の素直さを取る。
DEFAULT_WORKERS = 2
CONNECT_TIMEOUT_S = 4.0

GOOD_MS = 30.0             # これ以下は緑 (この環境の 1.1.1.1 は 7〜8ms、国内CDNは10〜20ms)
WARN_MS = 70.0             # これ以下は黄、超えたら赤
FAIL_SUCCESS_PCT = 60.0    # 成功率がこれ未満なら内容によらず赤

OUTLIER_FACTOR = 2.5           # 全体中央値の何倍から「突出して遅い」とするか
OUTLIER_MIN_DELTA_MS = 20.0    # 倍率だけだと 2ms->6ms も引っかかるので絶対差の下限も要求する
OUTLIER_MIN_SAMPLES = 4        # 母数が少ないと中央値が当てにならない

CONFIG_NAME = "services.json"

# カテゴリ, 表示名, ホスト。全て 2026-08 時点で TCP/443 到達を実測済み。
DEFAULT_SERVICES = [
    ("ゲーム", "Steam", "api.steampowered.com"),
    ("ゲーム", "PlayStation Network", "www.playstation.com"),
    ("ゲーム", "Nintendo", "www.nintendo.co.jp"),
    ("ゲーム", "Xbox", "xbox.com"),
    ("ゲーム", "Epic Games", "www.epicgames.com"),
    ("ゲーム", "Riot (LoL)", "www.leagueoflegends.com"),
    ("動画・配信", "YouTube", "www.youtube.com"),
    ("動画・配信", "Netflix", "www.netflix.com"),
    ("動画・配信", "Twitch", "www.twitch.tv"),
    ("動画・配信", "ニコニコ動画", "www.nicovideo.jp"),
    ("動画・配信", "Prime Video", "www.primevideo.com"),
    ("SNS・通話", "Discord", "discord.com"),
    ("SNS・通話", "X", "x.com"),
    ("SNS・通話", "LINE", "line.me"),
    ("SNS・通話", "Zoom", "zoom.us"),
    ("開発・クラウド", "GitHub", "github.com"),
    ("開発・クラウド", "AWS", "aws.amazon.com"),
    ("開発・クラウド", "Cloudflare", "www.cloudflare.com"),
    ("開発・クラウド", "Google", "www.google.com"),
    ("国内主要", "Yahoo! JAPAN", "www.yahoo.co.jp"),
    ("国内主要", "楽天", "www.rakuten.co.jp"),
    ("国内主要", "Amazon.co.jp", "www.amazon.co.jp"),
]


# ---------- 純粋関数 (自己テスト対象) ----------

def summarize(rtts, trials):
    """成功したRTTのリスト -> 中央値/最小/最大/成功率。平均ではなく中央値なのは
    1発だけ刺さる再送 (+1000ms) に引きずられないため。"""
    ok = len(rtts)
    return {
        "median_ms": round(statistics.median(rtts), 1) if ok else None,
        "min_ms": round(min(rtts), 1) if ok else None,
        "max_ms": round(max(rtts), 1) if ok else None,
        "ok": ok,
        "trials": trials,
        "success_pct": round(ok / trials * 100, 1) if trials else 0.0,
    }


def rtt_tag(median_ms, success_pct):
    """中央値と成功率 -> Treeviewの色タグ名。取りこぼしがあれば良好とは呼ばない。"""
    if median_ms is None or success_pct < FAIL_SUCCESS_PCT:
        return "bad"
    if median_ms > setting("services.warn_ms", WARN_MS):
        return "bad"
    if median_ms > setting("services.good_ms", GOOD_MS):
        return "warn"
    return "good" if success_pct >= 100.0 else "warn"


def find_outliers(medians):
    """{名前: 中央値} -> 全体中央値から突出して遅い名前の集合。
    倍率と絶対差の両方を満たすものだけ。回線全体が遅い日に全部が外れ値になるのを防ぐ。"""
    vals = [v for v in medians.values() if v is not None]
    if len(vals) < OUTLIER_MIN_SAMPLES:
        return set()
    base = statistics.median(vals)
    return {k for k, v in medians.items()
            if v is not None and v >= base * OUTLIER_FACTOR and v - base >= OUTLIER_MIN_DELTA_MS}


def category_averages(rows):
    """[(カテゴリ, 平均中央値, 件数)] を宛先リストの登場順で返す。測定できた行のみ集計。"""
    order, acc = [], {}
    for r in rows:
        cat = r["category"]
        if cat not in acc:
            order.append(cat)
            acc[cat] = []
        if r.get("median_ms") is not None:
            acc[cat].append(r["median_ms"])
    return [(c, round(sum(acc[c]) / len(acc[c]), 1), len(acc[c])) for c in order if acc[c]]


def bar_layout(values, w, h, left=110, right=56, top=16, bottom=20, gap=8):
    """横棒グラフの矩形 [(x0,y0,x1,y1)] を返す。最大値が右端に来るよう正規化。"""
    n = len(values)
    plot_w, plot_h = w - left - right, h - top - bottom
    if n == 0 or plot_w <= 0 or plot_h <= 0:
        return []
    vmax = max(values) or 1.0
    band = plot_h / n
    bar_h = max(4.0, band - gap)
    return [(float(left), top + i * band + (band - bar_h) / 2,
             left + plot_w * (v / vmax), top + i * band + (band - bar_h) / 2 + bar_h)
            for i, v in enumerate(values)]


def load_services(path):
    """設定JSONを読む。無い / 壊れている / 型が違う場合は既定リストに黙って戻す
    (診断ツールが設定ファイルごときで起動不能になる方が困る)。"""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        rows = [(str(d["category"]), str(d["name"]), str(d["host"]))
                for d in data if d.get("host")]
        return rows or list(DEFAULT_SERVICES)
    except Exception:
        return list(DEFAULT_SERVICES)


def save_services(path, services):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([{"category": c, "name": n, "host": h} for c, n, h in services],
                               ensure_ascii=False, indent=2), encoding="utf-8")


# ---------- 計測 ----------

def measure_service(host, port=PORT, trials=DEFAULT_TRIALS, stop=None):
    """名前解決時間とTCP接続時間を分けて測る。-> 行dict

    名前解決は1回だけ。2回目以降はOSのリゾルバキャッシュに当たって 0ms 台になり
    「速い」ではなく「測れていない」数字になるため。以降の接続は解決済みIP宛に張って
    名前解決分を接続時間から完全に除く。
    """
    row = {"host": host, "ip": None, "org": "", "dns_ms": None, "error": ""}
    try:
        t0 = time.perf_counter()
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        row["dns_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        row["ip"] = infos[0][4][0]
    except OSError as e:
        row.update(summarize([], trials))
        row["error"] = f"名前解決に失敗: {e}"
        return row

    rtts = []
    for _ in range(trials):
        if stop is not None and stop.is_set():
            break
        try:
            t0 = time.perf_counter()
            sock = socket.create_connection((row["ip"], port), timeout=CONNECT_TIMEOUT_S)
            rtts.append((time.perf_counter() - t0) * 1000)
            sock.close()
        except OSError as e:
            row["error"] = str(e)
    row.update(summarize(rtts, trials))
    info = nd.lookup_ip_info(row["ip"]) or {}
    row["org"] = info.get("org") or ""
    return row


# ---------- タブ本体 ----------

COLUMNS = [
    ("category", "カテゴリ", 116), ("name", "サービス", 150), ("host", "ホスト", 190),
    ("ip", "IP", 118), ("org", "組織名", 210), ("dns", "DNS(ms)", 74),
    ("median", "中央値", 68), ("min", "最小", 60), ("max", "最大", 60), ("success", "成功率", 64),
]
CHART_H = 190


class ServicesTab:
    def __init__(self, parent, ctx):
        self.ctx = ctx
        self.config_path = nd.RESULTS_DIR / CONFIG_NAME
        self.services = load_services(self.config_path)
        self.rows = []                 # 完了した測定行 (宛先リストと同じ順に並べ替えて保持)
        self.outliers = set()
        self._stop = threading.Event()
        self._thread = None
        self._pool = None

        top = ttk.Frame(parent, padding=(4, 12, 4, 4))
        top.pack(fill="x")
        self.start_btn = ttk.Button(top, text="▶  測定", style="Accent.TButton", command=self.start)
        self.start_btn.pack(side="left", padx=(0, 4))
        self.stop_btn = ttk.Button(top, text="⏸  停止", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=4)
        ttk.Label(top, text="試行回数").pack(side="left", padx=(14, 4))
        self.trials_var = tk.IntVar(value=setting("services.trials", DEFAULT_TRIALS))
        ttk.Spinbox(top, from_=1, to=20, textvariable=self.trials_var, width=4).pack(side="left")
        ttk.Label(top, text="並列度").pack(side="left", padx=(12, 4))
        self.workers_var = tk.IntVar(value=setting("services.workers", DEFAULT_WORKERS))
        ttk.Spinbox(top, from_=1, to=16, textvariable=self.workers_var, width=4).pack(side="left")
        ttk.Button(top, text="＋ 追加", command=self.add_service).pack(side="left", padx=(16, 4))
        ttk.Button(top, text="✎ 編集", command=self.edit_service).pack(side="left", padx=4)
        ttk.Button(top, text="－ 削除", command=self.delete_service).pack(side="left", padx=4)
        ttk.Button(top, text="↺ 既定に戻す", command=self.reset_services).pack(side="left", padx=4)
        ttk.Button(top, text="⬇  CSV", command=lambda: self.export("csv")).pack(side="right", padx=4)
        ttk.Button(top, text="⬇  JSON", command=lambda: self.export("json")).pack(side="right", padx=4)

        self.status = ttk.Label(parent, text="未測定", padding=(6, 4))
        self.status.pack(fill="x")

        wrap = ttk.Frame(parent)
        wrap.pack(fill="both", expand=True, padx=4, pady=(4, 4))
        self.tree = ttk.Treeview(wrap, columns=[c[0] for c in COLUMNS], show="headings", height=14)
        for key, head, width in COLUMNS:
            self.tree.heading(key, text=head)
            self.tree.column(key, width=width,
                             anchor="w" if key in ("category", "name", "host", "ip", "org") else "e",
                             stretch=key == "org")
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<Double-1>", lambda e: self.edit_service())

        self.chart = tk.Canvas(parent, height=CHART_H, highlightthickness=0)
        self.chart.pack(fill="x", padx=4, pady=(0, 8))
        self.chart.bind("<Configure>", lambda e: self._draw_chart())

        self._show_pending()
        self.on_theme_changed()

    # ---- テーマ ----

    def on_theme_changed(self):
        t = self.ctx.theme
        for tag in ("good", "warn", "bad"):
            self.tree.tag_configure(tag, foreground=t[tag])
        self.tree.tag_configure("outlier", foreground=t["bad"], font=(self.ctx.font, 9, "bold"))
        self.tree.tag_configure("pending", foreground=t["muted"])
        # sv_ttk が Treeview の style map に -foreground を入れており、そのままだとタグ色が無視される。
        # 選択状態以外のマッピングを外してタグ色を優先させる (pathmon_tab.py と同じ対処)。
        style = ttk.Style()
        for opt in ("foreground", "background"):
            style.map("Treeview", **{opt: [s for s in style.map("Treeview", query_opt=opt)
                                           if s[0] in ("selected", "!selected")]})
        self.status.config(foreground=t["muted"])
        self.chart.config(bg=t["graph_bg"])
        self._draw_chart()

    # ---- 宛先リストの編集 ----

    def _selected_index(self):
        sel = self.tree.selection()
        return int(sel[0]) if sel and sel[0].isdigit() and int(sel[0]) < len(self.services) else None

    def _edit_dialog(self, title, initial):
        """カテゴリ/名前/ホストを入れる小さなモーダル。-> タプル or None"""
        dlg = tk.Toplevel(self.ctx.root)
        dlg.title(title)
        dlg.transient(self.ctx.root)
        dlg.resizable(False, False)
        dlg.configure(bg=self.ctx.theme["bg"])
        body = ttk.Frame(dlg, padding=12)
        body.pack(fill="both", expand=True)
        vars_ = []
        for i, (label, value) in enumerate(zip(("カテゴリ", "サービス名", "ホスト"), initial)):
            ttk.Label(body, text=label).grid(row=i, column=0, sticky="w", pady=4, padx=(0, 8))
            v = tk.StringVar(value=value)
            entry = ttk.Entry(body, textvariable=v, width=34)
            entry.grid(row=i, column=1, pady=4)
            if i == 0:
                entry.focus_set()
            vars_.append(v)
        result = {}

        def ok(*_):
            cat, name, host = (v.get().strip() for v in vars_)
            if not host:
                return
            result["v"] = (cat or "その他", name or host, host)
            dlg.destroy()

        btns = ttk.Frame(body)
        btns.grid(row=3, column=0, columnspan=2, sticky="e", pady=(10, 0))
        ttk.Button(btns, text="キャンセル", command=dlg.destroy).pack(side="right", padx=4)
        ttk.Button(btns, text="OK", style="Accent.TButton", command=ok).pack(side="right", padx=4)
        dlg.bind("<Return>", ok)
        dlg.bind("<Escape>", lambda e: dlg.destroy())
        dlg.grab_set()
        self.ctx.root.wait_window(dlg)
        return result.get("v")

    def _commit_services(self):
        save_services(self.config_path, self.services)
        keys = set(self.services)
        self.rows = [r for r in self.rows if (r["category"], r["name"], r["host"]) in keys]
        self._show_pending()
        self._refresh()

    def add_service(self):
        v = self._edit_dialog("宛先を追加", ("", "", ""))
        if v:
            self.services.append(v)
            self._commit_services()

    def edit_service(self):
        i = self._selected_index()
        if i is None:
            self._set_status("編集する行を選んでください", "warn")
            return
        v = self._edit_dialog("宛先を編集", self.services[i])
        if v:
            self.services[i] = v
            self._commit_services()

    def delete_service(self):
        i = self._selected_index()
        if i is None:
            self._set_status("削除する行を選んでください", "warn")
            return
        self.services.pop(i)
        self._commit_services()

    def reset_services(self):
        self.services = list(DEFAULT_SERVICES)
        self.rows = []
        self._commit_services()

    # ---- 制御 ----

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self.rows = []
        self.outliers = set()
        self._stop.clear()
        self._show_pending()
        self._draw_chart()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self._thread = threading.Thread(target=self._worker,
                                        args=(list(self.services), self.trials_var.get(),
                                              self.workers_var.get()), daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self.stop_btn.config(state="disabled")

    def on_close(self):
        self._stop.set()
        pool = self._pool
        if pool is not None:
            pool.shutdown(wait=False, cancel_futures=True)
        if self._thread:
            self._thread.join(timeout=3)

    def _ui(self, fn, *a):
        """ワーカースレッドからのUI更新は必ずここを通す。"""
        self.ctx.root.after(0, lambda: fn(*a))

    # ---- ワーカー ----

    def _worker(self, services, trials, workers):
        total = len(services)
        self._pool = cf.ThreadPoolExecutor(max_workers=max(1, workers))
        done = 0
        try:
            futs = {self._pool.submit(measure_service, host, PORT, trials, self._stop): (cat, name, host)
                    for cat, name, host in services}
            for fut in cf.as_completed(futs):
                cat, name, host = futs[fut]
                try:
                    row = fut.result()
                except Exception as e:   # 想定外はその行だけ失敗扱いにして測定全体は続ける
                    row = dict(summarize([], trials), host=host, ip=None, org="",
                               dns_ms=None, error=repr(e))
                row.update(category=cat, name=name)
                done += 1
                self._ui(self._row_done, row, done, total)
        finally:
            self._pool.shutdown(wait=False)
            self._pool = None
            self._ui(self._finished, done, total)

    def _row_done(self, row, done, total):
        self.rows.append(row)
        order = {key: i for i, key in enumerate(self.services)}
        self.rows.sort(key=lambda r: order.get((r["category"], r["name"], r["host"]), 1 << 30))
        self.outliers = find_outliers({r["name"]: r["median_ms"] for r in self.rows})
        self._refresh()
        self._set_status(f"測定中 {done}/{total} ...", "muted")

    def _finished(self, done, total):
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        oks = [r["median_ms"] for r in self.rows if r["median_ms"] is not None]
        base = round(statistics.median(oks), 1) if oks else None
        msg = ("中断 " if self._stop.is_set() else "完了 ") + f"{done}/{total}"
        if base is not None:
            msg += f"  /  全体の中央値 {base} ms"
        if self.outliers:
            msg += f"  /  ★突出して遅い: {', '.join(sorted(self.outliers))}"
        failed = [r["name"] for r in self.rows if r["median_ms"] is None]
        if failed:
            msg += f"  /  到達せず: {', '.join(failed)}"
        self._set_status(msg, "bad" if (self.outliers or failed) else "good")

    # ---- 表示 ----

    def _set_status(self, text, key="muted"):
        self.status.config(text=text, foreground=self.ctx.theme[key])

    def _show_pending(self):
        """測定前でも宛先リストが見えるように、iid = 宛先リストの添字で行だけ作っておく。"""
        self.tree.delete(*self.tree.get_children())
        for i, (cat, name, host) in enumerate(self.services):
            self.tree.insert("", "end", iid=str(i),
                             values=(cat, name, host, "", "", "-", "-", "-", "-", "-"),
                             tags=("pending",))

    def _refresh(self):
        by_key = {(r["category"], r["name"], r["host"]): r for r in self.rows}
        for i, key in enumerate(self.services):
            iid = str(i)
            if not self.tree.exists(iid):
                continue
            r = by_key.get(key)
            if r is None:
                self.tree.item(iid, values=(key[0], key[1], key[2], "", "", "-", "-", "-", "-", "-"),
                               tags=("pending",))
                continue
            star = "★ " if r["name"] in self.outliers else ""
            fmt = lambda v: f"{v:.1f}" if v is not None else "-"
            self.tree.item(iid, values=(r["category"], star + r["name"], r["host"], r["ip"] or "-",
                                        r["org"] or "-", fmt(r["dns_ms"]), fmt(r["median_ms"]),
                                        fmt(r["min_ms"]), fmt(r["max_ms"]),
                                        "{:.0f}%".format(r["success_pct"])),
                           tags=("outlier" if r["name"] in self.outliers
                                 else rtt_tag(r["median_ms"], r["success_pct"]),))
        self._draw_chart()

    def _draw_chart(self):
        """カテゴリ別の平均RTTを横棒で自前描画。「ゲームだけ遅い」のような偏りを一目で見る。"""
        c, t = self.chart, self.ctx.theme
        c.delete("all")
        w = c.winfo_width() or 900
        h = CHART_H
        c.create_rectangle(0, 0, w, h, fill=t["graph_bg"], outline="")
        cats = category_averages(self.rows)
        rects = bar_layout([a for _, a, _ in cats], w, h)
        if not rects:
            c.create_text(w / 2, h / 2, text="「▶  測定」を押すとカテゴリ別の平均RTTを表示します",
                          fill=t["muted"], font=(self.ctx.font, 9))
            return
        left, right = rects[0][0], w - 56
        vmax = max(a for _, a, _ in cats)

        c.create_text(8, 3, text="カテゴリ別 平均RTT (ms) ─ 短いほど良い", fill=t["muted"],
                      font=(self.ctx.font, 8), anchor="nw")
        for frac in (0, 0.25, 0.5, 0.75, 1.0):
            x = left + (right - left) * frac
            c.create_line(x, 16, x, h - 20, fill=t["graph_grid"])
            c.create_text(x, h - 17, text=f"{vmax * frac:.0f}", fill=t["muted"],
                          font=(self.ctx.font, 8), anchor="n")

        for (cat, avg, n), (x0, y0, x1, y1) in zip(cats, rects):
            c.create_rectangle(x0, y0, max(x1, x0 + 1), y1, fill=t[rtt_tag(avg, 100.0)], outline="")
            c.create_text(x0 - 8, (y0 + y1) / 2, text=f"{cat} ({n})", fill=t["fg"],
                          font=(self.ctx.font, 9), anchor="e")
            c.create_text(x1 + 6, (y0 + y1) / 2, text=f"{avg:.1f}", fill=t["fg"],
                          font=(self.ctx.font, 9), anchor="w")

    # ---- エクスポート ----

    def export(self, fmt):
        if not self.rows:
            self._set_status("エクスポートするデータがありません", "warn")
            return
        nd.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        path = nd.RESULTS_DIR / f"services_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
        if fmt == "csv":
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow([col[1] for col in COLUMNS] + ["突出", "エラー"])
                for r in self.rows:
                    w.writerow([r["category"], r["name"], r["host"], r["ip"] or "", r["org"],
                                r["dns_ms"], r["median_ms"], r["min_ms"], r["max_ms"],
                                r["success_pct"], "★" if r["name"] in self.outliers else "",
                                r.get("error", "")])
        else:
            oks = [r["median_ms"] for r in self.rows if r["median_ms"] is not None]
            path.write_text(json.dumps({
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "port": PORT, "trials": self.trials_var.get(),
                "overall_median_ms": round(statistics.median(oks), 1) if oks else None,
                "category_avg_ms": [{"category": c, "avg_ms": a, "n": n}
                                    for c, a, n in category_averages(self.rows)],
                "outliers": sorted(self.outliers),
                "services": self.rows,
            }, ensure_ascii=False, indent=2), encoding="utf-8")
        self._set_status(f"✓ 出力: {path.name}", "good")


# ---------- 自己テスト ----------

def _selftest():
    import tempfile
    from pathlib import Path

    # 統計の集計
    s = summarize([12.0, 10.0, 14.0], 5)
    assert (s["median_ms"], s["min_ms"], s["max_ms"]) == (12.0, 10.0, 14.0), s
    assert (s["ok"], s["trials"], s["success_pct"]) == (3, 5, 60.0), s
    assert summarize([4.0, 8.0], 2)["median_ms"] == 6.0                 # 偶数個は中間値
    assert summarize([1.0, 1.0, 1.0, 900.0], 4)["median_ms"] == 1.0     # 外れ値に引きずられない
    e = summarize([], 5)
    assert e["median_ms"] is None and e["success_pct"] == 0.0, e
    assert summarize([], 0)["success_pct"] == 0.0                       # 0除算しない

    # 閾値による色分け
    assert rtt_tag(10.0, 100.0) == "good"
    assert rtt_tag(GOOD_MS, 100.0) == "good" and rtt_tag(GOOD_MS + 0.1, 100.0) == "warn"
    assert rtt_tag(WARN_MS, 100.0) == "warn" and rtt_tag(WARN_MS + 0.1, 100.0) == "bad"
    assert rtt_tag(10.0, 80.0) == "warn", "取りこぼしがあるのに good は不可"
    assert rtt_tag(10.0, 40.0) == "bad"
    assert rtt_tag(None, 0.0) == "bad"

    # 乖離の判定
    base = {"a": 10.0, "b": 11.0, "c": 12.0, "d": 13.0}
    assert find_outliers(base) == set()
    assert find_outliers({**base, "slow": 200.0}) == {"slow"}
    assert find_outliers({**base, "mid": 30.0}) == set(), "2.5倍未満は外れ値としない"
    assert find_outliers({"a": 2.0, "b": 2.0, "c": 2.0, "d": 2.0, "e": 8.0}) == set(), \
        "絶対差が小さいものを拾ってはいけない"
    assert find_outliers({"a": 1.0, "b": 100.0}) == set(), "母数不足では判定しない"
    assert find_outliers({"a": 10.0, "b": 11.0, "c": 12.0, "d": None, "e": 500.0}) == {"e"}
    assert find_outliers({}) == set()

    # カテゴリ平均
    rows = [{"category": "ゲーム", "median_ms": 10.0}, {"category": "ゲーム", "median_ms": 20.0},
            {"category": "動画", "median_ms": 30.0}, {"category": "全滅", "median_ms": None}]
    assert category_averages(rows) == [("ゲーム", 15.0, 2), ("動画", 30.0, 1)], category_averages(rows)
    assert category_averages([]) == []

    # グラフの座標変換
    r = bar_layout([50.0, 100.0], 400, 100, left=100, right=50, top=10, bottom=10, gap=0)
    assert len(r) == 2
    assert r[0][0] == 100.0 and r[1][0] == 100.0                        # 左端は揃う
    assert abs(r[1][2] - 350.0) < 1e-9, r                               # 最大値が右端 (400-50)
    assert abs(r[0][2] - 225.0) < 1e-9, r                               # 半分の値は中間
    assert r[0][1] == 10.0 and abs(r[1][3] - 90.0) < 1e-9, r            # 縦は top..h-bottom に収まる
    assert abs(r[0][3] - r[1][1]) < 1e-9, r                             # gap=0 なら隙間なく連続
    for x0, y0, x1, y1 in bar_layout([1.0, 2.0, 3.0], 900, CHART_H):
        assert 0 <= x0 <= x1 <= 900 and 0 <= y0 < y1 <= CHART_H, (x0, y0, x1, y1)
    assert bar_layout([], 400, 100) == []
    assert bar_layout([1.0], 40, 100) == [], "幅が足りなければ描かない"
    assert bar_layout([1.0], 400, 5) == [], "高さが足りなければ描かない"
    assert bar_layout([0.0, 0.0], 400, 100), "全て0でも0除算せず矩形は返す"

    # 設定JSONの読み書き
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "services.json"
        assert load_services(p) == list(DEFAULT_SERVICES), "存在しないファイル -> 既定"
        save_services(p, [("A", "a", "a.example"), ("B", "b", "b.example")])
        assert load_services(p) == [("A", "a", "a.example"), ("B", "b", "b.example")]
        p.write_text("{ これは JSON ではない", encoding="utf-8")
        assert load_services(p) == list(DEFAULT_SERVICES), "壊れたファイル -> 既定"
        p.write_text('[{"category":"X"}]', encoding="utf-8")
        assert load_services(p) == list(DEFAULT_SERVICES), "host が無い -> 既定"
        p.write_text("[]", encoding="utf-8")
        assert load_services(p) == list(DEFAULT_SERVICES), "空リスト -> 既定"
        p.write_text('{"not":"a list"}', encoding="utf-8")
        assert load_services(p) == list(DEFAULT_SERVICES), "辞書 -> 既定"
        nested = Path(d) / "sub" / "services.json"
        save_services(nested, [("A", "a", "a.example")])
        assert load_services(nested) == [("A", "a", "a.example")], "親ディレクトリを作る"

    # 既定リストの健全性 (ホストの重複や空欄がないこと)
    assert len({h for _, _, h in DEFAULT_SERVICES}) == len(DEFAULT_SERVICES)
    assert all(c and n and h for c, n, h in DEFAULT_SERVICES)

    print("services selftest: OK")


if __name__ == "__main__":
    import sys

    if "--selftest" in sys.argv:
        _selftest()
        sys.exit()

    import sv_ttk

    root = tk.Tk()
    root.geometry("1250x720")
    root.title("サービス到達性ダッシュボード")
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
    tab = ServicesTab(frame, ctx)
    if "--auto" in sys.argv:
        root.after(400, tab.start)
    root.protocol("WM_DELETE_WINDOW", lambda: (tab.on_close(), root.destroy()))
    root.mainloop()
