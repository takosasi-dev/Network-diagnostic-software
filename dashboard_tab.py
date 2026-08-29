#!/usr/bin/env python3
"""ダッシュボード。19ページを横断して「今どうなのか」を1画面で答える。

このタブは**新しい測定ロジックを持たない**。既存の関数を組み合わせるだけにしてある:
    現在の遅延   -> nd.measure_latency
    リンク       -> nd.get_wifi_info / nd.get_link_stats
    品質グレード -> nd.grade_connection(保存済みフル診断)
    対策の優先度 -> advisor_tab.evaluate

同じ判定を2箇所で書くと必ず食い違うため、判定の実体は各モジュールに置いたまま
ここでは「拾って並べる」ことに徹する。ここに独自のしきい値を足したくなったら、
それは元のモジュール側に足すべきサイン。

鮮度の扱い: 保存済み結果は「いつ測ったか」を必ず添えて出す。古い測定を現在の状態として
提示すると、対策を打った後も古い数値を見て判断してしまう。
"""
import json
import threading
import tkinter as tk
from datetime import datetime
from tkinter import ttk

import network_diag as nd
from settings_store import setting

# ライブ表示の更新間隔。ping 4発 x 2ホストで2〜3秒かかるので、それより十分長く取る。
DEFAULT_REFRESH_S = 10
LIVE_PING_COUNT = 4

# 保存済み結果が「古い」とみなす日数。対策の前後で数値が変わる程度の間隔として1週間。
STALE_DAYS = 7


def live_verdict(samples, warn_ms=None):
    """{名前: measure_latency結果} -> (総合ラベル, タグ)。

    損失を最優先する。遅延が良くても落ちていれば「問題あり」。
    体感の悪さは平均RTTよりパケット損失のほうが直結するため。
    """
    warn_ms = warn_ms if warn_ms is not None else setting("ping.warn_ms", 60)
    usable = [s for s in samples.values() if isinstance(s, dict) and not s.get("error")]
    if not usable:
        return "測定できていません", "muted"

    losses = [s["loss_pct"] for s in usable if s.get("loss_pct") is not None]
    rtts = [s["avg_ms"] for s in usable if s.get("avg_ms") is not None]

    if losses and max(losses) >= 100:
        return "到達できません", "bad"
    if losses and max(losses) > 0:
        return f"パケット損失 {max(losses)}%", "bad"
    if not rtts:
        return "応答はあるが遅延を取得できません", "warn"
    if max(rtts) > warn_ms:
        return f"遅延が大きめ (最大 {max(rtts)}ms)", "warn"
    return "良好", "good"


def age_text(when):
    """datetime -> 「3日前」のような相対表記。None なら未測定。"""
    if not when:
        return "未測定", True
    delta = datetime.now() - when
    days, secs = delta.days, delta.seconds
    if days >= 1:
        return f"{days}日前", days >= STALE_DAYS
    if secs >= 3600:
        return f"{secs // 3600}時間前", False
    if secs >= 60:
        return f"{secs // 60}分前", False
    return "さっき", False


def freshness(sources):
    """advisor.collect() の結果 -> [(タブ名, 経過表記, 古いか)]。測定の抜けを可視化する。"""
    import advisor_tab as ad
    rows = []
    for kind, label in ad.KIND_TAB.items():
        src = sources.get(kind)
        text, stale = age_text(src.get("mtime") if src else None)
        rows.append((label, text, stale))
    return rows


def latest_grade(sources):
    """保存済みフル診断 -> (grade辞書, 測定時刻) / 無ければ (None, None)。"""
    full = sources.get("full")
    if not full or not isinstance(full.get("data"), dict):
        return None, None
    try:
        grade = nd.grade_connection(full["data"])
    except Exception:
        return None, full.get("mtime")
    return grade, full.get("mtime")


def top_advice(ev, limit=3):
    """evaluate() の結果 -> 上位の対策。priority 降順は evaluate 側で済んでいる。"""
    return list((ev.get("advice") or [])[:limit])


def link_summary(wifi, link):
    """Wi-Fi情報とリンク統計 -> 1行の接続概要。無線なら電波状況まで出す。"""
    if isinstance(wifi, dict) and wifi.get("available") and wifi.get("ssid"):
        parts = [f"Wi-Fi {wifi.get('ssid')}"]
        if wifi.get("radio_type"):
            parts.append(str(wifi["radio_type"]))
        if wifi.get("signal_pct") is not None:
            parts.append(f"電波 {wifi['signal_pct']}%")
        # キー名は nd.parse_wlan_interfaces の戻りに合わせる。rx_mbps 等と書き間違えても
        # 例外にならず黙って欠落するだけなので、下の自己テストで名前を固定している。
        if wifi.get("receive_rate_mbps"):
            parts.append(f"受信 {wifi['receive_rate_mbps']}Mbps")
        return " / ".join(parts)

    adapters = (link or {}).get("adapters") or []
    if adapters:
        return f"有線 {adapters[0].get('Name', '')}".strip()
    return "接続方式を取得できません"


class DashboardTab:
    def __init__(self, parent, ctx):
        self.ctx = ctx
        self.stop_event = threading.Event()
        self.raw = []            # テーマ追従が必要な素のtkウィジェット
        self._after_id = None
        self._busy = False

        head = ttk.Frame(parent, padding=(14, 12, 14, 4))
        head.pack(fill="x")
        ttk.Label(head, text="ダッシュボード", font=(ctx.font, 15, "bold")).pack(side="left")
        self.refresh_btn = ttk.Button(head, text="更新", command=self.refresh)
        self.refresh_btn.pack(side="right")
        self.auto_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(head, text=f"{DEFAULT_REFRESH_S}秒ごとに自動更新",
                        variable=self.auto_var).pack(side="right", padx=10)

        body = ttk.Frame(parent, padding=(14, 4, 14, 14))
        body.pack(fill="both", expand=True)

        # ---- 現在の状態 ----
        self.live_card = tk.Frame(body, bd=0, highlightthickness=1)
        self.live_card.pack(fill="x")
        self.raw.append(("card", self.live_card))
        # 余白は pack 側で付ける。ウィジェットの pady はタプルを受け付けず
        # TclError: bad screen distance になる(2要素タプルは pack/grid 専用)。
        self.live_label = tk.Label(self.live_card, text="測定中...", anchor="w",
                                   font=(ctx.font, 20, "bold"), padx=16)
        self.live_label.pack(fill="x", pady=(12, 0))
        self.raw.append(("value", self.live_label))
        self.live_detail = tk.Label(self.live_card, text="", anchor="w", justify="left",
                                    font=(ctx.font, 10), padx=16)
        self.live_detail.pack(fill="x", pady=(2, 12))
        self.raw.append(("muted", self.live_detail))

        # ---- カード3枚 ----
        cards = ttk.Frame(body)
        cards.pack(fill="x", pady=(12, 0))
        for i in range(3):
            cards.columnconfigure(i, weight=1, uniform="c")
        self.grade_card = self._card(cards, 0, "品質グレード")
        self.link_card = self._card(cards, 1, "接続")
        self.fresh_card = self._card(cards, 2, "測定の鮮度")

        # ---- 対策 ----
        adv = ttk.LabelFrame(body, text="いま効きそうな対策 (総合診断より)", padding=10)
        adv.pack(fill="both", expand=True, pady=(12, 0))
        self.advice_box = tk.Text(adv, height=9, wrap="word", bd=0,
                                  highlightthickness=0, font=(ctx.font, 10))
        self.advice_box.pack(fill="both", expand=True)
        self.advice_box.configure(state="disabled")
        self.raw.append(("text", self.advice_box))

        self.status = ttk.Label(body, text="", font=(ctx.font, 9))
        self.status.pack(anchor="w", pady=(8, 0))

        self.on_theme_changed()
        self._schedule(200)

    # ---- 部品 ----

    def _card(self, parent, col, title):
        frame = tk.Frame(parent, bd=0, highlightthickness=1)
        frame.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else 8, 0))
        self.raw.append(("card", frame))
        cap = tk.Label(frame, text=title, anchor="w", font=(self.ctx.font, 9), padx=12)
        cap.pack(fill="x", pady=(10, 0))
        self.raw.append(("muted", cap))
        big = tk.Label(frame, text="—", anchor="w", font=(self.ctx.font, 17, "bold"), padx=12)
        big.pack(fill="x", pady=(2, 0))
        self.raw.append(("value", big))
        sub = tk.Label(frame, text="", anchor="w", justify="left",
                       font=(self.ctx.font, 9), padx=12)
        sub.pack(fill="x", pady=(2, 12))
        self.raw.append(("muted", sub))
        frame.big, frame.sub = big, sub
        return frame

    def _theme(self):
        return self.ctx.theme

    def on_theme_changed(self):
        t = self._theme()
        for kind, w in self.raw:
            try:
                if kind == "card":
                    w.configure(bg=t["card_bg"], highlightbackground=t["graph_grid"])
                elif kind == "value":
                    w.configure(bg=t["card_bg"], fg=t["fg"])
                elif kind == "muted":
                    w.configure(bg=t["card_bg"], fg=t["muted"])
                elif kind == "text":
                    w.configure(bg=t["bg"], fg=t["fg"], insertbackground=t["fg"])
            except tk.TclError:
                pass
        for name, color in (("good", t["good"]), ("warn", t["warn"]),
                            ("bad", t["bad"]), ("muted", t["muted"])):
            try:
                self.advice_box.tag_configure(name, foreground=color)
            except tk.TclError:
                pass

    # ---- 更新 ----

    def _schedule(self, delay_ms=None):
        if self.stop_event.is_set():
            return
        delay = delay_ms if delay_ms is not None else DEFAULT_REFRESH_S * 1000
        try:
            self._after_id = self.ctx.root.after(delay, self._tick)
        except (RuntimeError, tk.TclError):
            pass

    def _tick(self):
        if self.auto_var.get():
            self.refresh()
        else:
            self._schedule()

    def refresh(self):
        if self._busy or self.stop_event.is_set():
            return
        self._busy = True
        self.status.configure(text="更新中...")
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self):
        payload = {}
        try:
            gw = nd.get_default_gateway()
            samples = {}
            if gw:
                samples["ゲートウェイ"] = nd.measure_latency(gw, count=LIVE_PING_COUNT, timeout_ms=1000)
            target = setting("targets.primary", "1.1.1.1")
            samples[target] = nd.measure_latency(target, count=LIVE_PING_COUNT, timeout_ms=1000)
            payload["samples"] = samples
            payload["gateway"] = gw
            payload["wifi"] = nd.get_wifi_info()
            payload["link"] = nd.get_link_stats()

            import advisor_tab as ad
            sources = ad.collect()
            payload["grade"], payload["grade_when"] = latest_grade(sources)
            payload["fresh"] = freshness(sources)
            try:
                payload["advice"] = top_advice(ad.evaluate(sources))
            except Exception as e:                      # 提案側が落ちても現況表示は出す
                payload["advice"] = []
                payload["advice_error"] = str(e)
        except Exception as e:
            payload["error"] = str(e)

        # mainloop が終わった後の after は例外になる。閉じ際に落とさない。
        try:
            self.ctx.root.after(0, self._apply, payload)
        except (RuntimeError, tk.TclError):
            pass

    def _apply(self, p):
        self._busy = False
        if self.stop_event.is_set():
            return
        t = self._theme()

        if p.get("error"):
            self.status.configure(text=f"更新に失敗: {p['error']}")
            self._schedule()
            return

        samples = p.get("samples") or {}
        label, tag = live_verdict(samples)
        self.live_label.configure(text=label, fg=t.get(tag, t["fg"]))
        detail = []
        for name, s in samples.items():
            if not isinstance(s, dict) or s.get("error"):
                detail.append(f"{name}: 測定失敗")
            else:
                detail.append(f"{name}: {s.get('avg_ms')}ms / 損失 {s.get('loss_pct')}%")
        self.live_detail.configure(text="   ".join(detail))

        grade, when = p.get("grade"), p.get("grade_when")
        if grade:
            age, stale = age_text(when)
            self.grade_card.big.configure(text=f"{grade['grade']}  {grade['score']}/100",
                                          fg=t["warn"] if stale else t["fg"])
            self.grade_card.sub.configure(
                text=f"{age}の測定{'（古い）' if stale else ''}\n{grade.get('comment', '')}")
        else:
            self.grade_card.big.configure(text="未測定", fg=t["muted"])
            self.grade_card.sub.configure(text="「フル診断」で一通り測ると出ます")

        self.link_card.big.configure(text=link_summary(p.get("wifi"), p.get("link")), fg=t["fg"])
        retrans = (p.get("link") or {}).get("tcp_retransmit_pct")
        self.link_card.sub.configure(
            text=f"TCP再送率 {retrans}%" if retrans is not None else "TCP再送率は取得できず")

        rows = p.get("fresh") or []
        missing = [r[0] for r in rows if r[1] == "未測定"]
        stale = [r[0] for r in rows if r[2] and r[1] != "未測定"]
        self.fresh_card.big.configure(
            text=f"{len(rows) - len(missing)}/{len(rows)} 種",
            fg=t["warn"] if (missing or stale) else t["good"])
        note = []
        if missing:
            note.append("未測定: " + "、".join(missing))
        if stale:
            note.append(f"{STALE_DAYS}日以上前: " + "、".join(stale))
        self.fresh_card.sub.configure(text="\n".join(note) if note else "すべて最近の測定です")

        self._render_advice(p)
        self.status.configure(text=f"最終更新 {datetime.now().strftime('%H:%M:%S')}")
        self._schedule()

    def _render_advice(self, p):
        self.advice_box.configure(state="normal")
        self.advice_box.delete("1.0", "end")
        advice = p.get("advice") or []
        if p.get("advice_error"):
            self.advice_box.insert("end", f"提案の生成に失敗: {p['advice_error']}\n", "muted")
        elif not advice:
            self.advice_box.insert(
                "end", "提案できる対策がありません。\n"
                       "各タブで測定して結果を保存すると、根拠つきで優先度順に並びます。\n", "muted")
        for i, a in enumerate(advice, 1):
            import advisor_tab as ad
            tag = ad.CONF_TAG.get(a.get("confidence"), "muted")
            self.advice_box.insert("end", f"{i}. [{a.get('confidence')}] {a.get('title')}\n", tag)
            for ev in (a.get("evidence") or [])[:2]:
                self.advice_box.insert("end", f"     根拠: {ev}\n", "muted")
            if a.get("expect"):
                self.advice_box.insert("end", f"     見込み: {a['expect']}\n", "muted")
        self.advice_box.configure(state="disabled")

    def on_close(self):
        self.stop_event.set()
        if self._after_id is not None:
            try:
                self.ctx.root.after_cancel(self._after_id)
            except (RuntimeError, tk.TclError):
                pass


# ---------- 自己テスト ----------

def _selftest():
    from datetime import timedelta

    # 損失は遅延より優先される(速くても落ちていれば問題)
    assert live_verdict({"a": {"avg_ms": 3, "loss_pct": 0}})[1] == "good"
    assert live_verdict({"a": {"avg_ms": 3, "loss_pct": 5}})[1] == "bad"
    assert live_verdict({"a": {"avg_ms": 3, "loss_pct": 100}})[0] == "到達できません"
    # 遅い方に引きずられる(片方が良くても全体は警告)
    assert live_verdict({"a": {"avg_ms": 3, "loss_pct": 0},
                         "b": {"avg_ms": 900, "loss_pct": 0}}, warn_ms=60)[1] == "warn"
    # 測定できていないものは good と言わない
    assert live_verdict({})[1] == "muted"
    assert live_verdict({"a": {"error": "boom"}})[1] == "muted"
    assert live_verdict({"a": {"loss_pct": 0, "avg_ms": None}})[1] == "warn"

    # 鮮度: 未測定と「測ったが古い」を混同しない
    assert age_text(None) == ("未測定", True)
    assert age_text(datetime.now())[0] == "さっき"
    assert age_text(datetime.now() - timedelta(minutes=5)) == ("5分前", False)
    assert age_text(datetime.now() - timedelta(hours=3)) == ("3時間前", False)
    assert age_text(datetime.now() - timedelta(days=2)) == ("2日前", False)
    assert age_text(datetime.now() - timedelta(days=30)) == ("30日前", True)

    # 接続概要: 無線が取れれば無線、無ければ有線、どちらも無ければ言い切らない
    assert "Wi-Fi" in link_summary({"available": True, "ssid": "home", "signal_pct": 80}, {})
    assert link_summary({"available": False}, {"adapters": [{"Name": "イーサネット"}]}) \
        == "有線 イーサネット"
    assert "取得できません" in link_summary({}, {})

    # 参照しているキー名が nd 側の実際の戻りと一致していること。
    # 綴り違いは例外にならず「その項目だけ消える」ので気づけない。実際 rx_mbps と
    # 書いていて receive_rate_mbps が正しかった。
    wifi_keys = nd.parse_wlan_interfaces(
        "SSID                   : home\n"
        "Radio type             : 802.11ax\n"
        "Signal                 : 82%\n"
        "Receive rate (Mbps)    : 1200\n"
        "Transmit rate (Mbps)   : 1200\n")
    assert wifi_keys["available"], wifi_keys
    summary = link_summary(wifi_keys, {})
    for expect in ("home", "802.11ax", "82%", "1200Mbps"):
        assert expect in summary, (expect, summary)

    # グレード/提案は空データでも落ちない
    assert latest_grade({}) == (None, None)
    assert latest_grade({"full": {"data": "壊れている"}}) == (None, None)
    assert top_advice({}) == []
    assert top_advice({"advice": [1, 2, 3, 4, 5]}, limit=2) == [1, 2]

    # 鮮度表は advisor の種類を全部並べる(抜けをそのまま可視化するため)
    import advisor_tab as ad
    rows = freshness({})
    assert len(rows) == len(ad.KIND_TAB)
    assert all(r[1] == "未測定" for r in rows)

    # ウィジェットが実際に組み立つこと。純関数のテストだけでは
    # pady=(0, 12) のような Tk 固有の型エラーを取り逃す(実際に取り逃した)。
    root = tk.Tk()
    root.withdraw()

    class _Ctx:
        font = "Segoe UI"
        theme = {"bg": "#1c1c1c", "card_bg": "#2b2b2b", "fg": "#f2f2f2", "muted": "#9d9d9d",
                 "good": "#3fb950", "warn": "#e3b341", "bad": "#f85149",
                 "graph_bg": "#232323", "graph_grid": "#3a3a3a"}

    ctx = _Ctx()
    ctx.root = root
    tab = DashboardTab(tk.Frame(root), ctx)
    root.update()

    # 測定結果が無くても描画できること(初回起動はこの状態)
    tab._apply({"samples": {}, "fresh": freshness({}), "advice": []})
    root.update()
    # 一通り値が入った状態でも落ちないこと
    tab._apply({"samples": {"gw": {"avg_ms": 4, "loss_pct": 0}},
                "wifi": {"available": False}, "link": {"tcp_retransmit_pct": 3.6,
                                                       "adapters": [{"Name": "イーサネット"}]},
                "grade": {"grade": "D", "score": 54.0, "comment": "テスト"},
                "grade_when": datetime.now(), "fresh": freshness({}), "advice": []})
    root.update()
    tab.on_theme_changed()
    tab.on_close()
    root.update()
    root.destroy()

    print("dashboard selftest: OK")


if __name__ == "__main__":
    import sys

    if "--selftest" in sys.argv:
        _selftest()
        sys.exit()

    root = tk.Tk()
    root.title("dashboard 単体")
    root.geometry("980x760")

    class Ctx:
        font = "Segoe UI"
        theme = {"bg": "#1c1c1c", "card_bg": "#2b2b2b", "fg": "#f2f2f2", "muted": "#9d9d9d",
                 "good": "#3fb950", "warn": "#e3b341", "bad": "#f85149",
                 "graph_bg": "#232323", "graph_grid": "#3a3a3a"}

    ctx = Ctx()
    ctx.root = root
    tab = DashboardTab(root, ctx)
    root.protocol("WM_DELETE_WINDOW", lambda: (tab.on_close(), root.destroy()))
    root.mainloop()
