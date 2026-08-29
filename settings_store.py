"""全モジュール共通の設定ストア。JSONに永続化し、変更を購読できる。

各タブが独自に持っている定数のうち、ユーザーが触りたくなるものをここへ集約する。
値は "section.key" のドット記法で読み書きする。未知のキーを読むと KeyError ではなく
DEFAULTS 由来の値が返るので、呼び出し側で毎回 try する必要はない。
"""
import copy
import json
import threading
import sys
from pathlib import Path

def app_dir():
    """設定やAPIキーなど「消えては困るファイル」を置く基準ディレクトリ。
    PyInstaller onefile の __file__ は %TEMP%\_MEIxxxx を指し終了時に消えるので、
    凍結時は exe 本体の隣を使う。ここを間違えると exe 版だけ保存されない。"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent


CONFIG_PATH = app_dir() / "settings.json"

# (既定値, 型, ラベル, 説明, 制約) の形で1か所に定義する。設定ウィンドウはこれを読んでUIを自動生成する。
# 型: "int" / "float" / "bool" / "str" / "choice"
SCHEMA = {
    "general": {
        "_label": "全般",
        "contract_mbps": (1000, "int", "契約速度 (Mbps)",
                          "品質グレードの採点で「契約比」を出すのに使う。実際の契約プランに合わせること。",
                          {"min": 1, "max": 100000}),
        "theme": ("dark", "choice", "テーマ", "起動時のテーマ。", {"choices": ["dark", "light"]}),
        "window_width": (1500, "int", "ウィンドウ幅", "起動時の幅(px)。タブが14枚あるので1400以上を推奨。",
                         {"min": 900, "max": 5000}),
        "window_height": (780, "int", "ウィンドウ高さ", "起動時の高さ(px)。", {"min": 600, "max": 3000}),
    },
    "targets": {
        "_label": "測定先",
        "primary": ("1.1.1.1", "str", "主要ターゲット1", "遅延・経路測定に使う宛先。", {}),
        "secondary": ("8.8.8.8", "str", "主要ターゲット2", "比較用の2つ目の宛先。", {}),
        "speed_host": ("speed.cloudflare.com", "str", "速度測定サーバ",
                       "スループット測定に使うホスト。変更すると測定値の互換性が失われる点に注意。", {}),
    },
    "ping": {
        "_label": "Ping / パケロス",
        "interval_s": (1.0, "float", "更新間隔 (秒)", "連続pingの送信間隔。", {"min": 0.2, "max": 10.0}),
        "loss_alert_streak": (3, "int", "連続応答なしの警告しきい値",
                              "この回数連続でタイムアウトすると警告を出す。", {"min": 1, "max": 50}),
        "graph_points": (80, "int", "グラフの表示点数", "折れ線グラフに表示する直近の点数。",
                         {"min": 20, "max": 1000}),
        "warn_ms": (60, "int", "遅延の警告しきい値 (ms)", "これ以上で数値が黄色になる。", {"min": 1, "max": 5000}),
    },
    "throughput": {
        "_label": "スループット測定",
        "duration_s": (8, "int", "測定時間 (秒)",
                       "1方向あたりの測定秒数。長くしても精度はあまり上がらず通信量だけ増える(実測で確認済み)。",
                       {"min": 1, "max": 60}),
        "parallel_streams": (6, "int", "並列接続数", "並列ダウンロード/アップロードのストリーム数。",
                             {"min": 1, "max": 32}),
        "chunk_mb": (4, "int", "1リクエストのサイズ (MB)",
                     "Cloudflareは1リクエストが大きすぎると403/429を返すため、小さめに保つこと。",
                     {"min": 1, "max": 90}),
    },
    "bufferbloat": {
        "_label": "バッファブロート",
        "idle_count": (10, "int", "アイドル時のping回数", "", {"min": 3, "max": 100}),
        "load_streams": (6, "int", "負荷をかける並列数", "", {"min": 1, "max": 32}),
        "load_duration_s": (10, "int", "負荷時間 (秒)", "", {"min": 3, "max": 60}),
    },
    "services": {
        "_label": "サービス到達性",
        "workers": (2, "int", "並列度",
                    "上げると測定値そのものが歪む(実測: 1並列9.9ms→16並列23.9ms)。2を推奨。",
                    {"min": 1, "max": 16}),
        "trials": (5, "int", "1宛先あたりの試行回数", "", {"min": 1, "max": 20}),
        "good_ms": (30, "int", "良好と判定する上限 (ms)", "", {"min": 1, "max": 1000}),
        "warn_ms": (70, "int", "警告と判定する上限 (ms)", "これを超えると赤。", {"min": 1, "max": 5000}),
    },
    "watchdog": {
        "_label": "常時監視",
        "interval_s": (5.0, "float", "ping間隔 (秒)", "", {"min": 1.0, "max": 300.0}),
        "timeout_streak": (3, "int", "連続タイムアウトで記録", "", {"min": 1, "max": 50}),
        "spike_factor": (3.0, "float", "RTT急増と見なす倍率", "直近の中央値の何倍でイベントとするか。",
                         {"min": 1.5, "max": 20.0}),
        "spike_min_delta_ms": (20, "int", "RTT急増の最小増加量 (ms)",
                               "倍率だけだと低遅延の宛先で誤検出するため、絶対量の下限も併用する。",
                               {"min": 1, "max": 1000}),
    },
    "trend": {
        "_label": "時間帯トレンド",
        "interval_min": (30, "int", "自動計測の間隔 (分)", "短くすると通信量が増える点に注意。",
                         {"min": 5, "max": 720}),
        "sample_duration_s": (3, "int", "1回あたりの測定秒数", "通信量に直結する。", {"min": 1, "max": 30}),
        "min_samples": (3, "int", "傾向を語るのに必要な件数",
                        "各時間帯でこの件数未満なら「データ不足」と表示する。", {"min": 1, "max": 100}),
    },
    "lanscan": {
        "_label": "LAN機器スキャン",
        "ping_workers": (64, "int", "並列ping数", "", {"min": 1, "max": 256}),
        "ping_timeout_ms": (500, "int", "pingタイムアウト (ms)", "", {"min": 100, "max": 5000}),
        "vendor_lookup": (True, "bool", "MACベンダーを外部APIで照会する",
                          "オフにするとローカル辞書のみになり、外部通信が発生しない。", {}),
    },
    "capture": {
        "_label": "通信量キャプチャ",
        "save_pcap": (False, "bool", "既定でpcapを保存する",
                      "Wiresharkで開ける形式。管理者権限が必要。", {}),
        "top_limit": (30, "int", "表示する上位件数", "", {"min": 5, "max": 200}),
    },
    "advanced": {
        "_label": "詳細",
        "ipinfo_enabled": (True, "bool", "ipinfo.io でIP情報を照会する",
                           "オフにすると組織名・都市が表示されなくなるが、外部への問い合わせが減る。", {}),
        "mtu_probe_low": (1200, "int", "MTU探索の下限ペイロード", "", {"min": 500, "max": 1400}),
        "mtu_probe_high": (1472, "int", "MTU探索の上限ペイロード",
                           "1472 + 28(IP+ICMPヘッダ) = 1500 が上限。", {"min": 1400, "max": 1472}),
        "jitter_samples": (20, "int", "ジッター測定のサンプル数", "", {"min": 5, "max": 200}),
    },
}


def defaults():
    out = {}
    for section, items in SCHEMA.items():
        out[section] = {k: v[0] for k, v in items.items() if not k.startswith("_")}
    return out


class SettingsStore:
    def __init__(self, path=CONFIG_PATH):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._listeners = []
        self._data = defaults()
        self.load()

    # ---- 永続化 ----

    def load(self):
        """保存済みの設定を読む。壊れていたら既定値のまま続行する(起動を止めない)。"""
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        if not isinstance(raw, dict):
            return False
        with self._lock:
            for section, items in raw.items():
                if section not in self._data or not isinstance(items, dict):
                    continue  # 知らないセクションは無視(古い設定ファイルとの互換性)
                for key, value in items.items():
                    if key in self._data[section]:
                        coerced = self._coerce(section, key, value)
                        if coerced is not None:
                            self._data[section][key] = coerced
        return True

    def save(self):
        with self._lock:
            snapshot = copy.deepcopy(self._data)
        self.path.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
        return self.path

    # ---- 値の読み書き ----

    def _coerce(self, section, key, value):
        """スキーマの型と制約に合わせる。合わなければ None を返して呼び出し側で既定値を使わせる。"""
        spec = SCHEMA.get(section, {}).get(key)
        if not spec:
            return None
        _, kind, _, _, limits = spec
        try:
            if kind == "int":
                value = int(value)
            elif kind == "float":
                value = float(value)
            elif kind == "bool":
                value = bool(value)
            elif kind == "choice":
                value = str(value)
                if value not in limits.get("choices", []):
                    return None
            else:
                value = str(value)
        except (TypeError, ValueError):
            return None
        if kind in ("int", "float"):
            if "min" in limits:
                value = max(limits["min"], value)
            if "max" in limits:
                value = min(limits["max"], value)
        return value

    def get(self, dotted, fallback=None):
        section, _, key = dotted.partition(".")
        with self._lock:
            if section in self._data and key in self._data[section]:
                return self._data[section][key]
        if fallback is not None:
            return fallback
        spec = SCHEMA.get(section, {}).get(key)
        return spec[0] if spec else None

    def set(self, dotted, value, notify=True):
        section, _, key = dotted.partition(".")
        coerced = self._coerce(section, key, value)
        if coerced is None:
            return False
        with self._lock:
            if section not in self._data:
                return False
            changed = self._data[section].get(key) != coerced
            self._data[section][key] = coerced
        if changed and notify:
            self._notify(dotted, coerced)
        return True

    def section(self, name):
        with self._lock:
            return dict(self._data.get(name, {}))

    def reset_section(self, name):
        with self._lock:
            if name not in SCHEMA:
                return False
            self._data[name] = {k: v[0] for k, v in SCHEMA[name].items() if not k.startswith("_")}
        self._notify(f"{name}.*", None)
        return True

    def reset_all(self):
        with self._lock:
            self._data = defaults()
        self._notify("*", None)

    # ---- 変更通知 ----

    def subscribe(self, callback):
        """callback(dotted, value) を変更時に呼ぶ。UIスレッド外から呼ばれうる点に注意。"""
        self._listeners.append(callback)
        return callback

    def unsubscribe(self, callback):
        if callback in self._listeners:
            self._listeners.remove(callback)

    def _notify(self, dotted, value):
        for cb in list(self._listeners):
            try:
                cb(dotted, value)
            except Exception:
                pass  # 1つのリスナーの失敗で他を巻き込まない


# アプリ全体で共有する単一インスタンス
settings = SettingsStore()


def setting(dotted, fallback):
    """設定を1件取る。ストアが壊れている/未初期化でも呼び出し側を落とさない。
    各モジュールが同じtry/exceptを書いていたのをここに集約したもの。"""
    try:
        value = settings.get(dotted)
    except Exception:
        return fallback
    return fallback if value is None else value



def _selftest():
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "s.json"
        s = SettingsStore(p)

        assert s.get("general.contract_mbps") == 1000
        assert s.get("services.workers") == 2

        # 範囲外はクランプされる
        assert s.set("general.contract_mbps", 999999999)
        assert s.get("general.contract_mbps") == 100000
        assert s.set("ping.interval_s", 0.01)
        assert s.get("ping.interval_s") == 0.2

        # 型違いは弾く / 数値文字列は受ける
        assert not s.set("general.contract_mbps", "abc")
        assert s.set("general.contract_mbps", "500")
        assert s.get("general.contract_mbps") == 500
        assert not s.set("general.theme", "purple")   # choices 外
        assert s.set("general.theme", "light")
        assert not s.set("nosuch.key", 1)

        # 保存 → 別インスタンスで復元
        s.save()
        s2 = SettingsStore(p)
        assert s2.get("general.contract_mbps") == 500
        assert s2.get("general.theme") == "light"

        # 壊れたJSONでも既定値で起動できる
        p.write_text("{ broken", encoding="utf-8")
        s3 = SettingsStore(p)
        assert s3.get("general.contract_mbps") == 1000

        # 知らないセクション/キーが入っていても既存値を壊さない
        p.write_text(json.dumps({"general": {"contract_mbps": 300, "unknown": 1}, "ghost": {"a": 1}}),
                     encoding="utf-8")
        s4 = SettingsStore(p)
        assert s4.get("general.contract_mbps") == 300
        assert s4.get("general.theme") == "dark"

        # 通知
        seen = []
        s4.subscribe(lambda d, v: seen.append((d, v)))
        s4.set("ping.warn_ms", 99)
        assert seen == [("ping.warn_ms", 99)], seen
        s4.set("ping.warn_ms", 99)  # 同値なら通知しない
        assert len(seen) == 1

        # セクション単位のリセット
        s4.reset_section("ping")
        assert s4.get("ping.warn_ms") == 60

        # スキーマの妥当性: 既定値が自身の制約を満たすこと
        for section, items in SCHEMA.items():
            for key, spec in items.items():
                if key.startswith("_"):
                    continue
                default, kind, label, _desc, limits = spec
                assert label, f"{section}.{key} にラベルが無い"
                if kind in ("int", "float"):
                    assert limits.get("min", default) <= default <= limits.get("max", default), \
                        f"{section}.{key} の既定値が制約外"
                if kind == "choice":
                    assert default in limits["choices"], f"{section}.{key} の既定値がchoices外"

    # 設定項目が実際にどこかで読まれていること。設定ウィンドウに出ているのに
    # 誰も参照していない「飾りのつまみ」が11件生えていたので、それを再発させないため。
    # exe(凍結)では .py が無いのでスキップする。
    src_dir = Path(__file__).resolve().parent
    sources = [f for f in src_dir.glob("*.py") if f.name not in ("settings_store.py", "settings_window.py")]
    if sources:
        blob = "".join(f.read_text(encoding="utf-8", errors="replace") for f in sources)
        dead = [f"{sec}.{k}" for sec, items in SCHEMA.items()
                for k in items if not k.startswith("_") and f"{sec}.{k}" not in blob]
        assert not dead, f"どのモジュールからも読まれていない設定: {dead}"

    print("settings selftest: OK")


if __name__ == "__main__":
    _selftest()
