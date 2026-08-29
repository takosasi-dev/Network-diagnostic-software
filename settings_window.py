"""設定を別ウィンドウ(Toplevel)で編集する画面。

UIは settings_store.SCHEMA から自動生成する。設定項目を増やすときは SCHEMA に足すだけでよく、
この画面には手を入れない。
"""
import tkinter as tk
from tkinter import ttk

from settings_store import SCHEMA, settings

FONT = "Segoe UI"


class SettingsWindow(tk.Toplevel):
    """アプリにつき1枚だけ開く設定ウィンドウ。既に開いていれば前面に出す。"""

    _instance = None

    @classmethod
    def open(cls, parent, theme, on_applied=None):
        if cls._instance is not None and cls._instance.winfo_exists():
            cls._instance.deiconify()
            cls._instance.lift()
            cls._instance.focus_force()
            return cls._instance
        cls._instance = cls(parent, theme, on_applied)
        return cls._instance

    def __init__(self, parent, theme, on_applied=None):
        super().__init__(parent)
        self.theme = theme
        self.on_applied = on_applied
        self.vars = {}          # "section.key" -> tk変数
        self.error_labels = {}  # "section.key" -> ttk.Label

        self.title("設定")
        self.geometry("1000x660")
        self.minsize(820, 520)
        self.transient(parent)

        header = ttk.Frame(self, padding=(16, 12, 16, 4))
        header.pack(fill="x")
        ttk.Label(header, text="設定", font=(FONT, 14, "bold")).pack(side="left")
        self.status = ttk.Label(header, text="", font=(FONT, 9))
        self.status.pack(side="right")

        # セクションが多くタブでは見出しが見切れるため、左に一覧・右に内容を出す形にする
        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, padx=12, pady=(4, 4))

        self.section_list = tk.Listbox(body, width=20, activestyle="none", exportselection=False,
                                       bd=0, highlightthickness=0, font=(FONT, 10))
        self.section_list.pack(side="left", fill="y", padx=(0, 12))

        self.content = ttk.Frame(body)
        self.content.pack(side="left", fill="both", expand=True)

        self.section_frames = {}
        self.section_names = []
        for section, items in SCHEMA.items():
            self.section_names.append(section)
            self.section_list.insert("end", f"  {items.get('_label', section)}")
            frame = self._build_section(self.content, section, items)
            self.section_frames[section] = frame

        self.section_list.bind("<<ListboxSelect>>", self._on_section_select)
        self.section_list.selection_set(0)
        self._show_section(self.section_names[0])

        footer = ttk.Frame(self, padding=(16, 8, 16, 12))
        footer.pack(fill="x")
        ttk.Button(footer, text="すべて既定値に戻す", command=self._reset_all).pack(side="left")
        ttk.Button(footer, text="閉じる", command=self._close).pack(side="right")
        ttk.Button(footer, text="適用して保存", style="Accent.TButton",
                   command=self._apply).pack(side="right", padx=(0, 8))

        self.protocol("WM_DELETE_WINDOW", self._close)

    # ---- セクションの切り替え ----

    def _on_section_select(self, _event=None):
        sel = self.section_list.curselection()
        if sel:
            self._show_section(self.section_names[sel[0]])

    def _show_section(self, section):
        for frame in self.section_frames.values():
            frame.pack_forget()
        self.section_frames[section].pack(fill="both", expand=True)
        self._apply_list_colors()

    def _apply_list_colors(self):
        t = self.theme
        self.section_list.configure(bg=t["card_bg"], fg=t["fg"],
                                    selectbackground="#0a84ff", selectforeground="#ffffff")

    # ---- セクションのUI生成 ----

    def _build_section(self, parent, section, items):
        outer = ttk.Frame(parent)
        canvas = tk.Canvas(outer, highlightthickness=0, bg=self.theme["bg"])
        scroll = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas, padding=(12, 12))
        inner_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(inner_id, width=e.width))
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        inner.columnconfigure(1, weight=1)
        row = 0
        for key, spec in items.items():
            if key.startswith("_"):
                continue
            default, kind, label, desc, limits = spec
            dotted = f"{section}.{key}"
            current = settings.get(dotted)

            ttk.Label(inner, text=label, font=(FONT, 10)).grid(
                row=row, column=0, sticky="w", pady=(8, 0), padx=(0, 12))
            self._build_editor(inner, dotted, kind, current, limits).grid(
                row=row, column=1, sticky="w", pady=(8, 0))
            row += 1

            if desc:
                ttk.Label(inner, text=desc, font=(FONT, 8), foreground=self.theme["muted"],
                          wraplength=680, justify="left").grid(
                    row=row, column=0, columnspan=2, sticky="w", pady=(1, 0))
                row += 1

            err = ttk.Label(inner, text="", font=(FONT, 8), foreground=self.theme["bad"])
            err.grid(row=row, column=0, columnspan=2, sticky="w")
            self.error_labels[dotted] = err
            row += 1

            ttk.Separator(inner, orient="horizontal").grid(
                row=row, column=0, columnspan=2, sticky="ew", pady=(6, 0))
            row += 1

        ttk.Button(inner, text=f"「{items.get('_label', section)}」を既定値に戻す",
                   command=lambda s=section: self._reset_section(s)).grid(
            row=row, column=0, columnspan=2, sticky="w", pady=(14, 0))
        return outer

    def _build_editor(self, parent, dotted, kind, current, limits):
        if kind == "bool":
            var = tk.BooleanVar(value=bool(current))
            widget = ttk.Checkbutton(parent, variable=var, text="有効")
        elif kind == "choice":
            var = tk.StringVar(value=str(current))
            widget = ttk.Combobox(parent, textvariable=var, values=limits.get("choices", []),
                                  state="readonly", width=18)
        elif kind in ("int", "float"):
            var = tk.StringVar(value=str(current))
            step = 1 if kind == "int" else 0.1
            widget = ttk.Spinbox(parent, textvariable=var, width=14,
                                 from_=limits.get("min", 0), to=limits.get("max", 10 ** 9),
                                 increment=step)
        else:
            var = tk.StringVar(value=str(current))
            widget = ttk.Entry(parent, textvariable=var, width=32)
        self.vars[dotted] = var
        return widget

    # ---- 操作 ----

    def _apply(self):
        applied, rejected = 0, []
        for dotted, var in self.vars.items():
            for lbl in (self.error_labels.get(dotted),):
                if lbl:
                    lbl.config(text="")
            try:
                value = var.get()
            except tk.TclError:
                value = ""
            before = settings.get(dotted)
            if settings.set(dotted, value):
                if settings.get(dotted) != before:
                    applied += 1
                # クランプされた場合は入力欄を実際の値へ戻して見た目を一致させる
                actual = settings.get(dotted)
                if str(actual) != str(value):
                    var.set(actual if not isinstance(actual, bool) else actual)
            else:
                rejected.append(dotted)
                lbl = self.error_labels.get(dotted)
                if lbl:
                    lbl.config(text=f"入力が不正なため無視しました(現在値: {before})")

        path = settings.save()
        if rejected:
            self.status.config(text=f"{applied}件を保存 / {len(rejected)}件は不正のため無視",
                               foreground=self.theme["warn"])
        else:
            self.status.config(text=f"{applied}件を保存しました → {path.name}",
                               foreground=self.theme["good"])
        if self.on_applied:
            self.on_applied()

    def _reset_section(self, section):
        settings.reset_section(section)
        self._reload_vars()
        self.status.config(text=f"「{SCHEMA[section].get('_label', section)}」を既定値に戻しました(未保存)",
                           foreground=self.theme["muted"])

    def _reset_all(self):
        settings.reset_all()
        self._reload_vars()
        self.status.config(text="すべて既定値に戻しました(未保存)", foreground=self.theme["muted"])

    def _reload_vars(self):
        for dotted, var in self.vars.items():
            var.set(settings.get(dotted))
        for lbl in self.error_labels.values():
            lbl.config(text="")

    def _close(self):
        type(self)._instance = None
        self.destroy()


def _selftest():
    """UIを実際に組み立てて、SCHEMAの全項目にエディタが生成されることを確認する。"""
    import sv_ttk

    root = tk.Tk()
    root.withdraw()
    sv_ttk.set_theme("dark")
    theme = {"bg": "#1c1c1c", "card_bg": "#2b2b2b", "fg": "#f2f2f2", "muted": "#9d9d9d",
             "good": "#3fb950", "warn": "#e3b341", "bad": "#f85149",
             "graph_bg": "#232323", "graph_grid": "#3a3a3a"}

    win = SettingsWindow.open(root, theme)
    root.update()

    expected = {f"{s}.{k}" for s, items in SCHEMA.items() for k in items if not k.startswith("_")}
    assert set(win.vars) == expected, set(win.vars) ^ expected
    assert set(win.error_labels) == expected

    # 左の一覧にSCHEMAの全セクションが並び、切り替えで内容が入れ替わること
    assert win.section_names == list(SCHEMA), win.section_names
    assert win.section_list.size() == len(SCHEMA)
    for section in SCHEMA:
        win._show_section(section)
        root.update()
        shown = [s for s, f in win.section_frames.items() if f.winfo_manager()]
        assert shown == [section], (section, shown)

    # 同じウィンドウが再利用されること(2枚開かない)
    assert SettingsWindow.open(root, theme) is win

    # 不正な入力は無視され、既存の値が壊れないこと
    before = settings.get("general.contract_mbps")
    win.vars["general.contract_mbps"].set("abc")
    win._apply()
    assert settings.get("general.contract_mbps") == before
    assert "不正" in win.error_labels["general.contract_mbps"].cget("text")

    # 範囲外はクランプされ、入力欄も実際の値に揃うこと
    win.vars["ping.interval_s"].set("999")
    win._apply()
    assert settings.get("ping.interval_s") == 10.0
    assert win.vars["ping.interval_s"].get() == "10.0"

    win._reset_all()
    assert settings.get("general.contract_mbps") == 1000
    settings.save()

    win._close()
    assert SettingsWindow._instance is None
    root.destroy()
    print("settings_window selftest: OK")


if __name__ == "__main__":
    _selftest()
