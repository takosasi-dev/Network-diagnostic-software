"""exe をビルドする。手打ちのPyInstaller呼び出しを覚えておく必要をなくすためのもの。

  python build.py

プラグインタブは network_diag_gui.py から動的に import されるため PyInstaller の
静的解析では検出されない。--hidden-import で明示しないと exe だけタブが消える。
"""
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def plugin_modules():
    """GUI が読み込むタブモジュール名を network_diag_gui.py から拾う。
    リストを二重管理して片方だけ更新する事故を防ぐため、手書きしない。"""
    src = (HERE / "network_diag_gui.py").read_text(encoding="utf-8")
    mods = re.findall(r'\("([a-z0-9_]+_tab)",\s*"[A-Za-z0-9_]+",', src)
    assert mods, "network_diag_gui.py からタブ一覧を拾えなかった"
    return sorted(set(mods))


def build(script, extra):
    cmd = [sys.executable, "-m", "PyInstaller", "--onefile", "--clean", "-y",
           "--distpath", str(HERE), "--workpath", str(HERE / "build"),
           "--specpath", str(HERE / "build")] + extra + [str(HERE / script)]
    print(">", " ".join(cmd[3:]))
    subprocess.run(cmd, check=True, cwd=HERE)


def main():
    mods = plugin_modules()
    print(f"タブモジュール {len(mods)} 件: {', '.join(mods)}")

    build("network_diag.py", ["--console", "--hidden-import", "settings_store"])

    gui_extra = ["--noconsole", "--collect-data", "sv_ttk",
                 "--hidden-import", "settings_store",
                 "--hidden-import", "settings_window",
                 "--hidden-import", "traffic_monitor"]
    for m in mods:
        gui_extra += ["--hidden-import", m]
    build("network_diag_gui.py", gui_extra)

    for exe in ("network_diag.exe", "network_diag_gui.exe"):
        p = HERE / exe
        assert p.exists(), f"{exe} が生成されていない"
        print(f"OK {exe} {p.stat().st_size / 1e6:.1f} MB")


if __name__ == "__main__":
    main()
