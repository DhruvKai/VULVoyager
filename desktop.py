"""Standalone desktop entry point.

Runs the Flask app in a background thread and shows it in a native window
via pywebview (Windows: WebView2) -- no console, no browser tab.
"""

import socket
import sys
import threading
import time

import webview

from app import app, resource_path


def force_dark_titlebar(window):
    """Force a dark native title bar + frame border (Windows 10 1809+/11)
    matching the app's dark-by-default theme, instead of following the OS's
    separate light/dark setting (pywebview only auto-darkens the title bar
    when Windows itself is in dark mode) and Windows 11's system accent-color
    window border (visible as a bright, mismatched outline otherwise).
    Best-effort -- silently does nothing if unsupported."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        from webview.platforms.winforms import BrowserView

        form = BrowserView.instances.get(window.uid)
        if form is None:
            return
        hwnd = form.Handle.ToInt32()
        dwmapi = ctypes.windll.dwmapi

        DWMWA_USE_IMMERSIVE_DARK_MODE = 20
        DWMWA_BORDER_COLOR = 34  # Windows 11 22000+ only; no-ops on Windows 10
        DWMWA_CAPTION_COLOR = 35  # Windows 11 22000+ only; no-ops on Windows 10
        surface_color = 0x001E1E1E  # BGR, matches the app's --bg-primary-dm

        dwmapi.DwmSetWindowAttribute(
            hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE,
            ctypes.byref(ctypes.c_int(1)), ctypes.sizeof(ctypes.c_int)
        )
        dwmapi.DwmSetWindowAttribute(
            hwnd, DWMWA_CAPTION_COLOR,
            ctypes.byref(ctypes.c_int(surface_color)), ctypes.sizeof(ctypes.c_int)
        )
        dwmapi.DwmSetWindowAttribute(
            hwnd, DWMWA_BORDER_COLOR,
            ctypes.byref(ctypes.c_int(surface_color)), ctypes.sizeof(ctypes.c_int)
        )
    except Exception:
        pass  # cosmetic only -- never block app startup over this


def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_for_server(host, port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def main():
    host, port = "127.0.0.1", get_free_port()

    threading.Thread(
        target=lambda: app.run(host=host, port=port, debug=False,
                                use_reloader=False, threaded=True),
        daemon=True,
    ).start()

    if not wait_for_server(host, port):
        raise RuntimeError("VULVoyager server did not start in time")

    window = webview.create_window(
        "VULVoyager",
        f"http://{host}:{port}/",
        width=1400,
        height=900,
        min_size=(1000, 700),
    )
    window.events.shown += lambda: force_dark_titlebar(window)
    webview.start(icon=resource_path("icon.ico"))


if __name__ == "__main__":
    main()
