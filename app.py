from datetime import datetime
import os
import platform
import re
import socket
import sqlite3
import subprocess
import threading
import tkinter.messagebox as messagebox
import winreg
import customtkinter as ctk
import psutil

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

NO_WINDOW = 0x08000000
COLOR_BG_MAIN = "#0f172a"
COLOR_SIDEBAR = "#1e293b"
COLOR_CARD = "#1e293b"
COLOR_CARD_INNER = "#0f172a"
COLOR_ACCENT = "#6366f1"
COLOR_ACCENT_HOVER = "#4f46e5"
COLOR_SUCCESS = "#10b981"
COLOR_WARNING = "#f59e0b"
COLOR_DANGER = "#ef4444"
COLOR_TEXT_MUTED = "#94a3b8"

HIGH_RISK_PORTS = {
    21: ("FTP", "Truyền tệp không mã hóa, dễ bị nghe lén mật khẩu."),
    22: ("SSH", "Cổng điều khiển từ xa, cần giới hạn IP truy cập."),
    23: ("Telnet", "Giao thức lỗi thời, truyền dữ liệu dạng văn bản thuần."),
    135: ("MS-RPC", "Dịch vụ gọi thủ tục từ xa của Windows, hay bị khai thác."),
    139: ("NetBIOS", "Chia sẻ tài nguyên mạng cũ, dễ lộ thông tin hệ thống."),
    445: ("SMB", "Cổng chia sẻ file Windows, mục tiêu của mã độc WannaCry."),
    1433: ("MSSQL", "Cổng cơ sở dữ liệu SQL Server, không nên mở công khai."),
    3306: ("MySQL", "Cổng cơ sở dữ liệu MySQL, cần chặn truy cập từ bên ngoài."),
    3389: ("RDP", "Remote Desktop, dễ bị tấn công dò mật khẩu Brute-force."),
    5900: (
        "VNC",
        "Điều khiển màn hình từ xa, cần bật mã hóa hoặc tắt nếu không dùng.",
    ),
}

WATCHLIST_APPS = {
    "teamviewer": "Phần mềm điều khiển từ xa — cần kiểm soát quyền truy cập.",
    "anydesk": "Phần mềm điều khiển từ xa — dễ bị lợi dụng nếu mở tự động.",
    "ultraviewer": (
        "Phần mềm điều khiển từ xa — chỉ giữ lại nếu có nhu cầu hỗ trợ."
    ),
    "radmin": "Công cụ quản trị từ xa — cần giới hạn mật khẩu và IP.",
    "vnc": "Dịch vụ truy cập màn hình từ xa — kiểm tra cấu hình mã hóa.",
    "utorrent": (
        "Ứng dụng chia sẻ P2P/Torrent — tiềm ẩn rủi ro bản quyền & mã độc."
    ),
    "bittorrent": (
        "Ứng dụng chia sẻ P2P/Torrent — không khuyến nghị trên máy doanh nghiệp."
    ),
    "wireshark": "Công cụ bắt gói tin mạng — chỉ dành cho quản trị viên mạng.",
    "nmap": "Công cụ rà quét mạng — kiểm tra mục đích sử dụng hợp lệ.",
}


class SecOpsSOCDashboard(ctk.CTk):

  def __init__(self):
    super().__init__()
    self.title("SECOPS SENTINEL PRO — Cyber Security & System Audit Platform")
    self.geometry("1260x820")
    self.minsize(1120, 750)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    self.db_path = os.path.join(base_dir, "audit_history.db")
    self.init_db()

    self.current_score = 0
    self.current_status = "CHƯA QUÉT"
    self.scan_logs = []
    self.open_ports_data = []
    self.installed_apps_data = []
    self._search_after_id = None

    self.grid_rowconfigure(0, weight=1)
    self.grid_columnconfigure(1, weight=1)

    self.build_sidebar()
    self.build_main_area()
    self.switch_view("dashboard")

  def init_db(self):
    conn = sqlite3.connect(self.db_path)
    cursor = conn.cursor()
    cursor.execute("""
            CREATE TABLE IF NOT EXISTS audits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                asset_name TEXT,
                auditor TEXT,
                score INTEGER,
                open_ports INTEGER,
                risky_ports INTEGER,
                status TEXT
            )
        """)
    cursor.execute("PRAGMA table_info(audits)")
    existing_cols = {row[1] for row in cursor.fetchall()}
    required_cols = {
        "id",
        "timestamp",
        "asset_name",
        "auditor",
        "score",
        "open_ports",
        "risky_ports",
        "status",
    }
    if not required_cols.issubset(existing_cols):
      cursor.execute("DROP TABLE IF EXISTS audits")
      cursor.execute("""
                CREATE TABLE audits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    asset_name TEXT,
                    auditor TEXT,
                    score INTEGER,
                    open_ports INTEGER,
                    risky_ports INTEGER,
                    status TEXT
                )
            """)
    conn.commit()
    conn.close()

  def build_sidebar(self):
    self.sidebar = ctk.CTkFrame(
        self, width=250, corner_radius=0, fg_color=COLOR_SIDEBAR
    )
    self.sidebar.grid(row=0, column=0, sticky="nsew")
    self.sidebar.grid_rowconfigure(8, weight=1)

    brand_box = ctk.CTkFrame(self.sidebar, fg_color="transparent")
    brand_box.grid(row=0, column=0, padx=20, pady=(28, 20), sticky="ew")
    ctk.CTkLabel(
        brand_box,
        text="🛡️ SECOPS SENTINEL",
        font=ctk.CTkFont(size=20, weight="bold"),
        text_color="#f8fafc",
    ).pack(anchor="w")
    ctk.CTkLabel(
        brand_box,
        text="Enterprise Audit & Hardening Suite",
        font=ctk.CTkFont(size=12),
        text_color=COLOR_TEXT_MUTED,
    ).pack(anchor="w", pady=(2, 0))

    ctk.CTkFrame(self.sidebar, height=1, fg_color="#334155").grid(
        row=1, column=0, padx=20, pady=(0, 20), sticky="ew"
    )

    self.nav_buttons = {}
    nav_items = [
        ("dashboard", "📊   Tổng Quan & Kiểm Toán"),
        ("ports", "🌐   Phân Tích Cổng Mạng"),
        ("apps", "📦   Quản Lý Ứng Dụng"),
        ("hardening", "🔐   Chính Sách & Mật Khẩu"),
        ("history", "🕒   Lịch Sử Kiểm Toán"),
    ]
    for idx, (key, label) in enumerate(nav_items, start=2):
      btn = ctk.CTkButton(
          self.sidebar,
          text=label,
          height=42,
          corner_radius=8,
          anchor="w",
          font=ctk.CTkFont(size=14, weight="bold"),
          fg_color="transparent",
          hover_color="#334155",
          command=lambda k=key: self.switch_view(k),
      )
      btn.grid(row=idx, column=0, padx=16, pady=4, sticky="ew")
      self.nav_buttons[key] = btn

    sys_card = ctk.CTkFrame(
        self.sidebar, corner_radius=10, fg_color=COLOR_CARD_INNER
    )
    sys_card.grid(row=9, column=0, padx=16, pady=(10, 20), sticky="ew")
    os_name = f"{platform.system()} {platform.release()}"
    cpu_cores = psutil.cpu_count(logical=True)
    ram_gb = round(psutil.virtual_memory().total / (1024**3), 1)
    ctk.CTkLabel(
        sys_card,
        text="THÔNG SỐ MÁY TRẠM",
        font=ctk.CTkFont(size=11, weight="bold"),
        text_color=COLOR_ACCENT,
    ).pack(anchor="w", padx=12, pady=(10, 4))
    ctk.CTkLabel(
        sys_card,
        text=f"• OS: {os_name}\n• CPU: {cpu_cores} Luồng\n• RAM: {ram_gb} GB",
        justify="left",
        font=ctk.CTkFont(size=12),
        text_color=COLOR_TEXT_MUTED,
    ).pack(anchor="w", padx=12, pady=(0, 10))

  def build_main_area(self):
    self.main_area = ctk.CTkFrame(self, corner_radius=0, fg_color=COLOR_BG_MAIN)
    self.main_area.grid(row=0, column=1, sticky="nsew")
    self.main_area.grid_rowconfigure(1, weight=1)
    self.main_area.grid_columnconfigure(0, weight=1)

    top_bar = ctk.CTkFrame(
        self.main_area, height=70, corner_radius=0, fg_color=COLOR_SIDEBAR
    )
    top_bar.grid(row=0, column=0, sticky="ew")
    self.lbl_page_title = ctk.CTkLabel(
        top_bar,
        text="Bảng Điều Khiển Kiểm Toán Bảo Mật",
        font=ctk.CTkFont(size=20, weight="bold"),
    )
    self.lbl_page_title.pack(side="left", padx=25, pady=18)

    self.btn_scan = ctk.CTkButton(
        top_bar,
        text="⚡ QUÉT TOÀN HỆ THỐNG",
        height=40,
        corner_radius=8,
        fg_color=COLOR_ACCENT,
        hover_color=COLOR_ACCENT_HOVER,
        font=ctk.CTkFont(size=13, weight="bold"),
        command=self.start_scan_thread,
    )
    self.btn_scan.pack(side="right", padx=25, pady=15)

    self.view_container = ctk.CTkFrame(self.main_area, fg_color="transparent")
    self.view_container.grid(row=1, column=0, padx=22, pady=18, sticky="nsew")
    self.view_container.grid_rowconfigure(0, weight=1)
    self.view_container.grid_columnconfigure(0, weight=1)

    self.views = {
        "dashboard": ctk.CTkFrame(self.view_container, fg_color="transparent"),
        "ports": ctk.CTkFrame(self.view_container, fg_color="transparent"),
        "apps": ctk.CTkFrame(self.view_container, fg_color="transparent"),
        "hardening": ctk.CTkFrame(self.view_container, fg_color="transparent"),
        "history": ctk.CTkFrame(self.view_container, fg_color="transparent"),
    }
    self.setup_dashboard_view()
    self.setup_ports_view()
    self.setup_apps_view()
    self.setup_hardening_view()
    self.setup_history_view()

  def switch_view(self, view_name):
    titles = {
        "dashboard": "Bảng Điều Khiển Kiểm Toán Bảo Mật",
        "ports": "Phân Tích Mạng & Cổng Dịch Vụ",
        "apps": "Quản Lý & Kiểm Kê Ứng Dụng Cài Đặt",
        "hardening": "Chính Sách Mật Khẩu & Gia Cố Hệ Thống",
        "history": "Kho Lưu Trữ Lịch Sử Kiểm Toán",
    }
    self.lbl_page_title.configure(text=titles[view_name])
    for k, frame in self.views.items():
      if k == view_name:
        frame.grid(row=0, column=0, sticky="nsew")
        self.nav_buttons[k].configure(fg_color=COLOR_ACCENT)
      else:
        frame.grid_forget()
        self.nav_buttons[k].configure(fg_color="transparent")

    if view_name == "ports":
      self.render_ports_list()
    elif view_name == "apps":
      if not self.installed_apps_data:
        self.refresh_installed_apps()
      else:
        self.render_apps_list()
    elif view_name == "hardening":
      self.read_windows_password_policy()
    elif view_name == "history":
      self.load_history()

  # ================= VIEW 1: DASHBOARD =================
  def setup_dashboard_view(self):
    dash = self.views["dashboard"]
    dash.grid_rowconfigure(2, weight=1)
    dash.grid_columnconfigure(0, weight=3)
    dash.grid_columnconfigure(1, weight=2)

    kpi_row = ctk.CTkFrame(dash, fg_color="transparent")
    kpi_row.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 14))
    for i in range(4):
      kpi_row.grid_columnconfigure(i, weight=1)

    self.kpi_score = self.create_kpi_card(
        kpi_row, 0, "ĐIỂM AN TOÀN", "0 / 100", "Chưa đánh giá", COLOR_ACCENT
    )
    self.kpi_passed = self.create_kpi_card(
        kpi_row, 1, "TIÊU CHUẨN ĐẠT", "0 / 10", "Hạng mục tuân thủ", COLOR_SUCCESS
    )
    self.kpi_open_ports = self.create_kpi_card(
        kpi_row, 2, "CỔNG ĐANG MỞ", "0", "Toàn bộ cổng TCP", "#38bdf8"
    )
    self.kpi_risky_ports = self.create_kpi_card(
        kpi_row, 3, "CỔNG RỦI RO CAO", "0", "Cần kiểm tra tường lửa", COLOR_DANGER
    )

    meta_bar = ctk.CTkFrame(dash, corner_radius=10, fg_color=COLOR_CARD)
    meta_bar.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 14))

    ctk.CTkLabel(
        meta_bar, text="Thiết bị:", font=ctk.CTkFont(weight="bold")
    ).pack(side="left", padx=(16, 6), pady=12)
    self.entry_asset = ctk.CTkEntry(
        meta_bar, width=165, fg_color=COLOR_CARD_INNER
    )
    self.entry_asset.insert(0, os.environ.get("COMPUTERNAME", "WORKSTATION"))
    self.entry_asset.pack(side="left", padx=4, pady=12)

    ctk.CTkLabel(
        meta_bar, text="Chuyên viên:", font=ctk.CTkFont(weight="bold")
    ).pack(side="left", padx=(14, 6), pady=12)
    self.entry_auditor = ctk.CTkEntry(
        meta_bar, width=155, fg_color=COLOR_CARD_INNER
    )
    self.entry_auditor.insert(0, os.environ.get("USERNAME", "SecOps_Admin"))
    self.entry_auditor.pack(side="left", padx=4, pady=12)

    ctk.CTkButton(
        meta_bar,
        text="📄 Xuất Báo Cáo Ổ D",
        width=165,
        height=34,
        fg_color="#0284c7",
        hover_color="#0369a1",
        font=ctk.CTkFont(weight="bold"),
        command=self.export_report,
    ).pack(side="right", padx=(6, 16), pady=12)
    ctk.CTkButton(
        meta_bar,
        text="💾 Lưu Lịch Sử",
        width=135,
        height=34,
        fg_color=COLOR_SUCCESS,
        hover_color="#059669",
        font=ctk.CTkFont(weight="bold"),
        command=lambda: self.save_to_history(silent=False),
    ).pack(side="right", padx=6, pady=12)

    left_panel = ctk.CTkFrame(dash, corner_radius=12, fg_color=COLOR_CARD)
    left_panel.grid(row=2, column=0, sticky="nsew", padx=(0, 10))
    ctk.CTkLabel(
        left_panel,
        text="📋 Danh Mục 10 Tiêu Chuẩn Tuân Thủ (ISO 27001 / CIS Controls)",
        font=ctk.CTkFont(size=15, weight="bold"),
    ).pack(anchor="w", padx=18, pady=(15, 8))

    self.progress_bar = ctk.CTkProgressBar(
        left_panel, height=10, progress_color=COLOR_ACCENT
    )
    self.progress_bar.pack(fill="x", padx=18, pady=(0, 12))
    self.progress_bar.set(0)

    self.criteria_scroll = ctk.CTkScrollableFrame(
        left_panel, fg_color="transparent"
    )
    self.criteria_scroll.pack(fill="both", expand=True, padx=10, pady=(0, 12))

    self.check_items = []
    criteria_defs = [
        ("1. Tường lửa Windows Firewall đang bật (All Profiles)", 12),
        ("2. Trình bảo vệ Antivirus / Windows Defender hoạt động", 12),
        ("3. Chính sách độ dài mật khẩu tối thiểu (>= 8 ký tự)", 10),
        ("4. Chính sách khóa tài khoản chống dò mật khẩu (Lockout)", 10),
        ("5. Cơ chế chống leo thang đặc quyền UAC (EnableLUA)", 10),
        ("6. Tài khoản khách (Guest Account) đã bị vô hiệu hóa", 10),
        ("7. Kiểm soát cổng mạng: Không lộ dịch vụ rủi ro cao", 10),
        ("8. Vô hiệu hóa giao thức chia sẻ cũ SMBv1 (Chống Ransomware)", 10),
        ("9. Mã hóa ổ đĩa dữ liệu BitLocker đang kích hoạt", 8),
        ("10. Dịch vụ cập nhật vá lỗi Windows Update sẵn sàng", 8),
    ]
    for title, weight in criteria_defs:
      row_card = ctk.CTkFrame(
          self.criteria_scroll, corner_radius=8, fg_color=COLOR_CARD_INNER
      )
      row_card.pack(fill="x", padx=6, pady=4)
      var = ctk.IntVar(value=0)
      ctk.CTkCheckBox(
          row_card,
          text=f"{title} ({weight}%)",
          variable=var,
          font=ctk.CTkFont(size=13),
          command=self.recalculate_dashboard,
      ).pack(side="left", padx=12, pady=8)
      badge = ctk.CTkLabel(
          row_card,
          text="CHỜ QUÉT",
          width=78,
          height=24,
          corner_radius=6,
          fg_color="#334155",
          text_color="#cbd5e1",
          font=ctk.CTkFont(size=11, weight="bold"),
      )
      badge.pack(side="right", padx=12, pady=8)
      self.check_items.append((var, weight, title, badge))

    right_panel = ctk.CTkFrame(dash, corner_radius=12, fg_color=COLOR_CARD)
    right_panel.grid(row=2, column=1, sticky="nsew", padx=(10, 0))
    term_header = ctk.CTkFrame(right_panel, fg_color="transparent")
    term_header.pack(fill="x", padx=16, pady=(15, 8))
    ctk.CTkLabel(
        term_header,
        text="💻 Live Security Terminal",
        font=ctk.CTkFont(size=15, weight="bold"),
    ).pack(side="left")
    ctk.CTkButton(
        term_header,
        text="Quản lý ứng dụng →",
        width=140,
        height=26,
        font=ctk.CTkFont(size=12),
        fg_color="#334155",
        hover_color="#475569",
        command=lambda: self.switch_view("apps"),
    ).pack(side="right")

    self.log_box = ctk.CTkTextbox(
        right_panel,
        fg_color="#090d16",
        text_color="#e2e8f0",
        font=ctk.CTkFont(family="Consolas", size=12),
    )
    self.log_box.pack(fill="both", expand=True, padx=16, pady=(0, 16))
    self.log_box.insert(
        "end",
        "[SYSTEM] Sẵn sàng kiểm toán 10 tiêu chuẩn bảo mật.\n[SYSTEM] Nhấn 'QUÉT TOÀN HỆ THỐNG' để bắt đầu.\n",
    )
    self.log_box.configure(state="disabled")

  def create_kpi_card(self, parent, col, title, value, subtitle, accent_color):
    card = ctk.CTkFrame(parent, corner_radius=12, fg_color=COLOR_CARD)
    card.grid(
        row=0,
        column=col,
        sticky="ew",
        padx=(0 if col == 0 else 8, 0 if col == 3 else 8),
    )
    ctk.CTkLabel(
        card,
        text=title,
        font=ctk.CTkFont(size=11, weight="bold"),
        text_color=COLOR_TEXT_MUTED,
    ).pack(anchor="w", padx=16, pady=(14, 2))
    lbl_val = ctk.CTkLabel(
        card,
        text=value,
        font=ctk.CTkFont(size=24, weight="bold"),
        text_color=accent_color,
    )
    lbl_val.pack(anchor="w", padx=16, pady=2)
    lbl_sub = ctk.CTkLabel(
        card,
        text=subtitle,
        font=ctk.CTkFont(size=12),
        text_color=COLOR_TEXT_MUTED,
    )
    lbl_sub.pack(anchor="w", padx=16, pady=(0, 14))
    return (lbl_val, lbl_sub)

  # ================= VIEW 2: CỔNG MẠNG =================
  def setup_ports_view(self):
    p_view = self.views["ports"]
    p_view.grid_rowconfigure(1, weight=1)
    p_view.grid_columnconfigure(0, weight=1)

    filter_bar = ctk.CTkFrame(p_view, corner_radius=10, fg_color=COLOR_CARD)
    filter_bar.grid(row=0, column=0, sticky="ew", pady=(0, 12))
    self.lbl_ports_summary = ctk.CTkLabel(
        filter_bar,
        text="Chưa có dữ liệu quét cổng. Hãy bấm nút Quét ở góc trên.",
        font=ctk.CTkFont(size=14, weight="bold"),
    )
    self.lbl_ports_summary.pack(side="left", padx=18, pady=14)

    self.port_filter_var = ctk.StringVar(value="Tất cả cổng mở")
    ctk.CTkSegmentedButton(
        filter_bar,
        values=["Tất cả cổng mở", "Chỉ cổng rủi ro cao"],
        variable=self.port_filter_var,
        command=lambda _: self.render_ports_list(),
    ).pack(side="right", padx=18, pady=12)

    self.ports_scroll = ctk.CTkScrollableFrame(
        p_view, corner_radius=12, fg_color=COLOR_CARD
    )
    self.ports_scroll.grid(row=1, column=0, sticky="nsew")

  def render_ports_list(self):
    for w in self.ports_scroll.winfo_children():
      w.destroy()
    if not self.open_ports_data:
      ctk.CTkLabel(
          self.ports_scroll,
          text="Chưa có dữ liệu. Nhấn 'QUÉT TOÀN HỆ THỐNG' để kiểm tra các cổng mạng.",
          text_color=COLOR_TEXT_MUTED,
          font=ctk.CTkFont(size=14),
      ).pack(pady=40)
      return

    only_risky = self.port_filter_var.get() == "Chỉ cổng rủi ro cao"
    filtered = [
        p for p in self.open_ports_data if (not only_risky or p["is_risky"])
    ]
    risky_count = sum(1 for p in self.open_ports_data if p["is_risky"])
    self.lbl_ports_summary.configure(
        text=f"Toàn bộ cổng TCP  •  Đang mở: {len(self.open_ports_data)} cổng  •  Rủi ro cao: {risky_count} cổng"
    )

    for item in filtered:
      card = ctk.CTkFrame(
          self.ports_scroll, corner_radius=8, fg_color=COLOR_CARD_INNER
      )
      card.pack(fill="x", padx=12, pady=5)
      badge_color = COLOR_DANGER if item["is_risky"] else COLOR_SUCCESS
      badge_text = "RỦI RO CAO" if item["is_risky"] else "AN TOÀN"
      ctk.CTkLabel(
          card,
          text=f"PORT {item['port']}",
          width=95,
          height=28,
          corner_radius=6,
          fg_color=badge_color,
          text_color="#ffffff",
          font=ctk.CTkFont(size=12, weight="bold"),
      ).pack(side="left", padx=14, pady=12)
      info_text = f"Dịch vụ: {item['service']}   |   Tiến trình: {item['process']}   |   Địa chỉ lắng nghe: {item['ip']}\nĐánh giá ({badge_text}): {item['desc']}"
      ctk.CTkLabel(
          card,
          text=info_text,
          justify="left",
          font=ctk.CTkFont(size=13),
          text_color="#e2e8f0",
      ).pack(side="left", padx=8, pady=10)

  # ================= VIEW 3: QUẢN LÝ ỨNG DỤNG =================
  def setup_apps_view(self):
    a_view = self.views["apps"]
    a_view.grid_rowconfigure(2, weight=1)
    a_view.grid_columnconfigure(0, weight=1)

    top_ctrl = ctk.CTkFrame(a_view, corner_radius=10, fg_color=COLOR_CARD)
    top_ctrl.grid(row=0, column=0, sticky="ew", pady=(0, 10))
    self.lbl_apps_summary = ctk.CTkLabel(
        top_ctrl,
        text="Đang chờ quét danh sách phần mềm đã cài đặt trên máy...",
        font=ctk.CTkFont(size=14, weight="bold"),
    )
    self.lbl_apps_summary.pack(side="left", padx=18, pady=14)

    ctk.CTkButton(
        top_ctrl,
        text="📄 Xuất Danh Sách",
        width=145,
        height=32,
        fg_color="#0284c7",
        hover_color="#0369a1",
        font=ctk.CTkFont(size=12, weight="bold"),
        command=self.export_apps_inventory,
    ).pack(side="right", padx=(6, 18), pady=12)
    ctk.CTkButton(
        top_ctrl,
        text="🔄 Làm Mới Danh Sách",
        width=165,
        height=32,
        fg_color=COLOR_ACCENT,
        hover_color=COLOR_ACCENT_HOVER,
        font=ctk.CTkFont(size=12, weight="bold"),
        command=self.refresh_installed_apps,
    ).pack(side="right", padx=6, pady=12)

    search_bar = ctk.CTkFrame(a_view, corner_radius=10, fg_color=COLOR_CARD)
    search_bar.grid(row=1, column=0, sticky="ew", pady=(0, 12))
    ctk.CTkLabel(
        search_bar,
        text="🔍 Tìm kiếm:",
        font=ctk.CTkFont(size=13, weight="bold"),
    ).pack(side="left", padx=(18, 8), pady=12)

    self.entry_app_search = ctk.CTkEntry(
        search_bar,
        width=320,
        height=34,
        placeholder_text="Nhập tên phần mềm hoặc nhà phát hành...",
        fg_color=COLOR_CARD_INNER,
    )
    self.entry_app_search.pack(side="left", padx=4, pady=12)
    self.entry_app_search.bind("<KeyRelease>", self.on_app_search_change)

    self.app_filter_var = ctk.StringVar(value="Tất cả ứng dụng")
    ctk.CTkSegmentedButton(
        search_bar,
        values=["Tất cả ứng dụng", "Cần kiểm tra rủi ro", "Có thể gỡ cài đặt"],
        variable=self.app_filter_var,
        command=lambda _: self.render_apps_list(),
    ).pack(side="right", padx=18, pady=12)

    self.apps_scroll = ctk.CTkScrollableFrame(
        a_view, corner_radius=12, fg_color=COLOR_CARD
    )
    self.apps_scroll.grid(row=2, column=0, sticky="nsew")

  def on_app_search_change(self, _=None):
    if self._search_after_id is not None:
      self.after_cancel(self._search_after_id)
    self._search_after_id = self.after(250, self.render_apps_list)

  def refresh_installed_apps(self):
    self.lbl_apps_summary.configure(
        text="⏳ Đang đọc danh sách phần mềm từ Windows Registry..."
    )
    threading.Thread(target=self._scan_registry_apps, daemon=True).start()

  def _scan_registry_apps(self):
    reg_locations = [
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            winreg.HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
    ]
    apps_dict = {}
    for hive, subkey_path in reg_locations:
      try:
        with winreg.OpenKey(hive, subkey_path) as key:
          num_subkeys = winreg.QueryInfoKey(key)[0]
          for i in range(num_subkeys):
            try:
              sub_name = winreg.EnumKey(key, i)
              with winreg.OpenKey(key, sub_name) as app_key:
                try:
                  display_name, _ = winreg.QueryValueEx(app_key, "DisplayName")
                except FileNotFoundError:
                  continue
                display_name = str(display_name).strip()
                if not display_name:
                  continue
                try:
                  sys_comp, _ = winreg.QueryValueEx(app_key, "SystemComponent")
                  if sys_comp == 1:
                    continue
                except FileNotFoundError:
                  pass
                try:
                  version, _ = winreg.QueryValueEx(app_key, "DisplayVersion")
                except FileNotFoundError:
                  version = "Không rõ"
                try:
                  publisher, _ = winreg.QueryValueEx(app_key, "Publisher")
                except FileNotFoundError:
                  publisher = "Không rõ nhà phát hành"
                try:
                  install_date, _ = winreg.QueryValueEx(app_key, "InstallDate")
                  if len(str(install_date)) == 8 and str(install_date).isdigit():
                    d = str(install_date)
                    install_date = f"{d[6:8]}/{d[4:6]}/{d[0:4]}"
                except FileNotFoundError:
                  install_date = "N/A"
                uninstall_cmd = ""
                try:
                  uninstall_cmd, _ = winreg.QueryValueEx(
                      app_key, "UninstallString"
                  )
                except FileNotFoundError:
                  pass

                risk_note = ""
                lower_name = display_name.lower()
                for kw, note in WATCHLIST_APPS.items():
                  if kw in lower_name:
                    risk_note = note
                    break
                if lower_name not in apps_dict:
                  apps_dict[lower_name] = {
                      "name": display_name,
                      "version": str(version),
                      "publisher": str(publisher),
                      "install_date": str(install_date),
                      "uninstall_cmd": str(uninstall_cmd).strip(),
                      "is_watchlist": bool(risk_note),
                      "risk_note": risk_note,
                  }
            except Exception:
              continue
      except Exception:
        continue

    self.installed_apps_data = sorted(
        apps_dict.values(),
        key=lambda x: (not x["is_watchlist"], x["name"].lower()),
    )
    self.after(0, self.render_apps_list)

  def render_apps_list(self):
    for w in self.apps_scroll.winfo_children():
      w.destroy()

    total_all = len(self.installed_apps_data)
    watchlist_cnt = sum(1 for a in self.installed_apps_data if a["is_watchlist"])
    if total_all == 0:
      self.lbl_apps_summary.configure(
          text="Không tìm thấy ứng dụng nào. Nhấn 'Làm Mới Danh Sách' để thử lại."
      )
      return

    query = self.entry_app_search.get().strip().lower()
    mode = self.app_filter_var.get()
    filtered = []
    for app in self.installed_apps_data:
      if mode == "Cần kiểm tra rủi ro" and not app["is_watchlist"]:
        continue
      if mode == "Có thể gỡ cài đặt" and not app["uninstall_cmd"]:
        continue
      if (
          query
          and query not in app["name"].lower()
          and query not in app["publisher"].lower()
      ):
        continue
      filtered.append(app)

    shown_items = filtered[:100]
    self.lbl_apps_summary.configure(
        text=f"Tổng ứng dụng: {total_all}   •   Cần kiểm tra: {watchlist_cnt}   •   Hiển thị: {len(shown_items)}/{len(filtered)} kết quả"
    )

    if not shown_items:
      ctk.CTkLabel(
          self.apps_scroll,
          text="Không có ứng dụng nào khớp với từ khóa tìm kiếm.",
          text_color=COLOR_TEXT_MUTED,
          font=ctk.CTkFont(size=14),
      ).pack(pady=40)
      return

    for item in shown_items:
      card = ctk.CTkFrame(
          self.apps_scroll, corner_radius=8, fg_color=COLOR_CARD_INNER
      )
      card.pack(fill="x", padx=10, pady=5)
      badge_bg = COLOR_WARNING if item["is_watchlist"] else "#334155"
      badge_txt = "KIỂM TRA" if item["is_watchlist"] else "HỢP LỆ"
      ctk.CTkLabel(
          card,
          text=badge_txt,
          width=82,
          height=28,
          corner_radius=6,
          fg_color=badge_bg,
          text_color="#ffffff",
          font=ctk.CTkFont(size=11, weight="bold"),
      ).pack(side="left", padx=(14, 10), pady=12)

      info_box = ctk.CTkFrame(card, fg_color="transparent")
      info_box.pack(side="left", fill="both", expand=True, padx=4, pady=8)
      ctk.CTkLabel(
          info_box,
          text=f"{item['name']}   (v{item['version']})",
          font=ctk.CTkFont(size=13, weight="bold"),
          text_color="#f8fafc",
      ).pack(anchor="w")

      sub_line = f"Nhà phát hành: {item['publisher']}   |   Ngày cài: {item['install_date']}"
      if item["is_watchlist"]:
        sub_line += f"\n⚠ Lưu ý: {item['risk_note']}"
      ctk.CTkLabel(
          info_box,
          text=sub_line,
          justify="left",
          font=ctk.CTkFont(size=12),
          text_color=COLOR_WARNING if item["is_watchlist"] else COLOR_TEXT_MUTED,
      ).pack(anchor="w", pady=(2, 0))

      if item["uninstall_cmd"]:
        ctk.CTkButton(
            card,
            text="🗑️ Gỡ cài đặt",
            width=110,
            height=32,
            fg_color=COLOR_DANGER,
            hover_color="#dc2626",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=lambda app_info=item: self.uninstall_application(app_info),
        ).pack(side="right", padx=14, pady=12)
      else:
        ctk.CTkLabel(
            card,
            text="Thành phần hệ thống",
            font=ctk.CTkFont(size=11),
            text_color=COLOR_TEXT_MUTED,
        ).pack(side="right", padx=16, pady=12)

  def uninstall_application(self, app_info):
    name = app_info["name"]
    cmd = app_info["uninstall_cmd"]
    if not messagebox.askyesno(
        "Xác Nhận Gỡ Cài Đặt Ứng Dụng",
        f"Bạn có chắc chắn muốn khởi chạy trình gỡ cài đặt cho:\n\n• Ứng dụng: {name}\n• Nhà phát hành: {app_info['publisher']}\n\nSau khi gỡ xong, hãy bấm 'Làm Mới Danh Sách' để cập nhật.",
    ):
      return
    try:
      if "msiexec" in cmd.lower() and "/i" in cmd.lower():
        cmd = re.sub(r"/i", "/X", cmd, flags=re.IGNORECASE)
      subprocess.Popen(cmd, shell=True)
    except Exception as e:
      messagebox.showerror(
          "Lỗi Gỡ Cài Đặt",
          f"Không thể khởi chạy trình gỡ cài đặt cho {name}:\n{e}",
      )

  def export_apps_inventory(self):
    if not self.installed_apps_data:
      messagebox.showinfo(
          "Chưa Có Dữ Liệu", "Vui lòng đợi hệ thống quét xong danh sách ứng dụng."
      )
      return
    asset = self.entry_asset.get().strip() or "UNKNOWN"
    report_dir = (
        "D:\\BaoCao_BaoMat" if os.path.exists("D:\\") else "BaoCao_BaoMat"
    )
    os.makedirs(report_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = os.path.join(report_dir, f"Software_Inventory_{asset}_{ts}.txt")
    now_str = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    with open(file_path, "w", encoding="utf-8") as f:
      f.write(
          "=" * 78
          + "\n         BÁO CÁO KIỂM KÊ PHẦN MỀM & ỨNG DỤNG CÀI ĐẶT TRÊN MÁY\n"
          + "=" * 78
          + "\n"
      )
      f.write(
          f"Thời gian kiểm kê : {now_str}\nThiết bị          : {asset}\nTổng số ứng dụng  : {len(self.installed_apps_data)}\n"
          + "-" * 78
          + "\n"
      )
      for idx, app in enumerate(self.installed_apps_data, start=1):
        flag = "[CẦN KIỂM TRA] " if app["is_watchlist"] else "[HỢP LỆ]       "
        f.write(
            f"{idx:03d}. {flag}{app['name']} (v{app['version']}) - {app['publisher']}\n"
        )
        if app["is_watchlist"]:
          f.write(f"     -> Cảnh báo: {app['risk_note']}\n")
      f.write("=" * 78 + "\n")
    messagebox.showinfo(
        "Xuất Danh Sách Thành Công",
        f"Đã lưu danh sách {len(self.installed_apps_data)} ứng dụng tại:\n{file_path}",
    )

  # ================= VIEW 4: CHÍNH SÁCH & GIA CỐ =================
  def setup_hardening_view(self):
    h_view = self.views["hardening"]
    h_view.grid_rowconfigure(1, weight=1)
    h_view.grid_columnconfigure(0, weight=1)
    h_view.grid_columnconfigure(1, weight=1)

    banner = ctk.CTkFrame(h_view, corner_radius=10, fg_color=COLOR_CARD)
    banner.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 14))
    ctk.CTkLabel(
        banner,
        text="🔐 Trung Tâm Kiểm Tra Chính Sách Mật Khẩu & Gia Cố (Hardening)",
        font=ctk.CTkFont(size=15, weight="bold"),
    ).pack(side="left", padx=18, pady=14)
    ctk.CTkButton(
        banner,
        text="🔄 Đọc Lại Chính Sách Windows",
        width=200,
        height=32,
        fg_color=COLOR_ACCENT,
        hover_color=COLOR_ACCENT_HOVER,
        command=self.read_windows_password_policy,
    ).pack(side="right", padx=18, pady=12)

    left_card = ctk.CTkFrame(h_view, corner_radius=12, fg_color=COLOR_CARD)
    left_card.grid(row=1, column=0, sticky="nsew", padx=(0, 10))
    ctk.CTkLabel(
        left_card,
        text="1. Chính Sách Mật Khẩu Hiện Tại Trên Máy (net accounts)",
        font=ctk.CTkFont(size=14, weight="bold"),
        text_color="#38bdf8",
    ).pack(anchor="w", padx=18, pady=(16, 8))
    self.policy_textbox = ctk.CTkTextbox(
        left_card,
        height=175,
        fg_color=COLOR_CARD_INNER,
        font=ctk.CTkFont(family="Consolas", size=12),
    )
    self.policy_textbox.pack(fill="x", padx=18, pady=(0, 16))

    ctk.CTkLabel(
        left_card,
        text="2. Công Cụ Đánh Giá Độ Mạnh Mật Khẩu (Password Strength Tester)",
        font=ctk.CTkFont(size=14, weight="bold"),
        text_color="#38bdf8",
    ).pack(anchor="w", padx=18, pady=(4, 8))
    self.entry_test_pw = ctk.CTkEntry(
        left_card,
        placeholder_text="Nhập mật khẩu mẫu để kiểm tra độ an toàn...",
        height=38,
        fg_color=COLOR_CARD_INNER,
    )
    self.entry_test_pw.pack(fill="x", padx=18, pady=(0, 8))
    self.entry_test_pw.bind("<KeyRelease>", self.evaluate_password_strength)

    self.pw_strength_bar = ctk.CTkProgressBar(left_card, height=10)
    self.pw_strength_bar.pack(fill="x", padx=18, pady=(0, 8))
    self.pw_strength_bar.set(0)
    self.lbl_pw_feedback = ctk.CTkLabel(
        left_card,
        text="• Yêu cầu chuẩn ISO 27001: Tối thiểu 12 ký tự, gồm chữ HOA, chữ thường, số và ký tự đặc biệt.",
        justify="left",
        wraplength=460,
        font=ctk.CTkFont(size=13),
        text_color=COLOR_TEXT_MUTED,
    )
    self.lbl_pw_feedback.pack(anchor="w", padx=18, pady=(0, 16))

    right_card = ctk.CTkFrame(h_view, corner_radius=12, fg_color=COLOR_CARD)
    right_card.grid(row=1, column=1, sticky="nsew", padx=(10, 0))
    ctk.CTkLabel(
        right_card,
        text="3. Khắc Phục Nhanh & Gia Cố Bảo Mật (Yêu Cầu Quyền Admin)",
        font=ctk.CTkFont(size=14, weight="bold"),
        text_color=COLOR_WARNING,
    ).pack(anchor="w", padx=18, pady=(16, 6))
    ctk.CTkLabel(
        right_card,
        text="Áp dụng trực tiếp các chính sách an toàn chuẩn doanh nghiệp lên hệ điều hành Windows:",
        wraplength=460,
        justify="left",
        font=ctk.CTkFont(size=12),
        text_color=COLOR_TEXT_MUTED,
    ).pack(anchor="w", padx=18, pady=(0, 12))

    hardening_actions = [
        (
            "🔑 Áp đặt Mật khẩu mạnh (Tối thiểu 12 ký tự)",
            "Cấu hình minpwlen:12 trên toàn hệ thống Windows.",
            "net accounts /minpwlen:12",
        ),
        (
            "🛡️ Bật Khóa tài khoản chống dò mật khẩu (Brute-force)",
            "Tự động khóa 15 phút nếu nhập sai mật khẩu quá 5 lần.",
            "net accounts /lockoutthreshold:5 /lockoutduration:15",
        ),
        (
            "🔥 Bật Tường lửa Windows Firewall (Tất cả Profile)",
            "Kích hoạt lớp bảo vệ tường lửa cho Domain, Private và Public.",
            "netsh advfirewall set allprofiles state on",
        ),
        (
            "🚫 Khóa tài khoản khách (Disable Guest Account)",
            "Ngăn chặn truy cập ẩn danh trái phép vào máy tính.",
            "net user Guest /active:no",
        ),
    ]
    for btn_title, desc, cmd in hardening_actions:
      box = ctk.CTkFrame(
          right_card, corner_radius=8, fg_color=COLOR_CARD_INNER
      )
      box.pack(fill="x", padx=18, pady=6)
      info_col = ctk.CTkFrame(box, fg_color="transparent")
      info_col.pack(side="left", fill="both", expand=True, padx=12, pady=10)
      ctk.CTkLabel(
          info_col, text=btn_title, font=ctk.CTkFont(size=13, weight="bold")
      ).pack(anchor="w")
      ctk.CTkLabel(
          info_col,
          text=desc,
          font=ctk.CTkFont(size=12),
          text_color=COLOR_TEXT_MUTED,
      ).pack(anchor="w")
      ctk.CTkButton(
          box,
          text="Áp Dụng",
          width=85,
          height=32,
          fg_color=COLOR_SUCCESS,
          hover_color="#059669",
          font=ctk.CTkFont(size=12, weight="bold"),
          command=lambda c=cmd, t=btn_title: self.apply_hardening_cmd(c, t),
      ).pack(side="right", padx=12, pady=10)

  def read_windows_password_policy(self):
    self.policy_textbox.configure(state="normal")
    self.policy_textbox.delete("1.0", "end")
    try:
      self.policy_textbox.insert("end", self.run_cmd("net accounts").strip())
    except Exception as e:
      self.policy_textbox.insert("end", f"Không thể truy xuất chính sách: {e}")
    self.policy_textbox.configure(state="disabled")

  def evaluate_password_strength(self, _=None):
    pw = self.entry_test_pw.get()
    if not pw:
      self.pw_strength_bar.set(0)
      self.lbl_pw_feedback.configure(
          text="• Nhập mật khẩu bất kỳ vào ô trên để phân tích độ phức tạp.",
          text_color=COLOR_TEXT_MUTED,
      )
      return
    score, tips = 0, []
    if len(pw) >= 12:
      score += 30
    else:
      tips.append("Cần ít nhất 12 ký tự")
    if re.search(r"[A-Z]", pw):
      score += 20
    else:
      tips.append("Thiếu chữ IN HOA")
    if re.search(r"[a-z]", pw):
      score += 15
    else:
      tips.append("Thiếu chữ thường")
    if re.search(r"[0-9]", pw):
      score += 15
    else:
      tips.append("Thiếu chữ số (0-9)")
    if re.search(r"[^A-Za-z0-9]", pw):
      score += 20
    else:
      tips.append("Thiếu ký tự đặc biệt (!@#$...)")

    self.pw_strength_bar.set(score / 100)
    if score >= 85:
      self.pw_strength_bar.configure(progress_color=COLOR_SUCCESS)
      self.lbl_pw_feedback.configure(
          text=f"✔ ĐẠT CHUẨN MẬT KHẨU MẠNH ({score}/100 điểm) — Đủ điều kiện bảo vệ tài khoản Quản trị.",
          text_color=COLOR_SUCCESS,
      )
    elif score >= 55:
      self.pw_strength_bar.configure(progress_color=COLOR_WARNING)
      self.lbl_pw_feedback.configure(
          text=f"⚠ MỨC TRUNG BÌNH ({score}/100 điểm) — Khắc phục: {', '.join(tips)}.",
          text_color=COLOR_WARNING,
      )
    else:
      self.pw_strength_bar.configure(progress_color=COLOR_DANGER)
      self.lbl_pw_feedback.configure(
          text=f"✘ MẬT KHẨU YẾU ({score}/100 điểm) — Rủi ro cao! {', '.join(tips)}.",
          text_color=COLOR_DANGER,
      )

  def apply_hardening_cmd(self, cmd, title):
    try:
      subprocess.check_output(
          cmd,
          shell=True,
          text=True,
          stderr=subprocess.STDOUT,
          creationflags=NO_WINDOW,
      )
      self.read_windows_password_policy()
      messagebox.showinfo(
          "Gia Cố Thành Công",
          f"Đã áp dụng cấu hình:\n{title}\n\nHãy quay lại tab Tổng Quan và bấm Quét lại để cập nhật điểm số!",
      )
    except subprocess.CalledProcessError:
      messagebox.showwarning(
          "Cần Quyền Quản Trị (Administrator)",
          "Windows từ chối thay đổi chính sách hệ thống.\n\nVui lòng chạy ứng dụng bằng chuột phải -> 'Run as administrator' để sử dụng tính năng gia cố tự động.",
      )

  # ================= VIEW 5: LỊCH SỬ =================
  def setup_history_view(self):
    h_view = self.views["history"]
    h_view.grid_rowconfigure(1, weight=1)
    h_view.grid_columnconfigure(0, weight=1)

    bar = ctk.CTkFrame(h_view, corner_radius=10, fg_color=COLOR_CARD)
    bar.grid(row=0, column=0, sticky="ew", pady=(0, 12))
    ctk.CTkLabel(
        bar,
        text="Lịch Sử Các Đợt Kiểm Toán Đã Lưu (Tự động & Thủ công)",
        font=ctk.CTkFont(size=15, weight="bold"),
    ).pack(side="left", padx=18, pady=14)

    ctk.CTkButton(
        bar,
        text="🗑️ Xóa Toàn Bộ",
        fg_color=COLOR_DANGER,
        hover_color="#dc2626",
        width=135,
        command=self.clear_history,
    ).pack(side="right", padx=(6, 18), pady=12)
    ctk.CTkButton(
        bar,
        text="🔄 Làm Mới",
        fg_color=COLOR_ACCENT,
        hover_color=COLOR_ACCENT_HOVER,
        width=115,
        command=self.load_history,
    ).pack(side="right", padx=6, pady=12)

    self.history_scroll = ctk.CTkScrollableFrame(
        h_view, corner_radius=12, fg_color=COLOR_CARD
    )
    self.history_scroll.grid(row=1, column=0, sticky="nsew")

  # ================= LOGIC QUÉT 10 TIÊU CHÍ =================
  def log(self, msg):
    self.scan_logs.append(msg)
    self.after(0, self._append_log, msg)

  def _append_log(self, msg):
    self.log_box.configure(state="normal")
    self.log_box.insert("end", msg + "\n")
    self.log_box.see("end")
    self.log_box.configure(state="disabled")

  def start_scan_thread(self):
    self.btn_scan.configure(state="disabled", text="⏳ ĐANG QUÉT HỆ THỐNG...")
    self.scan_logs = []
    self.log_box.configure(state="normal")
    self.log_box.delete("1.0", "end")
    self.log_box.configure(state="disabled")
    threading.Thread(target=self.execute_full_audit, daemon=True).start()

  def run_cmd(self, cmd):
    return subprocess.check_output(
        cmd,
        shell=True,
        text=True,
        stderr=subprocess.DEVNULL,
        creationflags=NO_WINDOW,
    )

  def update_item_status(self, idx, passed):
    def _ui():
      var, _, _, badge = self.check_items[idx]
      var.set(1 if passed else 0)
      badge.configure(
          text="ĐẠT (PASS)" if passed else "LỖI (FAIL)",
          fg_color=COLOR_SUCCESS if passed else COLOR_DANGER,
          text_color="#ffffff",
      )

    self.after(0, _ui)

  def execute_full_audit(self):
    now = datetime.now().strftime("%H:%M:%S")
    self.log(
        f"[{now}] Khởi động kiểm toán 10 tiêu chuẩn trên {self.entry_asset.get()}..."
    )

    self.log("[1/10] Truy vấn Windows Firewall...")
    try:
      ok = (
          "ON" in self.run_cmd("netsh advfirewall show allprofiles state").upper()
      )
      self.update_item_status(0, ok)
      self.log("  ✔ Firewall đang bật." if ok else "  ✘ Firewall đang tắt!")
    except Exception:
      self.update_item_status(0, False)

    self.log("[2/10] Kiểm tra Antivirus / Windows Defender...")
    try:
      ok = "RUNNING" in self.run_cmd("sc query WinDefend").upper()
      self.update_item_status(1, ok)
      self.log(
          "  ✔ Windows Defender hoạt động."
          if ok
          else "  ✘ Windows Defender không chạy!"
      )
    except Exception:
      self.update_item_status(1, False)

    self.log("[3/10] Kiểm tra chính sách độ dài mật khẩu tối thiểu...")
    try:
      out = self.run_cmd("net accounts")
      min_len = 0
      for line in out.splitlines():
        if "minimum password length" in line.lower():
          nums = re.findall(r"\d+", line)
          if nums:
            min_len = int(nums[0])
      ok = min_len >= 8
      self.update_item_status(2, ok)
      self.log(
          f"  ✔ Độ dài mật khẩu tối thiểu: {min_len} ký tự (Đạt)."
          if ok
          else f"  ✘ Độ dài mật khẩu tối thiểu quá yếu ({min_len} ký tự, yêu cầu >= 8)!"
      )
    except Exception:
      self.update_item_status(2, False)

    self.log("[4/10] Kiểm tra chính sách khóa tài khoản (Brute-force)...")
    try:
      out = self.run_cmd("net accounts")
      lockout_ok = False
      for line in out.splitlines():
        if "lockout threshold" in line.lower() and "never" not in line.lower():
          nums = re.findall(r"\d+", line)
          if nums and int(nums[0]) > 0:
            lockout_ok = True
      self.update_item_status(3, lockout_ok)
      self.log(
          "  ✔ Đã cấu hình tự động khóa khi nhập sai mật khẩu."
          if lockout_ok
          else "  ✘ Chưa bật giới hạn nhập sai mật khẩu (Never)!"
      )
    except Exception:
      self.update_item_status(3, False)

    self.log("[5/10] Kiểm tra Registry UAC (EnableLUA)...")
    try:
      path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
      with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as k:
        val, _ = winreg.QueryValueEx(k, "EnableLUA")
        ok = val == 1
        self.update_item_status(4, ok)
        self.log("  ✔ UAC đang bật." if ok else "  ✘ UAC đang tắt!")
    except Exception:
      self.update_item_status(4, False)

    self.log("[6/10] Kiểm tra tài khoản khách (Guest)...")
    try:
      ok = "NO" in self.run_cmd("net user Guest").upper()
      self.update_item_status(5, ok)
      self.log(
          "  ✔ Tài khoản Guest đã khóa."
          if ok
          else "  ✘ Tài khoản Guest đang mở!"
      )
    except Exception:
      self.update_item_status(5, False)

    self.log("[7/10] Đang phân tích toàn bộ cổng dịch vụ TCP...")
    port_map = {}
    try:
      for conn in psutil.net_connections(kind="tcp"):
        if conn.status == psutil.CONN_LISTEN and conn.laddr:
          p = conn.laddr.port
          if p not in port_map:
            proc_name = "System"
            if conn.pid:
              try:
                proc_name = psutil.Process(conn.pid).name()
              except Exception:
                proc_name = f"PID {conn.pid}"
            if p in HIGH_RISK_PORTS:
              svc, desc = HIGH_RISK_PORTS[p]
              is_risky = True
            else:
              try:
                svc = socket.getservbyport(p, "tcp").upper()
              except Exception:
                svc = "App Service"
              desc = "Dịch vụ ứng dụng nội bộ thông thường."
              is_risky = False
            port_map[p] = {
                "port": p,
                "ip": conn.laddr.ip,
                "service": svc,
                "process": proc_name,
                "is_risky": is_risky,
                "desc": desc,
            }
    except Exception as e:
      self.log(f"  ! Lỗi đọc bảng kết nối: {e}")

    self.open_ports_data = [port_map[k] for k in sorted(port_map.keys())]
    risky_list = [p for p in self.open_ports_data if p["is_risky"]]
    self.log(
        f"  -> Phát hiện {len(self.open_ports_data)} cổng mở ({len(risky_list)} cổng rủi ro cao)."
    )
    self.update_item_status(6, len(risky_list) == 0)

    self.log("[8/10] Kiểm tra vô hiệu hóa giao thức SMBv1...")
    try:
      smb_path = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
      with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, smb_path) as k:
        val, _ = winreg.QueryValueEx(k, "SMB1")
        ok = val == 0
    except Exception:
      ok = True
    self.update_item_status(7, ok)
    self.log(
        "  ✔ Giao thức SMBv1 đã được vô hiệu hóa."
        if ok
        else "  ✘ Cảnh báo: SMBv1 đang mở!"
    )

    self.log("[9/10] Kiểm tra trạng thái mã hóa ổ đĩa BitLocker...")
    try:
      ok = "PROTECTION ON" in self.run_cmd("manage-bde -status C:").upper()
      self.update_item_status(8, ok)
      self.log(
          "  ✔ BitLocker đang bảo vệ ổ đĩa hệ thống."
          if ok
          else "  ✘ Ổ đĩa C: chưa bật mã hóa BitLocker."
      )
    except Exception:
      self.update_item_status(8, False)

    self.log("[10/10] Kiểm tra dịch vụ cập nhật Windows Update...")
    try:
      ok = "DISABLED" not in self.run_cmd("sc qc wuauserv").upper()
      self.update_item_status(9, ok)
      self.log(
          "  ✔ Windows Update sẵn sàng."
          if ok
          else "  ✘ Windows Update đã bị vô hiệu hóa!"
      )
    except Exception:
      self.update_item_status(9, False)

    self.log("✔ HOÀN TẤT KIỂM TOÁN 10 HẠNG MỤC BẢO MẬT!")
    self.after(0, self.finish_audit)

  def finish_audit(self):
    self.recalculate_dashboard()
    self.save_to_history(silent=True)
    self.btn_scan.configure(state="normal", text="⚡ QUÉT TOÀN HỆ THỐNG")

  def recalculate_dashboard(self):
    score, passed_count = 0, 0
    for var, weight, _, badge in self.check_items:
      if var.get() == 1:
        score += weight
        passed_count += 1
        badge.configure(
            text="ĐẠT (PASS)", fg_color=COLOR_SUCCESS, text_color="#ffffff"
        )
      elif badge.cget("text") != "CHỜ QUÉT":
        badge.configure(
            text="LỖI (FAIL)", fg_color=COLOR_DANGER, text_color="#ffffff"
        )

    self.current_score = score
    self.progress_bar.set(score / 100)
    if score >= 85:
      self.current_status, color = "AN TOÀN CAO", COLOR_SUCCESS
    elif score >= 60:
      self.current_status, color = "TRUNG BÌNH", COLOR_WARNING
    else:
      self.current_status, color = "NGUY HIỂM", COLOR_DANGER

    self.progress_bar.configure(progress_color=color)
    self.kpi_score[0].configure(text=f"{score} / 100", text_color=color)
    self.kpi_score[1].configure(text=f"Mức độ: {self.current_status}")
    self.kpi_passed[0].configure(text=f"{passed_count} / 10")

    total_open = len(self.open_ports_data)
    risky_cnt = sum(1 for p in self.open_ports_data if p["is_risky"])
    self.kpi_open_ports[0].configure(text=str(total_open))
    self.kpi_risky_ports[0].configure(
        text=str(risky_cnt),
        text_color=COLOR_DANGER if risky_cnt > 0 else COLOR_SUCCESS,
    )

  # ================= LƯU DB & XUẤT BÁO CÁO =================
  def save_to_history(self, silent=False):
    self.recalculate_dashboard()
    asset = self.entry_asset.get().strip() or "UNKNOWN"
    auditor = self.entry_auditor.get().strip() or "Admin"
    now_str = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    total_open = len(self.open_ports_data)
    risky_cnt = sum(1 for p in self.open_ports_data if p["is_risky"])
    try:
      conn = sqlite3.connect(self.db_path)
      conn.execute(
          "INSERT INTO audits (timestamp, asset_name, auditor, score, open_ports, risky_ports, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
          (
              now_str,
              asset,
              auditor,
              self.current_score,
              total_open,
              risky_cnt,
              self.current_status,
          ),
      )
      conn.commit()
      conn.close()
      self.load_history()
      self._append_log(
          f"[DB] Đã lưu lịch sử kiểm toán ({self.current_score}/100 điểm)."
      )
      if not silent:
        messagebox.showinfo(
            "Đã Lưu Lịch Sử",
            f"Đã lưu kết quả kiểm toán của {asset} ({self.current_score}/100 điểm) vào mục Lịch Sử.",
        )
    except Exception as e:
      messagebox.showerror(
          "Lỗi Lưu Cơ Sở Dữ Liệu", f"Không thể ghi lịch sử kiểm toán:\n{e}"
      )

  def export_report(self):
    self.recalculate_dashboard()
    asset = self.entry_asset.get().strip() or "UNKNOWN"
    auditor = self.entry_auditor.get().strip() or "Admin"
    report_dir = (
        "D:\\BaoCao_BaoMat" if os.path.exists("D:\\") else "BaoCao_BaoMat"
    )
    os.makedirs(report_dir, exist_ok=True)
    file_path = os.path.join(
        report_dir,
        f"SOC_Audit_{asset}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
    )
    with open(file_path, "w", encoding="utf-8") as f:
      f.write(
          "=" * 78
          + "\n         BIÊN BẢN KIỂM TOÁN AN TOÀN HỆ THỐNG, CỔNG MẠNG & ỨNG DỤNG\n"
          + "=" * 78
          + "\n"
      )
      f.write(
          f"Thời gian kiểm toán : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\nThiết bị / Server   : {asset}\nChuyên viên thực hiện: {auditor}\n"
      )
      f.write(
          f"Hệ điều hành        : {platform.system()} {platform.release()}\nĐiểm tuân thủ       : {self.current_score} / 100 ({self.current_status})\n"
          + "-" * 78
          + "\n"
      )
      f.write("1. KẾT QUẢ ĐÁNH GIÁ 10 TIÊU CHUẨN:\n")
      for var, weight, title, _ in self.check_items:
        f.write(
            f"   {'[ĐẠT]     ' if var.get() == 1 else '[CHƯA ĐẠT]'} ({weight}%) {title}\n"
        )
      f.write(
          "-" * 78
          + f"\n2. DANH SÁCH CỔNG ĐANG MỞ ({len(self.open_ports_data)} CỔNG):\n"
      )
      for item in self.open_ports_data:
        f.write(
            f"   - Port {item['port']:<5} | {item['service']:<10} | {item['process']:<18} | {'RỦI RO CAO' if item['is_risky'] else 'Bình thường'}\n"
        )
      watchlist_found = [
          a for a in self.installed_apps_data if a["is_watchlist"]
      ]
      f.write(
          "-" * 78
          + f"\n3. ỨNG DỤNG CẦN KIỂM TRA RỦI RO ({len(watchlist_found)}/{len(self.installed_apps_data)} ỨNG DỤNG):\n"
      )
      for app in watchlist_found:
        f.write(
            f"   - {app['name']} (v{app['version']}) -> {app['risk_note']}\n"
        )
      f.write("=" * 78 + "\n")
    messagebox.showinfo(
        "Xuất Báo Cáo Thành Công", f"Đã lưu toàn bộ biên bản tại:\n{file_path}"
    )

  def load_history(self):
    for w in self.history_scroll.winfo_children():
      w.destroy()
    try:
      conn = sqlite3.connect(self.db_path)
      rows = conn.execute(
          "SELECT timestamp, asset_name, auditor, score, open_ports, risky_ports, status FROM audits ORDER BY id DESC"
      ).fetchall()
      conn.close()
    except Exception as e:
      ctk.CTkLabel(
          self.history_scroll,
          text=f"Lỗi đọc lịch sử: {e}",
          text_color=COLOR_DANGER,
      ).pack(pady=40)
      return

    if not rows:
      ctk.CTkLabel(
          self.history_scroll,
          text="Chưa có lịch sử kiểm toán nào được lưu.",
          text_color=COLOR_TEXT_MUTED,
      ).pack(pady=40)
      return
    for ts, asset, auditor, score, o_ports, r_ports, status in rows:
      card = ctk.CTkFrame(
          self.history_scroll, corner_radius=8, fg_color=COLOR_CARD_INNER
      )
      card.pack(fill="x", padx=10, pady=6)
      color = (
          COLOR_SUCCESS
          if score >= 85
          else (COLOR_WARNING if score >= 60 else COLOR_DANGER)
      )
      ctk.CTkLabel(
          card,
          text=f"{score}/100",
          width=85,
          height=36,
          corner_radius=8,
          fg_color=color,
          text_color="#ffffff",
          font=ctk.CTkFont(size=14, weight="bold"),
      ).pack(side="left", padx=14, pady=12)
      ctk.CTkLabel(
          card,
          text=f"Thiết bị: {asset}   •   Chuyên viên: {auditor}   •   Thời gian: {ts}\nTrạng thái: {status}   |   Cổng đang mở: {o_ports}   |   Cổng rủi ro cao: {r_ports}",
          justify="left",
          font=ctk.CTkFont(size=13),
          text_color="#e2e8f0",
      ).pack(side="left", padx=6, pady=10)

  def clear_history(self):
    if messagebox.askyesno("Xác nhận", "Xóa toàn bộ lịch sử kiểm toán?"):
      conn = sqlite3.connect(self.db_path)
      conn.execute("DELETE FROM audits")
      conn.commit()
      conn.close()
      self.load_history()


if __name__ == "__main__":
  app = SecOpsSOCDashboard()
  app.mainloop()
