# 🛡️ SECOPS SENTINEL PRO

Nền tảng kiểm toán bảo mật và gia cố hệ thống Windows (Enterprise Audit & Hardening Suite).

## Tính năng chính
- **Kiểm toán 10 tiêu chuẩn bảo mật (ISO 27001 / CIS Controls):** Đánh giá Windows Firewall, Windows Defender, chính sách mật khẩu, khóa tài khoản Brute-force, UAC, tài khoản Guest, cổng mạng rủi ro cao, SMBv1, BitLocker và Windows Update.
- **Phân tích cổng mạng TCP:** Liệt kê toàn bộ cổng đang mở, tiến trình sử dụng và cảnh báo các cổng rủi ro cao (FTP, SSH, Telnet, SMB, RDP, VNC...).
- **Kiểm kê & quản lý ứng dụng:** Quét phần mềm từ Windows Registry, cảnh báo công cụ điều khiển từ xa / P2P và hỗ trợ gỡ cài đặt nhanh.
- **Gia cố hệ thống (Hardening):** Kiểm tra độ mạnh mật khẩu và áp dụng nhanh các cấu hình bảo mật Windows.
- **Lưu trữ & xuất báo cáo:** Tự động lưu lịch sử kiểm toán vào cơ sở dữ liệu SQLite cục bộ và xuất biên bản `.txt`.

## Hướng dẫn cài đặt & chạy từ mã nguồn
1. Tải mã nguồn về máy và mở Command Prompt tại thư mục dự án.
2. Cài đặt các thư viện cần thiết:
   ```bash
   pip install -r requirements.txt# secops-sentinel-pro
