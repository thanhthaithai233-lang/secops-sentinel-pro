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
## 📥 Tải xuống ứng dụng (Windows)
👉 **[Tải về SecOps_Sentinel_Pro.exe (v1.0.0 - Portable)](https://github.com/thanhthaithai233-lang/secops-sentinel-pro/releases/download/v1.0.0/SecOps_Sentinel_Pro.exe)** *(Chạy trực tiếp, không cần cài Python)*

> **Lưu ý khi mở lần đầu:** Bấm chuột phải vào tệp vừa tải → chọn **Run as administrator**. Nếu Windows SmartScreen hiện hộp thoại bảo vệ, chọn **More info** → **Run anyway**.
# 🛡️ SECOPS SENTINEL PRO

Nền tảng kiểm toán bảo mật và gia cố hệ thống Windows (Enterprise Audit & Hardening Suite).

---

## 💻 Yêu cầu hệ thống

* **Hệ điều hành:** Windows 10 hoặc Windows 11 (64-bit).
* **Quyền hạn:** Tài khoản có quyền Quản trị viên (**Administrator**) để đọc cấu hình bảo mật và áp dụng các bản vá gia cố hệ thống.
* **Môi trường:** Không yêu cầu cài đặt Python hay thư viện phụ trợ (toàn bộ đã được đóng gói sẵn trong tệp `.exe`).

---

## 📥 Tải xuống & Cài đặt

### Cách 1: Sử dụng bản đóng gói độc lập (Khuyên dùng)
Ứng dụng hoạt động dưới dạng **Portable** (chạy trực tiếp không cần qua trình cài đặt Setup):

1. Truy cập trang phát hành chính thức tại mục **[Releases](https://github.com/thanhthaithai233-lang/secops-sentinel-pro/releases)** hoặc bấm tải trực tiếp tệp thực thi mới nhất:
   👉 **[Tải về SecOps_Sentinel_Pro.exe (v1.0.0)](https://github.com/thanhthaithai233-lang/secops-sentinel-pro/releases/download/v1.0.0/SecOps_Sentinel_Pro.exe)**
2. Tạo một thư mục riêng trên máy tính (ví dụ: `C:\SecOps_Sentinel_Pro`) và di chuyển tệp **`SecOps_Sentinel_Pro.exe`** vào đó.
   *(Lưu ý: Khi hoạt động, ứng dụng sẽ tự động tạo tệp cơ sở dữ liệu `audit_history` ngay cùng thư mục chứa tệp `.exe` để lưu lịch sử quét).*

### Cách 2: Chạy từ mã nguồn (Dành cho nhà phát triển)
Nếu muốn tùy chỉnh mã nguồn hoặc chạy trực tiếp bằng Python:

```bash
# 1. Tải mã nguồn về máy
git clone [https://github.com/thanhthaithai233-lang/secops-sentinel-pro.git](https://github.com/thanhthaithai233-lang/secops-sentinel-pro.git)
cd secops-sentinel-pro

# 2. Cài đặt các thư viện cần thiết (customtkinter, psutil)
pip install -r requirements.txt

# 3. Khởi chạy ứng dụng
python app.py
