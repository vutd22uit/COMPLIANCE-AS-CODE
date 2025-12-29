# ⚡ TỔNG HỢP LỆNH CHẠY DỰ ÁN (CHEATSHEET)

Dưới đây là toàn bộ các câu lệnh bạn cần để vận hành hệ thống "Compliance-as-Code".

---

## 1. 📦 Cài đặt (Chạy lần đầu)
*Dành cho cả Mac và Ubuntu.*

```bash
# Clone code
git clone https://github.com/vutd22uit/COMPLIANCE-AS-CODE.git
cd COMPLIANCE-AS-CODE

# Cài đặt tự động (InSpec, Ansible, Python)
make install
```

---

## 2. 🛡️ Chạy Demo (Chế độ Local/Mock)
*Dùng để test nhanh hoặc quay video demo kịch tính.*

```bash
# 1. Quét thử (dữ liệu giả lập)
make scan

# 2. Tạo Dashboard "Giả lập" sự cố (Làm đỏ biểu đồ)
python3 scripts/simulate_incident.py --break

# 3. Sửa lỗi "Giả lập" (Làm xanh biểu đồ)
python3 scripts/simulate_incident.py --fix
```

---

## 3. ☁️ Chạy LIVE trên OpenStack Thật
*Dùng khi demo trên máy Ubuntu có cài OpenStack.*

### Cách A: Quét Local (Chạy lệnh ngay trên máy Ubuntu)
```bash
# Quét trực tiếp
inspec exec tests/inspec/openstack-cis -t local:// --reporter cli html:report.html

# Xem báo cáo
firefox report.html
```

### Cách B: Quét Remote (Từ Mac SSH sang Ubuntu)
```bash
# 1. Khai báo thông tin (Thay IP thật vào)
export OPENSTACK_HOST="172.20.10.13"
export OPENSTACK_USER="eployer10"

# 2. Chạy lệnh quét
make scan-live
```

---

## 4. 📊 Bật Dashboard (Giám sát thời gian thực)
*Yêu cầu đã cài Docker.*

```bash
# Bật Dashboard
make dashboard

# Tắt Dashboard
make dashboard-stop
```
*Truy cập:* 
- Grafana: `http://<IP_MÁY_UBUNTU>:3000` (User/Pass: `admin/admin`)
- Prometheus: `http://<IP_MÁY_UBUNTU>:9090`

---

## 5. 🛠️ Tự động sửa lỗi (Auto Remediation)
*Cẩn thận: Lệnh này sẽ thay đổi cấu hình máy thật.*

```bash
# Chế độ kiểm tra thử (Dry-run) - Chỉ báo cái gì SẼ sửa
make remediate

# Chế độ Sửa thật (Apply) - Sửa luôn!
make remediate-apply
```

---

## 💡 Mẹo Demo thành công
1.  **Chuẩn bị:** Chạy `make install` và `make dashboard` từ trước.
2.  **Mở đầu:** Chạy `python3 scripts/simulate_incident.py --break` để Dashboard đỏ rực.
3.  **Hành động:** Chạy `make scan-live` để show lỗi thật trên terminal.
4.  **Kết thúc:** Chạy `make remediate-apply` và show lại Dashboard xanh mướt.
