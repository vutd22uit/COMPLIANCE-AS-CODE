# 🚀 HƯỚNG DẪN CHẠY DEMO TRÊN OPENSTACK THẬT (STEP-BY-STEP)

Để demo trên hệ thống thật thành công và chuyên nghiệp, bạn hãy làm theo đúng 5 bước sau:

---

### Bước 1: Chuẩn bị thông tin kết nối
Bạn cần thông tin của máy **OpenStack Controller**. Giả sử:
- **IP:** `192.168.1.100`
- **User:** `root` (hoặc user có quyền sudo)
- **SSH Key:** `/Users/vutruongdoan/.ssh/id_rsa` (đảm bảo đã copy public key lên server).

---

### Bước 2: Thiết lập môi trường (Chạy trên máy của bạn)
Mở terminal và chạy các lệnh export sau để "chỉ đường" cho hệ thống biết server thật ở đâu:

```bash
export OPENSTACK_HOST="192.168.1.100"
export OPENSTACK_USER="root"
export OPENSTACK_SSH_KEY="~/.ssh/id_rsa"
```

---

### Bước 3: Kiểm tra kết nối
Đảm bảo bạn có thể SSH vào server mà không cần nhập mật khẩu:
```bash
ssh -i $OPENSTACK_SSH_KEY $OPENSTACK_USER@$OPENSTACK_HOST "echo 'Kết nối thành công! Hostname: \$(hostname)'"
```

---

### Bước 4: Chạy Demo "Sạch" (Scan Live)
Bây giờ, thay vì chạy `make scan` (dùng data giả), hãy chạy lệnh quét thật:

```bash
# 1. Quét thực tế hệ thống
make scan-live

# 2. Tạo báo cáo dựa trên kết quả thật
make report
```
*Lưu ý: Lúc này InSpec sẽ SSH trực tiếp vào server để kiểm tra các file config thật.*

---

### Bước 5: Biểu diễn "Auto-Remediation" (Sửa lỗi thật)
Nếu báo cáo hiện ra các lỗi (ví dụ file config sai quyền), hãy thực hiện sửa lỗi ngay trước mặt khán giả:

```bash
# Sửa lỗi tự động bằng Ansible
make remediate-apply

# Quét lại để chứng minh lỗi đã biến mất
make scan-live
make report
```

---

### 🛡️ Mẹo nhỏ để Demo mượt hơn:
1.  **Chỉnh sửa file config trước:** Bạn có thể cố tình sửa sai 1 file config trên server OpenStack (ví dụ: `chmod 777 /etc/keystone/keystone.conf`) trước khi demo để lúc quét nó hiện màu **ĐỎ**.
2.  **Dashboard:** Sau khi chạy `make scan-live`, Dashboard sẽ tự cập nhật số liệu thật nếu bạn đã bật `make dashboard`.
3.  **Tích hợp:** Kiểm tra điện thoại/màn hình Slack để thấy thông báo bắn về từ server thật.

---

### 🛑 Lưu ý an toàn:
- Luôn demo trên môi trường **Staging/Lab**.
- Nếu dùng user khác `root`, hãy đảm bảo user đó có trong `sudoers` và không yêu cầu mật khẩu (`NOPASSWD`).

Chúc bạn có một buổi demo "Live" thành công rực rỡ!
