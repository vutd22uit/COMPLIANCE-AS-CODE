# 🔴 Demo trên OpenStack Thật vs 🟢 Demo Mock

## So sánh tổng quan

| Tiêu chí | Demo Mock (Hiện tại) | Demo trên OpenStack Thật |
|----------|---------------------|--------------------------|
| **Dữ liệu** | File JSON giả lập | Quét thực tế từ server OpenStack |
| **Thời gian setup** | 2 phút | 10-15 phút (cần SSH keys, network) |
| **Rủi ro** | Không có | Có thể ảnh hưởng môi trường production |
| **Tính thuyết phục** | Cao (cho demo) | Cực cao (cho stakeholder kỹ thuật) |
| **Yêu cầu** | Chỉ cần laptop | Cần access vào OpenStack Controller |

---

## 🟢 Demo Mock (Đang dùng)

### Cách hoạt động:
```bash
# Tạo dữ liệu giả
python3 scripts/simulate_incident.py --break

# Dashboard đọc từ file JSON tĩnh
# Không có kết nối SSH thực tế
```

### Ưu điểm:
- ✅ **An toàn tuyệt đối**: Không chạm vào hệ thống thật.
- ✅ **Nhanh chóng**: Setup trong vài giây.
- ✅ **Kiểm soát hoàn toàn**: Bạn quyết định control nào fail/pass.

### Nhược điểm:
- ❌ Người xem kỹ thuật có thể nghi ngờ "fake data".
- ❌ Không thể demo tính năng SSH vào server thật.

---

## 🔴 Demo trên OpenStack Thật

### Cách hoạt động:
```bash
# Thiết lập biến môi trường
export OPENSTACK_HOST="192.168.1.100"
export OPENSTACK_USER="root"
export OPENSTACK_SSH_KEY="/path/to/private_key"

# Quét thực tế
make scan-live

# InSpec sẽ SSH vào server, chạy lệnh thực tế:
# - cat /etc/keystone/keystone.conf
# - systemctl status nova-api
# - iptables -L
```

### Các bước chuẩn bị:

#### 1. Cấu hình SSH Key
```bash
# Tạo SSH key nếu chưa có
ssh-keygen -t rsa -b 4096 -f ~/.ssh/openstack_demo

# Copy public key lên OpenStack Controller
ssh-copy-id -i ~/.ssh/openstack_demo.pub root@192.168.1.100

# Test kết nối
ssh -i ~/.ssh/openstack_demo root@192.168.1.100 "hostname"
```

#### 2. Cấu hình Inventory (nếu dùng Ansible)
Sửa file `remediation/ansible/inventory/hosts.ini`:
```ini
[openstack_controllers]
controller-01 ansible_host=192.168.1.100 ansible_user=root ansible_ssh_private_key_file=~/.ssh/openstack_demo

[openstack_compute]
compute-01 ansible_host=192.168.1.101 ansible_user=root
compute-02 ansible_host=192.168.1.102 ansible_user=root
```

#### 3. Chạy Live Scan
```bash
# Quét OpenStack
make scan-live

# Kết quả sẽ là dữ liệu THẬT từ server
# Ví dụ: Nếu Keystone thực sự chưa bật SSL, control sẽ FAIL thật
```

#### 4. Demo "Sửa lỗi thật"
```bash
# Nếu phát hiện lỗi, chạy remediation
make remediate-apply

# Ansible sẽ SSH vào server và:
# - Sửa file cấu hình
# - Restart service
# - Verify lại
```

---

## 🎯 Kịch bản Demo Lai (Hybrid)

**Gợi ý tốt nhất cho bạn:**

### Phần 1: Mock Demo (5 phút đầu)
- Dùng `simulate_incident.py` để show "Chaos to Control".
- **Lý do**: Nhanh, an toàn, kiểm soát được timing.

### Phần 2: Live Proof (3 phút cuối)
```bash
# Chạy một lệnh scan thật để chứng minh
inspec exec tests/inspec/openstack-cis \
  -t ssh://root@192.168.1.100 \
  -i ~/.ssh/openstack_demo \
  --controls=os-1.1-keystone-ssl \
  --reporter cli

# Output sẽ hiện TRỰC TIẾP từ server
```

**Nói với audience:**
> "Phần trước là demo mô phỏng để tiết kiệm thời gian. Bây giờ tôi sẽ chạy thật trên OpenStack production để các anh chị thấy hệ thống hoạt động như thế nào."

---

## ⚠️ Lưu ý quan trọng khi Demo Live

### 1. Chuẩn bị môi trường "an toàn"
- **KHÔNG** demo trên production thật.
- Dùng môi trường staging hoặc lab.

### 2. Backup trước khi remediate
```bash
# Backup cấu hình trước khi sửa
ssh root@192.168.1.100 "tar -czf /root/backup-$(date +%Y%m%d).tar.gz /etc/keystone /etc/nova"
```

### 3. Có kế hoạch rollback
```bash
# Nếu có vấn đề, restore ngay
make remediate-rollback  # (Cần implement thêm)
```

### 4. Test trước ít nhất 1 ngày
- Chạy thử toàn bộ flow trước khi demo thật.
- Đảm bảo network, SSH, permissions đều OK.

---

## 📋 Checklist Demo Live

- [ ] SSH key đã được copy lên tất cả OpenStack nodes
- [ ] Test kết nối: `ssh root@<host> "echo OK"`
- [ ] InSpec profile đã được validate: `make test`
- [ ] Ansible inventory đã đúng IP và credentials
- [ ] Đã chạy thử `make scan-live` ít nhất 1 lần
- [ ] Dashboard đã được cấu hình đọc từ thư mục kết quả live
- [ ] Có backup của môi trường OpenStack
- [ ] Có kế hoạch rollback nếu demo fail

---

## 🚀 Lệnh nhanh cho Live Demo

```bash
# 1. Setup môi trường
export OPENSTACK_HOST="192.168.1.100"
export OPENSTACK_USER="root"
export OPENSTACK_SSH_KEY="~/.ssh/openstack_demo"

# 2. Quét live
make scan-live

# 3. Xem kết quả
make report
open compliance-report-*.html

# 4. Nếu có lỗi, sửa
make remediate-apply

# 5. Quét lại để verify
make scan-live
```

---

## 💡 Kết luận

**Demo Mock** phù hợp cho:
- Presentation cho C-level (họ quan tâm business value, không quan tâm technical details).
- Môi trường không có OpenStack sẵn.
- Cần demo nhanh, an toàn.

**Demo Live** phù hợp cho:
- Presentation cho đội kỹ thuật (DevOps, Security Engineers).
- Proof of Concept (POC) thực tế.
- Khi cần chứng minh hệ thống hoạt động trên infrastructure thật.

**Gợi ý của tôi:** Dùng **Hybrid** - Mock cho phần "story telling", Live cho phần "technical proof".
