# 🚀 HƯỚNG DẪN CHẠY NHANH (QUICK START)

## Chạy Compliance Scan trên OpenStack Kolla-Ansible Yoga

---

## 📋 CÁCH 1: Chạy trực tiếp trên Ubuntu (OpenStack Host)

### Bước 1: Cài đặt InSpec

```bash
curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -P inspec
```

### Bước 2: Clone dự án

```bash
git clone https://github.com/vutd22uit/COMPLIANCE-AS-CODE.git
cd COMPLIANCE-AS-CODE
```

### Bước 3: Chạy Scan

```bash
# Quick scan - Kolla specific controls
sudo inspec exec tests/inspec/openstack-cis \
  -t local:// \
  --controls /kolla-/ \
  --chef-license=accept-silent

# Full scan với báo cáo HTML
sudo inspec exec tests/inspec/openstack-cis \
  -t local:// \
  --chef-license=accept-silent \
  --reporter cli html:openstack-report.html
```

### Bước 4: Xem báo cáo

```bash
# Xem file HTML
firefox openstack-report.html &

# Hoặc copy về máy local
scp deployer@192.168.1.100:~/COMPLIANCE-AS-CODE/openstack-report.html .
```

---

## 📋 CÁCH 2: Chạy từ xa (Remote từ Mac/Linux)

### Bước 1: Cài đặt InSpec trên máy local

```bash
# Mac
curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -P inspec

# Verify
inspec version
```

### Bước 2: Cấu hình SSH

```bash
# Tạo SSH key
ssh-keygen -t ed25519 -f ~/.ssh/kolla_key -N ""

# Copy key lên OpenStack host
ssh-copy-id -i ~/.ssh/kolla_key deployer@192.168.1.100

# Test
ssh -i ~/.ssh/kolla_key deployer@192.168.1.100 "hostname"
```

### Bước 3: Clone và chạy scan

```bash
git clone https://github.com/vutd22uit/COMPLIANCE-AS-CODE.git
cd COMPLIANCE-AS-CODE

# Scan từ xa qua SSH
inspec exec tests/inspec/openstack-cis \
  -t ssh://deployer@192.168.1.100 \
  -i ~/.ssh/kolla_key \
  --sudo \
  --chef-license=accept-silent \
  --reporter cli html:openstack-report.html

# Mở báo cáo
open openstack-report.html
```

---

## 📋 CÁCH 3: Dùng script tự động

```bash
cd COMPLIANCE-AS-CODE

# Tạo file cấu hình
cat > .env.kolla << 'EOF'
export OPENSTACK_SSH_USER=deployer
export OPENSTACK_SSH_KEY=~/.ssh/kolla_key
export OPENSTACK_CONTROLLER_HOST=192.168.1.100
EOF

source .env.kolla

# Chạy scan
./scripts/scan-kolla.sh -t quick    # Kiểm tra nhanh
./scripts/scan-kolla.sh -t kolla    # Chỉ Kolla controls
./scripts/scan-kolla.sh -t full     # Full scan
```

---

## 📋 CÁCH 4: Mock Test (Không cần OpenStack)

```bash
cd COMPLIANCE-AS-CODE

# Chạy mock test để kiểm tra framework
./tests/integration/run_integration_tests.sh mock
```

---

## 🎯 LỆNH NHANH (COPY-PASTE)

### Trên Ubuntu (OpenStack Host):

```bash
# Một lệnh duy nhất
curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -P inspec && \
git clone https://github.com/vutd22uit/COMPLIANCE-AS-CODE.git && \
cd COMPLIANCE-AS-CODE && \
sudo inspec exec tests/inspec/openstack-cis -t local:// --chef-license=accept-silent
```

### Từ Mac (Remote):

```bash
git clone https://github.com/vutd22uit/COMPLIANCE-AS-CODE.git && \
cd COMPLIANCE-AS-CODE && \
inspec exec tests/inspec/openstack-cis \
  -t ssh://deployer@192.168.1.100 \
  -i ~/.ssh/kolla_key \
  --sudo \
  --chef-license=accept-silent
```

---

## 📊 KẾT QUẢ MONG ĐỢI

```
Profile:   CIS OpenStack Foundations Benchmark
Version:   0.1.0
Target:    local://

  ✔  kolla-1.1: Ensure Kolla config directory has correct permissions
  ✔  kolla-1.2: Ensure Keystone container config has correct permissions
  ✔  kolla-7.1: Ensure Docker containers are running
  ...

Profile Summary: 15 successful controls, 3 control failures
Test Summary: 45 successful, 5 failures, 2 skipped
```

---

## ⚠️ TROUBLESHOOTING

| Lỗi | Giải pháp |
|-----|-----------|
| `Permission denied` | Thêm `sudo` hoặc chạy `ssh-copy-id` |
| `Connection refused` | Kiểm tra firewall port 22 |
| `InSpec not found` | Chạy lại lệnh cài đặt InSpec |
| `No such file /etc/kolla/*` | OpenStack chưa deploy hoặc dùng path khác |

---

## 📞 HỖ TRỢ

- **GitHub Issues**: https://github.com/vutd22uit/COMPLIANCE-AS-CODE/issues
- **Email**: vutd22uit@gmail.com

---

**Cập nhật**: 2025-12-29
