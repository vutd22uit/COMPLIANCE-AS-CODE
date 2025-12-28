# 📚 HƯỚNG DẪN SỬ DỤNG COMPLIANCE-AS-CODE

## OpenStack CIS Benchmark Framework

---

## 📋 MỤC LỤC

1. [Giới thiệu](#1-giới-thiệu)
2. [Yêu cầu hệ thống](#2-yêu-cầu-hệ-thống)
3. [Cài đặt](#3-cài-đặt)
4. [Chạy Mock Test](#4-chạy-mock-test-không-cần-openstack)
5. [Chạy trên OpenStack thật](#5-chạy-trên-openstack-thật)
6. [Remediation tự động](#6-remediation-tự-động)
7. [Tạo báo cáo](#7-tạo-báo-cáo)
8. [CI/CD với GitHub Actions](#8-cicd-với-github-actions)
9. [Monitoring với Grafana](#9-monitoring-với-grafana)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. GIỚI THIỆU

### Dự án này là gì?

**Compliance-as-Code** là framework tự động hóa kiểm tra bảo mật cho OpenStack dựa trên **CIS OpenStack Foundations Benchmark**.

### Tính năng chính

| Tính năng | Mô tả |
|-----------|-------|
| ✅ **57 Security Controls** | Kiểm tra 7 dịch vụ OpenStack |
| ✅ **Auto Remediation** | Tự động sửa lỗi bằng Ansible |
| ✅ **Policy-as-Code** | Kiểm tra Heat template với OPA/Rego |
| ✅ **CI/CD Pipeline** | GitHub Actions tự động scan hàng ngày |
| ✅ **Dashboard** | Grafana + Prometheus monitoring |

### Các dịch vụ được kiểm tra

```
┌─────────────────────────────────────────────────────┐
│           OpenStack Services Coverage               │
├─────────────────────────────────────────────────────┤
│  Keystone (Identity)     │ 10 controls │ ✅ 100%   │
│  Nova (Compute)          │ 12 controls │ ✅ 100%   │
│  Neutron (Networking)    │  8 controls │ ✅ 100%   │
│  Cinder (Block Storage)  │  6 controls │ ✅ 100%   │
│  Swift (Object Storage)  │  4 controls │ ✅ 100%   │
│  Glance (Image)          │  5 controls │ ✅ 100%   │
│  Horizon (Dashboard)     │  7 controls │ ✅ 100%   │
│  Heat (Orchestration)    │  5 controls │ ✅ 100%   │
├─────────────────────────────────────────────────────┤
│  TỔNG CỘNG               │ 57 controls │ ✅ 100%   │
└─────────────────────────────────────────────────────┘
```

---

## 2. YÊU CẦU HỆ THỐNG

### Máy chạy scan (Local/CI Server)

| Thành phần | Phiên bản | Bắt buộc |
|------------|-----------|----------|
| macOS / Linux | 10.15+ / Ubuntu 20.04+ | ✅ |
| Python | 3.9+ | ✅ |
| Git | 2.x | ✅ |
| InSpec | 5.x | ✅ (cho live scan) |
| Ansible | 2.9+ | ⚠️ (cho remediation) |
| OPA/Conftest | 0.50+ | ⚠️ (cho policy check) |

### OpenStack Environment (cho live scan)

| Thành phần | Yêu cầu |
|------------|---------|
| OpenStack Version | Yoga, Zed, hoặc mới hơn |
| SSH Access | Root hoặc sudo trên các node |
| Nodes | Controller + Compute (tối thiểu) |

---

## 3. CÀI ĐẶT

### 3.1 Clone Repository

```bash
git clone https://github.com/vutd22uit/COMPLIANCE-AS-CODE.git
cd COMPLIANCE-AS-CODE
```

### 3.2 Cài đặt Dependencies

#### macOS

```bash
# Python
brew install python3

# InSpec
curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -P inspec

# Ansible (cho remediation)
brew install ansible

# OPA (cho policy check - optional)
brew install opa
```

#### Ubuntu/Debian

```bash
# Python
sudo apt update && sudo apt install -y python3 python3-pip

# InSpec
curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -P inspec

# Ansible
sudo apt install -y ansible

# OPA
curl -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
sudo chmod +x /usr/local/bin/opa
```

### 3.3 Verify Installation

```bash
python3 --version    # Python 3.9+
inspec version       # 5.x.x
ansible --version    # 2.9+
opa version          # 0.50+ (optional)
```

---

## 4. CHẠY MOCK TEST (KHÔNG CẦN OPENSTACK)

> 💡 **Tip:** Dùng mock mode để test framework mà không cần môi trường OpenStack thật.

### 4.1 Chạy Integration Test

```bash
# Cấp quyền thực thi
chmod +x tests/integration/run_integration_tests.sh

# Chạy mock test
./tests/integration/run_integration_tests.sh mock
```

### 4.2 Kết quả mong đợi

```
==============================================
🔬 OpenStack Compliance Integration Tests
==============================================
Mode: mock

📋 Checking dependencies...
⚠️ InSpec is not installed (Allowed in mock mode)
   ✅ Python: Python 3.x.x

🧪 Running mock tests...
✅ Test environment ready (mode: mock)

📊 Mock Results Summary:
   Passed:  3
   Failed:  0
   Skipped: 0
   Score:   100.0%

✅ Integration tests completed successfully!
==============================================
```

---

## 5. CHẠY TRÊN OPENSTACK THẬT

### 5.1 Chuẩn bị SSH Access

```bash
# Tạo SSH key (nếu chưa có)
ssh-keygen -t ed25519 -f ~/.ssh/openstack_key -N ""

# Copy key lên OpenStack nodes
ssh-copy-id -i ~/.ssh/openstack_key <user>@<controller-ip>
ssh-copy-id -i ~/.ssh/openstack_key <user>@<compute-ip>

# Test kết nối
ssh -i ~/.ssh/openstack_key <user>@<controller-ip> "hostname"
```

### 5.2 Cấu hình biến môi trường

```bash
# Tạo file .env
cat > .env << 'EOF'
export OPENSTACK_SSH_USER=ubuntu
export OPENSTACK_SSH_KEY=~/.ssh/openstack_key
export OPENSTACK_CONTROLLER_HOST=192.168.1.100
export OPENSTACK_COMPUTE_1_HOST=192.168.1.101
export OPENSTACK_COMPUTE_2_HOST=192.168.1.102
EOF

# Load biến
source .env
```

### 5.3 Chạy InSpec Scan

#### Scan Controller Node

```bash
inspec exec tests/inspec/openstack-cis \
  -t ssh://$OPENSTACK_SSH_USER@$OPENSTACK_CONTROLLER_HOST \
  -i $OPENSTACK_SSH_KEY \
  --sudo \
  --chef-license=accept-silent \
  --reporter cli json:controller-results.json
```

#### Scan Compute Node

```bash
inspec exec tests/inspec/openstack-cis \
  -t ssh://$OPENSTACK_SSH_USER@$OPENSTACK_COMPUTE_1_HOST \
  -i $OPENSTACK_SSH_KEY \
  --sudo \
  --controls /os-compute/ \
  --chef-license=accept-silent \
  --reporter cli json:compute-results.json
```

#### Scan theo từng service

```bash
# Chỉ scan Keystone
inspec exec tests/inspec/openstack-cis \
  -t ssh://$OPENSTACK_SSH_USER@$OPENSTACK_CONTROLLER_HOST \
  -i $OPENSTACK_SSH_KEY \
  --sudo \
  --controls /os-identity/ \
  --chef-license=accept-silent

# Chỉ scan Nova
inspec exec tests/inspec/openstack-cis \
  -t ssh://$OPENSTACK_SSH_USER@$OPENSTACK_COMPUTE_1_HOST \
  -i $OPENSTACK_SSH_KEY \
  --sudo \
  --controls /os-compute/ \
  --chef-license=accept-silent
```

### 5.4 Xem kết quả

```bash
# Đọc JSON results
cat controller-results.json | python3 -m json.tool

# Hoặc dùng jq
jq '.profiles[0].controls[] | {id, title, status: .results[0].status}' controller-results.json
```

---

## 6. REMEDIATION TỰ ĐỘNG

### 6.1 Tạo Inventory File

```bash
cat > inventory.ini << EOF
[controller]
$OPENSTACK_CONTROLLER_HOST ansible_user=$OPENSTACK_SSH_USER ansible_ssh_private_key_file=$OPENSTACK_SSH_KEY

[compute]
$OPENSTACK_COMPUTE_1_HOST ansible_user=$OPENSTACK_SSH_USER ansible_ssh_private_key_file=$OPENSTACK_SSH_KEY
$OPENSTACK_COMPUTE_2_HOST ansible_user=$OPENSTACK_SSH_USER ansible_ssh_private_key_file=$OPENSTACK_SSH_KEY
EOF
```

### 6.2 Chạy Dry-run (Xem trước)

```bash
ansible-playbook -i inventory.ini \
  remediation/ansible/openstack-hardening.yml \
  --extra-vars "target=controller" \
  --check --diff
```

### 6.3 Chạy Remediation thật

```bash
# Toàn bộ controller
ansible-playbook -i inventory.ini \
  remediation/ansible/openstack-hardening.yml \
  --extra-vars "target=controller"

# Chỉ Keystone
ansible-playbook -i inventory.ini \
  remediation/ansible/openstack-hardening.yml \
  --extra-vars "target=controller" \
  --tags keystone

# Chỉ Nova trên compute
ansible-playbook -i inventory.ini \
  remediation/ansible/openstack-hardening.yml \
  --extra-vars "target=compute" \
  --tags nova
```

### 6.4 Verify sau Remediation

```bash
# Chạy lại scan để xác nhận
inspec exec tests/inspec/openstack-cis \
  -t ssh://$OPENSTACK_SSH_USER@$OPENSTACK_CONTROLLER_HOST \
  -i $OPENSTACK_SSH_KEY \
  --sudo \
  --chef-license=accept-silent
```

---

## 7. TẠO BÁO CÁO

### 7.1 HTML Report

```bash
inspec exec tests/inspec/openstack-cis \
  -t ssh://$OPENSTACK_SSH_USER@$OPENSTACK_CONTROLLER_HOST \
  -i $OPENSTACK_SSH_KEY \
  --sudo \
  --chef-license=accept-silent \
  --reporter html:compliance-report.html

# Mở report
open compliance-report.html  # macOS
xdg-open compliance-report.html  # Linux
```

### 7.2 JSON Report

```bash
inspec exec tests/inspec/openstack-cis \
  -t ssh://$OPENSTACK_SSH_USER@$OPENSTACK_CONTROLLER_HOST \
  -i $OPENSTACK_SSH_KEY \
  --sudo \
  --chef-license=accept-silent \
  --reporter json:compliance-report.json
```

### 7.3 Tạo Summary từ JSON

```bash
# Thống kê passed/failed
jq '{
  total: .profiles[0].controls | length,
  passed: [.profiles[0].controls[] | select(.results[0].status == "passed")] | length,
  failed: [.profiles[0].controls[] | select(.results[0].status == "failed")] | length,
  score: (([.profiles[0].controls[] | select(.results[0].status == "passed")] | length) / (.profiles[0].controls | length) * 100 | floor)
}' compliance-report.json
```

---

## 8. CI/CD VỚI GITHUB ACTIONS

### 8.1 Cấu hình Secrets

Vào GitHub Repository → Settings → Secrets → Actions, thêm:

| Secret Name | Giá trị |
|-------------|---------|
| `OPENSTACK_SSH_KEY` | Nội dung private key |
| `OPENSTACK_SSH_USER` | `ubuntu` hoặc user SSH |
| `OPENSTACK_CONTROLLER_HOST` | IP của Controller |
| `OPENSTACK_COMPUTE_1_HOST` | IP của Compute 1 |
| `SLACK_WEBHOOK_URL` | (Optional) Webhook Slack |

### 8.2 Trigger Workflow

```bash
# Push code để trigger CI
git add .
git commit -m "Update compliance checks"
git push origin main

# Hoặc chạy manual
# Vào GitHub → Actions → openstack-compliance → Run workflow
```

### 8.3 Xem kết quả

- Vào GitHub → Actions → Chọn workflow run
- Download artifacts (reports)

---

## 9. MONITORING VỚI GRAFANA

### 9.1 Khởi động Stack

```bash
cd dashboards
docker-compose up -d
```

### 9.2 Truy cập

| Service | URL | Credentials |
|---------|-----|-------------|
| Grafana | http://localhost:3000 | admin / admin |
| Prometheus | http://localhost:9090 | - |

### 9.3 Import Dashboard

1. Mở Grafana → Dashboards → Import
2. Upload file `dashboards/grafana/openstack-compliance.json`
3. Chọn datasource Prometheus

---

## 10. TROUBLESHOOTING

### Lỗi thường gặp

| Lỗi | Nguyên nhân | Giải pháp |
|-----|-------------|-----------|
| `Permission denied (publickey)` | SSH key không đúng | Kiểm tra `ssh-copy-id` |
| `sudo: password required` | Không có NOPASSWD | Thêm `--sudo-password` hoặc cấu hình sudoers |
| `Connection refused` | SSH không mở | Kiểm tra firewall, port 22 |
| `InSpec: command not found` | Chưa cài InSpec | Chạy install script |
| `Control failed unexpectedly` | Config path khác | Kiểm tra path trong control |

### Debug commands

```bash
# Test SSH connection
ssh -v -i $OPENSTACK_SSH_KEY $OPENSTACK_SSH_USER@$OPENSTACK_CONTROLLER_HOST

# Test sudo
ssh -i $OPENSTACK_SSH_KEY $OPENSTACK_SSH_USER@$OPENSTACK_CONTROLLER_HOST "sudo whoami"

# Check InSpec profile
inspec check tests/inspec/openstack-cis --chef-license=accept-silent

# Verbose InSpec run
inspec exec tests/inspec/openstack-cis \
  -t ssh://$OPENSTACK_SSH_USER@$OPENSTACK_CONTROLLER_HOST \
  -i $OPENSTACK_SSH_KEY \
  --sudo \
  --chef-license=accept-silent \
  --log-level debug
```

---

## 📞 HỖ TRỢ

- **GitHub Issues:** https://github.com/vutd22uit/COMPLIANCE-AS-CODE/issues
- **Email:** vutd22uit@gmail.com

---

## 📄 LICENSE

MIT License - Xem file [LICENSE](LICENSE) để biết thêm chi tiết.

---

**Cập nhật lần cuối:** 2025-12-29
