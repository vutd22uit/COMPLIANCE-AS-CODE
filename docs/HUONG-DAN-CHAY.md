# 🚀 Hướng Dẫn Chạy Compliance-as-Code Framework
## Cho OpenStack Yoga (Kolla-Ansible)

---

## 📋 Mục Lục

1. [Yêu Cầu Trước Khi Chạy](#1-yêu-cầu-trước-khi-chạy)
2. [Cài Đặt Framework](#2-cài-đặt-framework)
3. [Chạy Compliance Scan](#3-chạy-compliance-scan)
4. [Xem Kết Quả](#4-xem-kết-quả)
5. [Chạy Remediation](#5-chạy-remediation-khắc-phục)
6. [Chạy Dashboard](#6-chạy-dashboard)
7. [Tự Động Hóa với CI/CD](#7-tự-động-hóa-với-cicd)

---

## 1. Yêu Cầu Trước Khi Chạy

### Trên máy OpenStack Controller (aio)

```bash
# Đăng nhập vào máy OpenStack
ssh deployer@192.168.1.100

# Kiểm tra OpenStack hoạt động
source /etc/kolla/admin-openrc.sh
openstack service list

# Kiểm tra Docker containers
docker ps | grep kolla
```

### Cài đặt InSpec

```bash
# Cài InSpec (trên Ubuntu)
curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -P inspec

# Hoặc cài qua gem
sudo gem install inspec

# Kiểm tra version
inspec version
# → Cần >= 5.0
```

### Cài đặt Python dependencies

```bash
# Tạo virtual environment (khuyến nghị)
python3 -m venv ~/compliance-venv
source ~/compliance-venv/bin/activate

# Cài dependencies
pip install pyyaml jinja2 python-openstackclient
```

---

## 2. Cài Đặt Framework

### Clone repository

```bash
# Clone từ GitHub
cd ~
git clone https://github.com/vutd22uit/COMPLIANCE-AS-CODE.git
cd COMPLIANCE-AS-CODE

# Kiểm tra cấu trúc
ls -la
```

### Tạo thư mục kết quả

```bash
mkdir -p scan-results evidence_store
```

---

## 3. Chạy Compliance Scan

### 🔹 Cách 1: Scan OpenStack Services (InSpec)

```bash
# Activate environment
source ~/compliance-venv/bin/activate
cd ~/COMPLIANCE-AS-CODE

# Chạy scan OpenStack CIS Benchmark
inspec exec tests/inspec/openstack-cis \
  --reporter cli json:scan-results/openstack-$(date +%Y%m%d-%H%M).json \
  --chef-license accept-silent

# Kết quả sẽ hiển thị trên terminal và lưu vào file JSON
```

### 🔹 Cách 2: Scan Linux CIS Benchmark

```bash
# Scan Linux host (controller)
inspec exec tests/inspec/linux-cis \
  --reporter cli json:scan-results/linux-$(date +%Y%m%d-%H%M).json \
  --chef-license accept-silent
```

### 🔹 Cách 3: Scan qua SSH (từ máy khác)

```bash
# Từ máy local, scan máy OpenStack qua SSH
inspec exec tests/inspec/openstack-cis \
  -t ssh://deployer@192.168.1.100 \
  --sudo \
  --reporter json:scan-results.json \
  --chef-license accept-silent
```

### 🔹 Cách 4: Scan Docker Containers

```bash
# Scan trực tiếp container Keystone
inspec exec tests/inspec/openstack-cis/controls/os-1-identity.rb \
  -t docker://keystone \
  --reporter cli

# Scan container Nova
inspec exec tests/inspec/openstack-cis/controls/os-2-compute.rb \
  -t docker://nova_compute \
  --reporter cli

# Script scan tất cả containers
for container in keystone nova_api nova_compute neutron_server glance_api horizon heat_api; do
  echo "=== Scanning $container ==="
  docker exec $container ls /etc/ 2>/dev/null && \
  inspec exec tests/inspec/openstack-cis -t docker://$container --reporter cli
done
```

### 🔹 Cách 5: Chạy OPA/Conftest (Pre-deployment check)

```bash
# Kiểm tra globals.yml với OPA policies
conftest test /etc/kolla/globals.yml \
  --policy policies/rego/openstack/ \
  --output json

# Hoặc kiểm tra config file cụ thể
docker exec keystone cat /etc/keystone/keystone.conf > /tmp/keystone.conf
conftest test /tmp/keystone.conf --policy policies/rego/openstack/keystone.rego
```

---

## 4. Xem Kết Quả

### 🔹 Xem trên Terminal

```bash
# Kết quả InSpec sẽ hiển thị như:
# Profile: OpenStack CIS Benchmark
# Version: 1.0.0
#
# os-identity-1.1: Ensure keystone.conf ownership
#   ✔  File /etc/keystone/keystone.conf should be owned by "root"
#
# os-identity-1.2: Ensure keystone.conf permissions
#   ✗  File /etc/keystone/keystone.conf should have mode "0640"
#      expected: 0640
#      got: 0644
```

### 🔹 Xem file JSON

```bash
# Parse kết quả với jq
cat scan-results/openstack-*.json | jq '.profiles[0].controls[] | {id: .id, title: .title, status: .results[0].status}'

# Đếm pass/fail
cat scan-results/openstack-*.json | jq '[.profiles[0].controls[].results[0].status] | group_by(.) | map({status: .[0], count: length})'
```

### 🔹 Thu thập Evidence

```bash
# Chạy evidence collector
python evidence/collectors/evidence_collector.py \
  --inspec-json scan-results/openstack-*.json \
  --evidence-path ./evidence_store \
  --store

# Xem evidence đã lưu
ls -la evidence_store/
```

### 🔹 Tạo báo cáo

```bash
# Tạo báo cáo Markdown
python evidence/reporters/compliance_reporter.py \
  --evidence-path ./evidence_store \
  --type daily \
  --format markdown \
  --output reports/daily-report.md

# Xem báo cáo
cat reports/daily-report.md
```

---

## 5. Chạy Remediation (Khắc Phục)

### 🔹 Chạy Ansible Playbook

```bash
# Activate Kolla environment
source ~/kolla-venv/bin/activate

# Chạy remediation cho OpenStack
ansible-playbook remediation/ansible/cis-openstack-remediation.yml \
  -i /etc/kolla/ansible/inventory/all-in-one \
  --tags keystone

# Chạy remediation cho Linux
ansible-playbook remediation/ansible/cis-linux-remediation.yml \
  -i /etc/kolla/ansible/inventory/all-in-one \
  --tags ssh,permissions
```

### 🔹 Áp dụng thay đổi config

```bash
# Sau khi remediation, cần reconfigure Kolla
kolla-ansible reconfigure -i /etc/kolla/ansible/inventory/all-in-one --tags keystone

# Hoặc restart service cụ thể
docker restart keystone
docker restart nova_api nova_compute
```

### 🔹 Chạy lại scan để verify

```bash
# Scan lại để kiểm tra remediation đã hoạt động
inspec exec tests/inspec/openstack-cis \
  --reporter cli json:scan-results/post-remediation-$(date +%Y%m%d-%H%M).json \
  --chef-license accept-silent
```

---

## 6. Chạy Dashboard

### 🔹 Cách 1: Dashboard HTML (Đơn giản nhất)

```bash
# Mở dashboard HTML (trên máy local có GUI)
# Copy file về máy local
scp deployer@192.168.1.100:~/COMPLIANCE-AS-CODE/dashboards/demo-dashboard.html ~/Desktop/

# Mở trong browser
open ~/Desktop/demo-dashboard.html
# hoặc trên Linux:
xdg-open ~/Desktop/demo-dashboard.html
```

### 🔹 Cách 2: Dashboard Grafana (Full monitoring)

```bash
# Trên máy có Docker
cd ~/COMPLIANCE-AS-CODE/dashboards

# Chỉnh sửa docker-compose nếu cần
nano docker-compose.yml

# Khởi động stack
docker-compose up -d

# Kiểm tra
docker-compose ps

# Truy cập:
# Grafana: http://192.168.1.100:3000 (admin / openstack-cis-2024)
# Prometheus: http://192.168.1.100:9091
```

### 🔹 Expose Dashboard ra internet (Optional)

```bash
# Nếu cần truy cập từ bên ngoài
# Thêm rule firewall
sudo iptables -A INPUT -p tcp --dport 3000 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9091 -j ACCEPT

# Hoặc dùng SSH tunnel từ máy local
ssh -L 3000:localhost:3000 deployer@192.168.1.100
# Rồi mở http://localhost:3000 trên browser
```

---

## 7. Tự Động Hóa với CI/CD

### 🔹 Chạy từ GitHub Actions

Push code lên GitHub sẽ tự động trigger workflow:

```yaml
# .github/workflows/compliance-check.yml
# Workflow sẽ chạy:
# 1. Validate OPA policies
# 2. Syntax check Ansible playbooks
# 3. Run InSpec tests (nếu có runner)
```

### 🔹 Cron Job tự động scan

```bash
# Thêm vào crontab
crontab -e

# Chạy scan mỗi ngày lúc 2:00 AM
0 2 * * * cd ~/COMPLIANCE-AS-CODE && ./scripts/daily-scan.sh >> /var/log/compliance-scan.log 2>&1
```

Tạo script `scripts/daily-scan.sh`:

```bash
#!/bin/bash
# Daily Compliance Scan Script

set -e

# Variables
TIMESTAMP=$(date +%Y%m%d-%H%M)
RESULT_DIR=~/COMPLIANCE-AS-CODE/scan-results
EVIDENCE_DIR=~/COMPLIANCE-AS-CODE/evidence_store

# Activate environment
source ~/compliance-venv/bin/activate
cd ~/COMPLIANCE-AS-CODE

echo "=== Starting Compliance Scan at $(date) ==="

# Run OpenStack scan
inspec exec tests/inspec/openstack-cis \
  --reporter json:$RESULT_DIR/openstack-$TIMESTAMP.json \
  --chef-license accept-silent || true

# Run Linux scan
inspec exec tests/inspec/linux-cis \
  --reporter json:$RESULT_DIR/linux-$TIMESTAMP.json \
  --chef-license accept-silent || true

# Collect evidence
python evidence/collectors/evidence_collector.py \
  --inspec-json $RESULT_DIR/openstack-$TIMESTAMP.json \
  --evidence-path $EVIDENCE_DIR \
  --store

# Generate report
python evidence/reporters/compliance_reporter.py \
  --evidence-path $EVIDENCE_DIR \
  --type daily \
  --format markdown \
  --output reports/report-$TIMESTAMP.md

echo "=== Scan Complete at $(date) ==="
echo "Results: $RESULT_DIR/openstack-$TIMESTAMP.json"
```

```bash
# Làm cho script chạy được
chmod +x scripts/daily-scan.sh

# Test thử
./scripts/daily-scan.sh
```

---

## 📊 Quick Reference Commands

```bash
# ============================================
# QUICK REFERENCE - COPY & PASTE
# ============================================

# 1. Scan OpenStack nhanh
cd ~/COMPLIANCE-AS-CODE && \
inspec exec tests/inspec/openstack-cis --reporter cli --chef-license accept-silent

# 2. Scan và lưu kết quả
inspec exec tests/inspec/openstack-cis \
  --reporter json:scan-results/scan-$(date +%Y%m%d).json

# 3. Xem pass/fail
cat scan-results/*.json | jq '.statistics'

# 4. Chạy remediation
ansible-playbook remediation/ansible/cis-openstack-remediation.yml \
  -i /etc/kolla/ansible/inventory/all-in-one

# 5. Mở dashboard
open dashboards/demo-dashboard.html

# 6. Full pipeline
./scripts/daily-scan.sh
```

---

## ⚠️ Troubleshooting

### InSpec không tìm thấy file config

```bash
# Kiểm tra container đang chạy
docker ps | grep kolla

# Extract config từ container
docker exec keystone cat /etc/keystone/keystone.conf > /tmp/keystone.conf

# Chạy scan với file local
inspec exec tests/inspec/openstack-cis --input config_path=/tmp
```

### Permission denied khi scan

```bash
# Chạy với sudo
sudo inspec exec tests/inspec/openstack-cis --chef-license accept-silent

# Hoặc thêm user vào group docker/kolla
sudo usermod -aG docker $USER
newgrp docker
```

### Dashboard không hiển thị data

```bash
# Kiểm tra exporter
curl http://localhost:9090/metrics

# Kiểm tra Prometheus
curl http://localhost:9091/api/v1/query?query=openstack_compliance_score_percent

# Restart services
cd dashboards && docker-compose restart
```

---

**🎯 Bắt đầu với lệnh đơn giản nhất:**

```bash
cd ~/COMPLIANCE-AS-CODE
inspec exec tests/inspec/openstack-cis --reporter cli --chef-license accept-silent
```

---

Chúc bạn thành công! 🚀
