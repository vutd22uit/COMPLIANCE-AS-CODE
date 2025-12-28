# Dashboard README - OpenStack CIS Compliance Monitoring

## 📊 Overview

Hệ thống Dashboard Minh Chứng (Evidence Dashboard) để theo dõi và hiển thị trạng thái tuân thủ CIS Benchmark cho OpenStack.

## 🏗️ Kiến Trúc

```
┌─────────────────────────────────────────────────────────────────┐
│                        GRAFANA DASHBOARD                        │
│  http://localhost:3000                                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │ Overall  │ │ Controls │ │ CRITICAL │ │ Last     │           │
│  │ Score %  │ │ Stats    │ │ Score %  │ │ Scan     │           │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
│  ┌────────────────────────┐ ┌────────────────────────┐         │
│  │ Compliance Trend       │ │ By Service Pie Chart   │         │
│  └────────────────────────┘ └────────────────────────┘         │
│  ┌──────────────────────────────────────────────────┐          │
│  │ Control Status Table (Pass/Fail by Control)      │          │
│  └──────────────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────────────┘
                              ↑
┌─────────────────────────────────────────────────────────────────┐
│                        PROMETHEUS                                │
│  http://localhost:9091                                          │
│  - Metrics storage (90 days retention)                          │
│  - Alert evaluation                                             │
│  - Query engine                                                 │
└─────────────────────────────────────────────────────────────────┘
                              ↑
┌─────────────────────────────────────────────────────────────────┐
│                   COMPLIANCE EXPORTER                            │
│  http://localhost:9090/metrics                                  │
│  - Reads InSpec JSON results                                    │
│  - Exposes Prometheus metrics                                   │
│  - Updates on each scrape                                       │
└─────────────────────────────────────────────────────────────────┘
                              ↑
┌─────────────────────────────────────────────────────────────────┐
│                      SCAN RESULTS                                │
│  scan-results/*.json                                            │
│  evidence_store/                                                │
└─────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### 1. Chạy InSpec Scan

```bash
# Scan OpenStack controller
inspec exec tests/inspec/openstack-cis \
  -t ssh://root@controller-node \
  --reporter json:scan-results/openstack-scan.json \
  --chef-license accept-silent

# Scan Linux hosts
inspec exec tests/inspec/linux-cis \
  -t ssh://root@target-host \
  --reporter json:scan-results/linux-scan.json \
  --chef-license accept-silent
```

### 2. Thu thập Evidence

```bash
python evidence/collectors/evidence_collector.py \
  --inspec-json scan-results/openstack-scan.json \
  --evidence-path ./evidence_store \
  --store
```

### 3. Khởi động Dashboard

```bash
cd dashboards
docker-compose up -d

# Kiểm tra services
docker-compose ps
```

### 4. Truy cập Dashboard

- **Grafana**: http://localhost:3000
  - Username: `admin`
  - Password: `openstack-cis-2024`

- **Prometheus**: http://localhost:9091

- **Alertmanager**: http://localhost:9093

## 📈 Metrics Exposed

| Metric | Type | Description |
|--------|------|-------------|
| `openstack_compliance_score_percent` | gauge | Overall compliance % |
| `openstack_controls_total` | gauge | Total controls |
| `openstack_controls_passed` | gauge | Passed controls |
| `openstack_controls_failed` | gauge | Failed controls |
| `openstack_critical_compliance_percent` | gauge | CRITICAL severity % |
| `openstack_service_compliance{service="keystone|nova|neutron|cinder"}` | gauge | By service % |
| `openstack_findings_by_severity{severity="critical|high|medium|low"}` | gauge | Findings count |
| `openstack_evidence_collected_total` | gauge | Evidence files |
| `openstack_mttr_hours` | gauge | Mean Time To Remediate |
| `openstack_mttd_minutes` | gauge | Mean Time To Detect |
| `openstack_last_scan_timestamp` | gauge | Unix timestamp |

## 🚨 Alert Rules

| Alert | Severity | Condition |
|-------|----------|-----------|
| ComplianceScoreLow | CRITICAL | Score < 80% |
| CriticalControlFailing | CRITICAL | CRITICAL controls < 100% |
| ComplianceScoreDropping | HIGH | Delta > -5% in 1h |
| KeystoneComplianceLow | HIGH | Keystone < 80% |
| NoRecentComplianceScan | HIGH | No scan in 24h |
| CriticalSeverityFindingsDetected | CRITICAL | Any CRITICAL findings |
| MTTRTooHigh | HIGH | MTTR > 4 hours |

## 📁 File Structure

```
dashboards/
├── README.md                  # This file
├── docker-compose.yml         # Container orchestration
│
├── grafana/
│   └── compliance-dashboard.json  # Main Grafana dashboard
│
├── prometheus/
│   ├── prometheus.yml         # Prometheus config
│   └── alerts.yml            # Alert rules
│
├── alertmanager/
│   └── alertmanager.yml      # Alert routing config
│
├── exporters/
│   ├── Dockerfile            # Exporter container
│   └── compliance_exporter.py # Metrics exporter
│
├── grafana-datasource.yml    # Grafana datasource config
└── kibana/                   # (Optional) Kibana configs
```

## 🔧 Customization

### Add Custom Metrics

Edit `exporters/compliance_exporter.py` to add new metrics:

```python
# In update_metrics() method
self.metrics['my_custom_metric'] = calculate_my_metric()

# In get_prometheus_format() method
add_metric('my_custom_metric', 
           self.metrics['my_custom_metric'],
           help_text='My custom metric description')
```

### Add Dashboard Panels

1. Open Grafana
2. Edit dashboard
3. Add new panel
4. Use PromQL to query metrics
5. Save dashboard
6. Export JSON to `grafana/compliance-dashboard.json`

### Configure Alerts

Edit `alertmanager/alertmanager.yml`:

```yaml
receivers:
  - name: 'my-team'
    slack_configs:
      - channel: '#my-channel'
        api_url: 'https://hooks.slack.com/services/...'
```

## 📊 Dashboard Panels

### Row 1: Overview
- **Overall Compliance Score** (Gauge)
- **Control Statistics** (Stat)
- **CRITICAL Compliance** (Gauge)
- **Last Scan Time** (Stat)

### Row 2: Trends & Distribution
- **Compliance Trend (7 Days)** (Time Series)
- **Controls by Service** (Pie Chart)
- **Findings by Severity** (Donut)

### Row 3: Control Details
- **Control Status Table** (Table with color coding)

### Row 4: Evidence & Remediation
- **Evidence Collected** (Stat)
- **Remediations Applied** (Stat)
- **MTTR** (Gauge)
- **MTTD** (Gauge)

### Row 5: Daily Analysis
- **Daily Scan Results** (Bar Chart)
- **Compliance by Service Trend** (Time Series)

## 🔄 Continuous Monitoring

### Cron Job for Scheduled Scans

```bash
# Add to crontab
# Run every hour
0 * * * * /path/to/scripts/run-compliance-scan.sh

# run-compliance-scan.sh
#!/bin/bash
cd /path/to/COMPLIANCE-AS-CODE

# Run scan
inspec exec tests/inspec/openstack-cis \
  -t ssh://root@controller \
  --reporter json:scan-results/scan-$(date +%Y%m%d-%H%M).json

# Collect evidence
python evidence/collectors/evidence_collector.py \
  --inspec-json scan-results/scan-$(date +%Y%m%d-%H%M).json \
  --evidence-path ./evidence_store \
  --store
```

## 🛠️ Troubleshooting

### Dashboard not showing data

1. Check exporter: `curl http://localhost:9090/metrics`
2. Check Prometheus: `curl http://localhost:9091/api/v1/query?query=openstack_compliance_score_percent`
3. Verify scan results exist: `ls scan-results/*.json`

### Alerts not firing

1. Check Alertmanager: http://localhost:9093
2. Verify alert rules: http://localhost:9091/alerts
3. Check Prometheus targets: http://localhost:9091/targets

### Container issues

```bash
# View logs
docker-compose logs -f compliance-exporter
docker-compose logs -f prometheus
docker-compose logs -f grafana

# Restart services
docker-compose restart

# Rebuild exporter
docker-compose build compliance-exporter
docker-compose up -d compliance-exporter
```

---

**Last Updated**: 2025-12-29
**Platform**: OpenStack CIS Benchmark
**Components**: Grafana, Prometheus, Alertmanager, Custom Exporter
