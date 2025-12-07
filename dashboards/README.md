# Grafana + Prometheus Compliance Dashboard

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose installed
- Compliance scan results in `../scan-results/` directory

### Start the Stack

```bash
# Navigate to dashboards directory
cd dashboards

# Start all services
docker-compose up -d

# Check status
docker-compose ps
```

### Access Services

| Service | URL | Credentials |
|---------|-----|-------------|
| **Grafana Dashboard** | http://localhost:3000 | admin / admin |
| **Prometheus** | http://localhost:9091 | N/A |
| **Metrics Exporter** | http://localhost:9090/metrics | N/A |

---

## 📊 Dashboard Features

### Real-time Metrics
- **Overall Compliance Score** - Gauge showing current compliance percentage
- **Violations by Severity** - Pie chart (Critical/High/Medium/Low)
- **Compliance Trend** - Line chart over time
- **Control Status Table** - Detailed pass/fail for each control
- **Top Failed Controls** - Bar chart of most common failures
- **Last Scan Time** - Time since last compliance scan

### Auto-Refresh
- Dashboard auto-refreshes every **30 seconds**
- Prometheus scrapes metrics every **30 seconds**
- Alerts evaluated every **60 seconds**

---

## 🔔 Alerting

Pre-configured alerts:
1. **ComplianceScoreLow** - Score < 90% (Critical)
2. **CriticalViolationsDetected** - Any CRITICAL violations (High)
3. **ComplianceScoreWarning** - Score < 95% (Warning)
4. **HighSeverityViolations** - More than 5 HIGH violations (Warning)
5. **ComplianceScanStale** - No scan in 2 hours (Info)

---

## 📁 Directory Structure

```
dashboards/
├── docker-compose.yml          # Orchestration
├── grafana/
│   └── compliance-dashboard.json   # Dashboard definition
├── grafana-datasource.yml      # Prometheus datasource
├── prometheus/
│   ├── prometheus.yml          # Prometheus config
│   └── alerts.yml              # Alert rules
└── exporters/
    ├── compliance_exporter.py  # Python exporter
    └── Dockerfile              # Exporter container
```

---

## 🔧 Configuration

### Change Scan Results Directory

Edit `docker-compose.yml`:
```yaml
compliance-exporter:
  volumes:
    - /your/scan/results:/app/scan-results:ro
```

### Change Alert Thresholds

Edit `prometheus/alerts.yml`:
```yaml
- alert: ComplianceScoreLow
  expr: compliance_score{standard="CIS-AWS"} < 90  # Change threshold
```

### Change Refresh Rate

Edit `docker-compose.yml`:
```yaml
compliance-exporter:
  command: ["--port", "9090", "--interval", "30"]  # Change interval
```

---

## 📈 Metrics Exposed

| Metric | Type | Description |
|--------|------|-------------|
| `compliance_score` | Gauge | Overall compliance percentage (0-100) |
| `compliance_control_status` | Gauge | Individual control status (1=pass, 0=fail) |
| `compliance_violations_severity` | Gauge | Count by severity level |
| `compliance_resource_status` | Gauge | Resource compliance status |
| `compliance_last_scan_timestamp` | Gauge | Unix timestamp of last scan |

---

## 🧪 Testing

### Run Exporter Locally
```bash
# Install dependencies
pip install prometheus-client

# Create test scan results
mkdir -p scan-results
echo '{"summary":{"passed":85,"failed":15}}' > scan-results/checkov-test.json

# Run exporter
python exporters/compliance_exporter.py --results-dir scan-results

# Check metrics
curl http://localhost:9090/metrics
```

### Verify Prometheus
```bash
# Check targets
open http://localhost:9091/targets

# Query metrics
curl 'http://localhost:9091/api/v1/query?query=compliance_score'
```

---

## 🛠️ Troubleshooting

### No Data in Grafana
1. Check exporter is running: `docker-compose logs compliance-exporter`
2. Verify scan results exist: `ls -la ../scan-results/`
3. Check Prometheus targets: http://localhost:9091/targets
4. Verify metrics endpoint: http://localhost:9090/metrics

### Alerts Not Firing
1. Check alert rules: http://localhost:9091/rules
2. Verify thresholds in `prometheus/alerts.yml`
3. Check Prometheus logs: `docker-compose logs prometheus`

### Dashboard Empty
1. Wait 1-2 minutes for initial data collection
2. Check time range (default: last 6 hours)
3. Verify datasource connection in Grafana

---

## 📦 Stack Components

- **Grafana 10.x** - Visualization
- **Prometheus 2.x** - Metrics database
- **Python 3.11** - Exporter runtime
- **Node Exporter** - System metrics (optional)

---

## 🔐 Security Notes

**Default Credentials:**
- Grafana: `admin / admin` (CHANGE IN PRODUCTION!)

**Production Recommendations:**
1. Change default passwords
2. Enable HTTPS/TLS
3. Use OAuth/LDAP authentication
4. Restrict network access
5. Enable audit logging

---

## 📝 Maintenance

### Stop Services
```bash
docker-compose down
```

### View Logs
```bash
docker-compose logs -f compliance-exporter
docker-compose logs -f prometheus
docker-compose logs -f grafana
```

### Backup Dashboards
```bash
# Export from Grafana UI: Dashboard Settings → JSON Model
# Or copy from volume
docker cp compliance-grafana:/var/lib/grafana/dashboards ./backup/
```

### Update Services
```bash
docker-compose pull
docker-compose up -d
```

---

## 🎯 Next Steps

1. ✅ Start dashboard: `docker-compose up -d`
2. ✅ Run compliance scans to generate data
3. ✅ Access Grafana at http://localhost:3000
4. ✅ Import dashboard from `grafana/compliance-dashboard.json`
5. ✅ Configure alerting notifications (Slack, email, PagerDuty)

---

**Dashboard is ready! 🎉**
