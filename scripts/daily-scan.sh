#!/bin/bash
# ============================================
# Daily Compliance Scan Script
# OpenStack CIS Benchmark + Linux CIS Benchmark
# ============================================

set -e

# ===== CONFIGURATION =====
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TIMESTAMP=$(date +%Y%m%d-%H%M)
DATE_ONLY=$(date +%Y%m%d)

RESULT_DIR="$PROJECT_DIR/scan-results"
EVIDENCE_DIR="$PROJECT_DIR/evidence_store"
REPORT_DIR="$PROJECT_DIR/reports"

# ===== COLORS =====
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ===== FUNCTIONS =====
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# ===== MAIN =====
echo "============================================"
echo "  OpenStack CIS Compliance Scan"
echo "  Started: $(date)"
echo "============================================"

# Create directories
mkdir -p "$RESULT_DIR" "$EVIDENCE_DIR" "$REPORT_DIR"

cd "$PROJECT_DIR"

# Check InSpec
if ! command -v inspec &> /dev/null; then
    log_error "InSpec not found. Please install InSpec first."
    exit 1
fi

log_info "InSpec version: $(inspec version)"

# ===== 1. OPENSTACK CIS SCAN =====
log_info "Running OpenStack CIS Benchmark scan..."

OPENSTACK_RESULT="$RESULT_DIR/openstack-$TIMESTAMP.json"

if inspec exec tests/inspec/openstack-cis \
    --reporter cli json:"$OPENSTACK_RESULT" \
    --chef-license accept-silent; then
    log_success "OpenStack scan completed successfully"
else
    log_warning "OpenStack scan completed with failures"
fi

# ===== 2. LINUX CIS SCAN =====
log_info "Running Linux CIS Benchmark scan..."

LINUX_RESULT="$RESULT_DIR/linux-$TIMESTAMP.json"

if inspec exec tests/inspec/linux-cis \
    --reporter cli json:"$LINUX_RESULT" \
    --chef-license accept-silent; then
    log_success "Linux scan completed successfully"
else
    log_warning "Linux scan completed with failures"
fi

# ===== 3. COLLECT EVIDENCE =====
log_info "Collecting evidence..."

if [ -f "$OPENSTACK_RESULT" ]; then
    python3 evidence/collectors/evidence_collector.py \
        --inspec-json "$OPENSTACK_RESULT" \
        --evidence-path "$EVIDENCE_DIR" \
        --store
    log_success "Evidence collected"
else
    log_warning "No OpenStack results to collect"
fi

# ===== 4. GENERATE REPORT =====
log_info "Generating compliance report..."

REPORT_FILE="$REPORT_DIR/report-$DATE_ONLY.md"

if python3 evidence/reporters/compliance_reporter.py \
    --evidence-path "$EVIDENCE_DIR" \
    --type daily \
    --format markdown \
    --output "$REPORT_FILE" 2>/dev/null; then
    log_success "Report generated: $REPORT_FILE"
else
    log_warning "Report generation skipped or failed"
fi

# ===== 5. SUMMARY =====
echo ""
echo "============================================"
echo "  Scan Complete: $(date)"
echo "============================================"
echo ""

# Parse results
if [ -f "$OPENSTACK_RESULT" ]; then
    TOTAL=$(cat "$OPENSTACK_RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('profiles',[{}])[0].get('controls',[])))" 2>/dev/null || echo "N/A")
    PASSED=$(cat "$OPENSTACK_RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(sum(1 for c in d.get('profiles',[{}])[0].get('controls',[]) for r in c.get('results',[]) if r.get('status')=='passed'))" 2>/dev/null || echo "N/A")
    FAILED=$(cat "$OPENSTACK_RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(sum(1 for c in d.get('profiles',[{}])[0].get('controls',[]) for r in c.get('results',[]) if r.get('status')=='failed'))" 2>/dev/null || echo "N/A")
    
    echo "OpenStack CIS Results:"
    echo "  - Total Controls: $TOTAL"
    echo "  - Passed: $PASSED"
    echo "  - Failed: $FAILED"
fi

echo ""
echo "Results saved to:"
echo "  - OpenStack: $OPENSTACK_RESULT"
echo "  - Linux: $LINUX_RESULT"
echo "  - Report: $REPORT_FILE"
echo ""
echo "View dashboard: open $PROJECT_DIR/dashboards/demo-dashboard.html"
echo "============================================"
