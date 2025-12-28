#!/bin/bash
# OpenStack Integration Test Runner
# Usage: ./run_integration_tests.sh [mock|live] [target]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

MODE="${1:-mock}"
TARGET="${2:-ssh://admin@localhost}"

echo "=============================================="
echo "🔬 OpenStack Compliance Integration Tests"
echo "=============================================="
echo "Mode: $MODE"
echo "Target: $TARGET"
echo "Project Root: $PROJECT_ROOT"
echo ""

# Check dependencies
check_dependencies() {
    echo "📋 Checking dependencies..."
    
    if ! command -v inspec &> /dev/null; then
        if [ "$MODE" == "mock" ]; then
            echo "⚠️ InSpec is not installed (Allowed in mock mode)"
        else
            echo "❌ InSpec is not installed"
            echo "   Install with: curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -P inspec"
            exit 1
        fi
    else
        echo "   ✅ InSpec: $(inspec version 2>/dev/null | head -1)"
    fi
    
    if ! command -v python3 &> /dev/null; then
        echo "❌ Python3 is not installed"
        exit 1
    fi
    echo "   ✅ Python: $(python3 --version)"
    
    echo ""
}

# Validate profiles
validate_profiles() {
    echo "📋 Validating InSpec profiles..."
    
    if ! command -v inspec &> /dev/null; then
        echo "   ⚠️ Skipping profile validation (InSpec missing)"
        return
    fi

    PROFILES=("openstack-cis" "linux-cis")
    
    for profile in "${PROFILES[@]}"; do
        PROFILE_PATH="$PROJECT_ROOT/tests/inspec/$profile"
        if [ -d "$PROFILE_PATH" ]; then
            if inspec check "$PROFILE_PATH" --chef-license=accept-silent 2>/dev/null; then
                echo "   ✅ $profile"
            else
                echo "   ❌ $profile - validation failed"
            fi
        else
            echo "   ⚠️ $profile - not found"
        fi
    done
    
    echo ""
}

# Run mock tests
run_mock_tests() {
    echo "🧪 Running mock tests..."
    
    cd "$PROJECT_ROOT"
    python3 tests/integration/test_openstack_compliance.py --mode mock
    
    echo ""
}

# Run live tests
run_live_tests() {
    echo "🔴 Running live tests against: $TARGET"
    
    # Check SSH connectivity
    echo "   Checking SSH connectivity..."
    HOST=$(echo "$TARGET" | sed 's/ssh:\/\///' | cut -d'@' -f2)
    USER=$(echo "$TARGET" | sed 's/ssh:\/\///' | cut -d'@' -f1)
    
    if ssh -o ConnectTimeout=5 -o BatchMode=yes "$USER@$HOST" "echo 'Connection OK'" 2>/dev/null; then
        echo "   ✅ SSH connection successful"
    else
        echo "   ❌ Cannot connect to $HOST"
        echo "   Make sure SSH key is configured"
        exit 1
    fi
    
    # Create results directory
    RESULTS_DIR="$PROJECT_ROOT/results/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$RESULTS_DIR"
    
    # Run OpenStack CIS profile
    echo ""
    echo "   Running OpenStack CIS Benchmark..."
    inspec exec "$PROJECT_ROOT/tests/inspec/openstack-cis" \
        -t "$TARGET" \
        --chef-license=accept-silent \
        --reporter cli json:"$RESULTS_DIR/openstack-cis.json" html:"$RESULTS_DIR/openstack-cis.html" \
        || true
    
    # Run Linux CIS profile
    echo ""
    echo "   Running Linux CIS Benchmark..."
    inspec exec "$PROJECT_ROOT/tests/inspec/linux-cis" \
        -t "$TARGET" \
        --chef-license=accept-silent \
        --reporter cli json:"$RESULTS_DIR/linux-cis.json" html:"$RESULTS_DIR/linux-cis.html" \
        || true
    
    echo ""
    echo "📊 Results saved to: $RESULTS_DIR"
    
    # Generate summary
    if [ -f "$RESULTS_DIR/openstack-cis.json" ]; then
        echo ""
        echo "📈 OpenStack CIS Summary:"
        jq -r '
            .profiles[] as $profile |
            ($profile.controls | map(.results[].status) | group_by(.) | map({(.[0]): length}) | add) as $counts |
            "   Total Controls: \($profile.controls | length)",
            "   Passed: \($counts.passed // 0)",
            "   Failed: \($counts.failed // 0)",
            "   Skipped: \($counts.skipped // 0)"
        ' "$RESULTS_DIR/openstack-cis.json" 2>/dev/null || echo "   Unable to parse results"
    fi
    
    echo ""
}

# Main execution
main() {
    check_dependencies
    validate_profiles
    
    case "$MODE" in
        mock)
            run_mock_tests
            ;;
        live)
            run_live_tests
            ;;
        *)
            echo "❌ Invalid mode: $MODE"
            echo "Usage: $0 [mock|live] [target]"
            exit 1
            ;;
    esac
    
    echo "=============================================="
    echo "✅ Integration tests completed!"
    echo "=============================================="
}

main
