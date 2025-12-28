#!/bin/bash
#
# OpenStack Kolla-Ansible Compliance Scanner
# Specifically designed for Kolla containerized deployments
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
PROFILE_PATH="$PROJECT_ROOT/tests/inspec/openstack-cis"
INPUTS_FILE="$PROFILE_PATH/inputs-kolla.yml"

# Load environment
if [ -f "$PROJECT_ROOT/.env.kolla" ]; then
    source "$PROJECT_ROOT/.env.kolla"
fi

# Configuration
SSH_USER="${OPENSTACK_SSH_USER:-deployer}"
SSH_KEY="${OPENSTACK_SSH_KEY:-~/.ssh/kolla_key}"
CONTROLLER_HOST="${OPENSTACK_CONTROLLER_HOST:-192.168.1.100}"

print_header() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║     OpenStack Kolla-Ansible Compliance Scanner               ║"
    echo "║     CIS OpenStack Foundations Benchmark                      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

check_prerequisites() {
    print_info "Checking prerequisites..."
    
    # Check InSpec
    if ! command -v inspec &> /dev/null; then
        print_error "InSpec is not installed"
        echo "  Install with: curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -P inspec"
        exit 1
    fi
    print_success "InSpec: $(inspec version 2>/dev/null | head -1)"
    
    # Check SSH key
    SSH_KEY_EXPANDED="${SSH_KEY/#\~/$HOME}"
    if [ ! -f "$SSH_KEY_EXPANDED" ]; then
        print_error "SSH key not found: $SSH_KEY"
        exit 1
    fi
    print_success "SSH key: $SSH_KEY"
    
    # Test SSH connection
    print_info "Testing SSH connection to $CONTROLLER_HOST..."
    if ssh -i "$SSH_KEY_EXPANDED" -o ConnectTimeout=5 -o BatchMode=yes "$SSH_USER@$CONTROLLER_HOST" "echo OK" &>/dev/null; then
        print_success "SSH connection successful"
    else
        print_error "Cannot connect to $SSH_USER@$CONTROLLER_HOST"
        exit 1
    fi
}

check_kolla_deployment() {
    print_info "Checking Kolla deployment status..."
    
    # Check if Kolla containers are running
    CONTAINERS=$(ssh -i "${SSH_KEY/#\~/$HOME}" "$SSH_USER@$CONTROLLER_HOST" "sudo docker ps --format '{{.Names}}' | grep -E '^(keystone|nova|neutron|glance|horizon)' | wc -l")
    
    if [ "$CONTAINERS" -gt 0 ]; then
        print_success "Found $CONTAINERS OpenStack containers running"
    else
        print_warning "No OpenStack containers found - is Kolla deployed?"
    fi
    
    # Check Kolla config directory
    if ssh -i "${SSH_KEY/#\~/$HOME}" "$SSH_USER@$CONTROLLER_HOST" "test -d /etc/kolla/keystone"; then
        print_success "Kolla config directory exists"
    else
        print_error "/etc/kolla/keystone not found"
        exit 1
    fi
}

run_scan() {
    local SCAN_TYPE="$1"
    local OUTPUT_DIR="$PROJECT_ROOT/reports"
    local TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    
    mkdir -p "$OUTPUT_DIR"
    
    print_info "Running $SCAN_TYPE scan..."
    
    case "$SCAN_TYPE" in
        "full")
            # Run all controls
            inspec exec "$PROFILE_PATH" \
                -t "ssh://$SSH_USER@$CONTROLLER_HOST" \
                -i "${SSH_KEY/#\~/$HOME}" \
                --sudo \
                --input-file "$INPUTS_FILE" \
                --chef-license=accept-silent \
                --reporter cli json:"$OUTPUT_DIR/kolla-full-$TIMESTAMP.json" html:"$OUTPUT_DIR/kolla-full-$TIMESTAMP.html"
            ;;
        "kolla")
            # Run only Kolla-specific controls
            inspec exec "$PROFILE_PATH" \
                -t "ssh://$SSH_USER@$CONTROLLER_HOST" \
                -i "${SSH_KEY/#\~/$HOME}" \
                --sudo \
                --controls /kolla-/ \
                --input-file "$INPUTS_FILE" \
                --chef-license=accept-silent \
                --reporter cli json:"$OUTPUT_DIR/kolla-specific-$TIMESTAMP.json"
            ;;
        "quick")
            # Quick check - just container and config permissions
            inspec exec "$PROFILE_PATH" \
                -t "ssh://$SSH_USER@$CONTROLLER_HOST" \
                -i "${SSH_KEY/#\~/$HOME}" \
                --sudo \
                --controls kolla-1.1 kolla-7.1 kolla-8.1 \
                --chef-license=accept-silent \
                --reporter cli
            ;;
        *)
            print_error "Unknown scan type: $SCAN_TYPE"
            exit 1
            ;;
    esac
    
    print_success "Scan complete! Reports saved to: $OUTPUT_DIR"
}

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --host HOST     OpenStack controller host (default: \$OPENSTACK_CONTROLLER_HOST or 192.168.1.100)"
    echo "  -u, --user USER     SSH user (default: \$OPENSTACK_SSH_USER or deployer)"
    echo "  -k, --key FILE      SSH private key (default: \$OPENSTACK_SSH_KEY or ~/.ssh/kolla_key)"
    echo "  -t, --type TYPE     Scan type: full, kolla, quick (default: kolla)"
    echo "  --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Run Kolla-specific scan with defaults"
    echo "  $0 -t full                            # Run full CIS scan"
    echo "  $0 -t quick                           # Quick health check"
    echo "  $0 -h 192.168.1.100 -u ubuntu -t full # Custom host and user"
}

# Parse arguments
SCAN_TYPE="kolla"

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--host)
            CONTROLLER_HOST="$2"
            shift 2
            ;;
        -u|--user)
            SSH_USER="$2"
            shift 2
            ;;
        -k|--key)
            SSH_KEY="$2"
            shift 2
            ;;
        -t|--type)
            SCAN_TYPE="$2"
            shift 2
            ;;
        --help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Main execution
print_header

echo -e "${YELLOW}Configuration:${NC}"
echo "  Controller: $CONTROLLER_HOST"
echo "  SSH User:   $SSH_USER"
echo "  SSH Key:    $SSH_KEY"
echo "  Scan Type:  $SCAN_TYPE"
echo ""

check_prerequisites
check_kolla_deployment
run_scan "$SCAN_TYPE"

echo ""
print_success "Kolla-Ansible compliance scan completed!"
