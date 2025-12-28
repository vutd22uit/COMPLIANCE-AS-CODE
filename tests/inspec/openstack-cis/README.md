# CIS OpenStack Foundations Benchmark

![Profile Version](https://img.shields.io/badge/version-0.1.0-blue.svg)
![Controls](https://img.shields.io/badge/controls-50+-green.svg)

This InSpec profile implements the **CIS OpenStack Foundations Benchmark** for security compliance validation.

## 📊 Coverage Summary

| Section | Service | Controls | Status |
|---------|---------|----------|--------|
| 1 | **Identity (Keystone)** | 10 | ✅ Complete |
| 2 | **Compute (Nova)** | 12 | ✅ Complete |
| 3 | **Networking (Neutron)** | 8 | ✅ Complete |
| 4 | **Block Storage (Cinder)** | 6 | ✅ Complete |
| 5 | **Object Storage (Swift)** | 4 | ✅ Complete |
| 6 | **Image (Glance)** | 5 | ✅ Complete |
| 7 | **Dashboard (Horizon)** | 7 | ✅ Complete |
| 8 | **Orchestration (Heat)** | 5 | ✅ Complete |
| **TOTAL** | | **57** | |

## 🎯 Control Details

### Section 1: Identity (Keystone)
- `os-identity-1.1` - keystone.conf ownership
- `os-identity-1.2` - keystone.conf permissions
- `os-identity-1.3` - TLS protocol security
- `os-identity-1.4` - Admin token disabled
- `os-identity-1.5` - Fernet tokens enabled
- `os-identity-1.6` - Token expiration (≤1 hour)
- `os-identity-1.7` - Password hash algorithm (bcrypt/scrypt)
- `os-identity-1.8` - keystone-paste.ini permissions
- `os-identity-1.9` - policy.json permissions
- `os-identity-1.10` - Password regex configured

### Section 2: Compute (Nova)
- `os-compute-2.1` - nova.conf ownership
- `os-compute-2.2` - nova.conf permissions
- `os-compute-2.3` - VNC SSL enforcement
- `os-compute-2.4` - Internal API HTTPS
- `os-compute-2.5` - Live migration encryption
- `os-compute-2.6` - Serial console security
- `os-compute-2.7` - Metadata service HTTPS
- `os-compute-2.8` - API rate limiting
- `os-compute-2.9` - Nova API SSL
- `os-compute-2.10` - Libvirt security driver
- `os-compute-2.11` - Ephemeral disk encryption
- `os-compute-2.12` - Network isolation

### Section 3: Networking (Neutron)
- `os-networking-3.1` - neutron.conf ownership
- `os-networking-3.2` - neutron.conf permissions
- `os-networking-3.3` - Neutron API SSL
- `os-networking-3.4` - Keystone auth strategy
- `os-networking-3.5` - ML2 secure drivers
- `os-networking-3.6` - DHCP agent security
- `os-networking-3.7` - L3 agent namespaces
- `os-networking-3.8` - Metadata agent security

### Section 4-5: Storage (Cinder/Swift)
- File ownership and permissions
- Volume encryption
- NAS secure operations
- Swift hash path configuration
- Swift proxy SSL
- Container sync authentication

### Section 6: Image (Glance)
- Configuration file security
- API SSL enforcement
- Image signing
- Keystone authentication
- Image location restrictions

### Section 7: Dashboard (Horizon)
- HTTPS enforcement
- CSRF protection
- Secure session cookies
- Password autocomplete disabled
- Session timeout
- DEBUG mode disabled

### Section 8: Orchestration (Heat)
- Configuration file security
- API SSL
- Stack domain configuration
- Deferred authentication via trusts

## 🚀 Usage

### Basic Execution
```bash
# Run against OpenStack Controller
inspec exec tests/inspec/openstack-cis \
  -t ssh://admin@controller-node \
  --chef-license=accept-silent

# Run with JSON output
inspec exec tests/inspec/openstack-cis \
  -t ssh://admin@controller-node \
  --reporter cli json:results.json

# Run specific controls only
inspec exec tests/inspec/openstack-cis \
  -t ssh://admin@controller-node \
  --controls os-identity-1.1 os-identity-1.2
```

### Run by Service
```bash
# Test only Keystone controls
inspec exec tests/inspec/openstack-cis \
  -t ssh://admin@controller \
  --controls /os-identity/

# Test only Nova controls
inspec exec tests/inspec/openstack-cis \
  -t ssh://admin@compute-node \
  --controls /os-compute/
```

### Generate HTML Report
```bash
inspec exec tests/inspec/openstack-cis \
  -t ssh://admin@controller \
  --reporter html:compliance-report.html
```

## 📋 Prerequisites

### Target Requirements
- SSH access to OpenStack nodes
- Root or sudo access
- OpenStack services installed and configured

### Node Types
| Profile Section | Recommended Target |
|-----------------|-------------------|
| Identity, Networking, Image, Heat | Controller Node |
| Compute | Compute Node(s) |
| Storage (Cinder) | Controller or Storage Node |
| Storage (Swift) | Swift Proxy Node |
| Dashboard | Controller or Dashboard Node |

## 🔧 Customization

### Input Variables
Create an `inputs.yml` file to customize thresholds:

```yaml
# inputs.yml
token_expiration_max: 3600
config_file_mode: 0640
enable_volume_encryption: true
```

Run with inputs:
```bash
inspec exec tests/inspec/openstack-cis \
  -t ssh://admin@controller \
  --input-file inputs.yml
```

### Skip Controls
Create a `waivers.yml` for exceptions:

```yaml
os-compute-2.6:
  expiration_date: 2025-12-31
  justification: "Serial console required for emergency access"
  run: false
```

## 📈 Integration

### CI/CD Pipeline
See `.github/workflows/openstack-compliance.yml` for GitHub Actions integration.

### Prometheus Metrics
Results can be exported to Prometheus using the compliance exporter in `dashboards/exporters/`.

## 📝 References

- [CIS OpenStack Benchmark](https://www.cisecurity.org/benchmark/openstack)
- [OpenStack Security Guide](https://docs.openstack.org/security-guide/)
- [InSpec Documentation](https://docs.chef.io/inspec/)
