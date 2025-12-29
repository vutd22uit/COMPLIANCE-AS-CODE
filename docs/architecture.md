# 🏗️ System Architecture: Compliance-as-Code

This diagram illustrates the high-level architecture of the Compliance-as-Code framework for OpenStack.

```mermaid
graph TD
    %% Define Styles
    classDef target fill:#e1f5fe,stroke:#01579b,stroke-width:2px;
    classDef tools fill:#fff3e0,stroke:#e65100,stroke-width:2px;
    classDef report fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
    classDef user fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px;
    classDef storage fill:#fff9c4,stroke:#fbc02d,stroke-width:2px;

    subgraph "👥 Users & Stakeholders"
        DevOps[DevOps Engineer]:::user
        Auditor[Compliance Auditor]:::user
        Manager[IT Manager]:::user
    end

    subgraph "⚙️ Compliance Framework (The Engine)"
        Scanner[🔍 Chef InSpec<br/>(CIS Profiles)]:::tools
        Fixer[🔧 Ansible Playbooks<br/>(Auto-Remediation)]:::tools
        OPA[🛡️ OPA/Rego<br/>(Policy Check)]:::tools
        Exporter[📤 Compliance Exporter<br/>(Prometheus Metrics)]:::tools
    end

    subgraph "☁️ Target Environment (OpenStack)"
        Keystone[Keystone (Identity)]:::target
        Nova[Nova (Compute)]:::target
        Neutron[Neutron (Network)]:::target
        Cinder[Cinder (Storage)]:::target
        Linux[Linux OS Nodes]:::target
    end

    subgraph "📊 Reporting & Storage"
        Grafana[📈 Grafana Dashboard<br/>(Visualization)]:::report
        Prometheus[🔥 Prometheus<br/>(Time-Series DB)]:::storage
        JSON[📄 JSON Reports<br/>(Evidence)]:::storage
    end

    %% Flows
    DevOps -->|Triggers| Scanner
    DevOps -->|Triggers| Fixer
    
    Scanner -->|SSH Scan| Keystone
    Scanner -->|SSH Scan| Nova
    Scanner -->|SSH Scan| Neutron
    Scanner -->|SSH Scan| Linux
    
    Fixer -->|Remediate| Keystone
    Fixer -->|Remediate| Nova
    
    Scanner -->|Generates| JSON
    JSON -->|Parsed by| Exporter
    Exporter -->|Scraped by| Prometheus
    Prometheus -->|Data Source| Grafana
    
    Grafana -->|View Score| Manager
    JSON -->|Review Evidence| Auditor
```

## 🧩 Component Description

| Component | Function | Technology |
|-----------|----------|------------|
| **Target System** | The private cloud infrastructure being audited. | OpenStack (Keystone, Nova, Neutron), Linux |
| **Scanner** | Connects to targets to verify CIS controls. | Chef InSpec |
| **Remediator** | Automatically fixes configuration drift. | Ansible |
| **Evidence Store** | Raw compliance data for audit trails. | JSON / S3 |
| **Metrics Engine** | Converts static reports into time-series data. | Python Exporter + Prometheus |
| **Dashboard** | Visualizes compliance posture for stakeholders. | Grafana |
