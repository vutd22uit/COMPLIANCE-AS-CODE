# System Architecture & Data Flow - CIS Benchmark Compliance Framework

## Table of Contents
- [1. High-Level System Architecture](#1-high-level-system-architecture)
- [2. Detailed Component Architecture](#2-detailed-component-architecture)
- [3. Data Flow Diagrams](#3-data-flow-diagrams)
- [4. Deployment Architecture](#4-deployment-architecture)
- [5. Sequence Diagrams](#5-sequence-diagrams)

---

## 1. High-Level System Architecture

```mermaid
graph TB
    subgraph "Developer Workspace"
        DEV[Developer]
        IDE[VS Code + Terraform]
        GIT[Git Repository]
    end

    subgraph "CI/CD Pipeline - GitHub Actions"
        PREHOOK[Pre-commit Hooks]
        CI[CI Workflow]
        CHECKOV[Checkov Scanner]
        TFSEC[tfsec Scanner]
        OPA[OPA/Conftest]
        GATE[Quality Gate]
    end

    subgraph "Cloud Infrastructure - AWS"
        subgraph "Compute"
            EC2[EC2 Instances]
            LAMBDA[Lambda Functions]
        end

        subgraph "Storage"
            S3[S3 Buckets]
            EBS[EBS Volumes]
            RDS[RDS Databases]
        end

        subgraph "Network"
            VPC[VPC]
            SG[Security Groups]
            NACL[NACLs]
        end

        subgraph "Security & Monitoring"
            IAM[IAM Users/Roles]
            CLOUDTRAIL[CloudTrail]
            CONFIG[AWS Config]
            KMS[KMS Keys]
        end
    end

    subgraph "Runtime Scanning Layer"
        INSPEC[InSpec Scanner]
        SCOUT[ScoutSuite]
        CONFIGRULES[AWS Config Rules]
    end

    subgraph "Compliance Engine"
        ANALYZER[Violation Analyzer]
        DECISION[Decision Engine]
        EXCEPTION[Exception DB]
    end

    subgraph "Enforcement & Remediation"
        CUSTODIAN[Cloud Custodian]
        ANSIBLE[Ansible Playbooks]
        SSM[SSM Automation]
        MANUAL[Manual Remediation Queue]
    end

    subgraph "Evidence & Reporting"
        S3EVIDENCE[S3 Evidence Bucket]
        ELASTIC[Elasticsearch]
        KIBANA[Kibana Dashboard]
        REPORTS[Compliance Reports]
    end

    subgraph "Notification System"
        SLACK[Slack Alerts]
        EMAIL[Email Notifications]
        SNS[AWS SNS]
        JIRA[Jira Tickets]
    end

    %% Developer Flow
    DEV -->|Write IaC| IDE
    IDE -->|Commit| PREHOOK
    PREHOOK -->|Checkov/tfsec| PREHOOK
    PREHOOK -->|Push| GIT
    GIT -->|Trigger| CI

    %% CI/CD Flow
    CI -->|Scan| CHECKOV
    CI -->|Scan| TFSEC
    CI -->|Policy Check| OPA
    CHECKOV -->|Results| GATE
    TFSEC -->|Results| GATE
    OPA -->|Results| GATE
    GATE -->|Pass| EC2
    GATE -->|Fail| GIT

    %% Runtime Scanning Flow
    EC2 -.->|Scan| INSPEC
    S3 -.->|Scan| INSPEC
    RDS -.->|Scan| INSPEC
    IAM -.->|Scan| INSPEC
    VPC -.->|Scan| SCOUT
    CLOUDTRAIL -.->|Events| CONFIGRULES
    CONFIG -.->|Monitor| CONFIGRULES

    %% Compliance Analysis
    INSPEC -->|Findings| ANALYZER
    SCOUT -->|Findings| ANALYZER
    CONFIGRULES -->|Violations| ANALYZER
    ANALYZER -->|Evaluate| DECISION
    DECISION -->|Check| EXCEPTION

    %% Enforcement Paths
    DECISION -->|Auto-remediate| CUSTODIAN
    DECISION -->|Config Mgmt| ANSIBLE
    DECISION -->|AWS Native| SSM
    DECISION -->|Alert| SLACK
    DECISION -->|Create Ticket| JIRA

    %% Evidence Collection
    INSPEC -->|Reports| S3EVIDENCE
    SCOUT -->|Reports| S3EVIDENCE
    CUSTODIAN -->|Logs| S3EVIDENCE
    S3EVIDENCE -->|Index| ELASTIC
    ELASTIC -->|Visualize| KIBANA
    ELASTIC -->|Generate| REPORTS

    %% Notifications
    DECISION -->|Critical| SNS
    SNS -->|Route| SLACK
    SNS -->|Route| EMAIL
    DECISION -->|Incident| JIRA

    style GATE fill:#f96,stroke:#333,stroke-width:4px
    style DECISION fill:#6f9,stroke:#333,stroke-width:4px
    style CUSTODIAN fill:#69f,stroke:#333,stroke-width:2px
    style S3EVIDENCE fill:#ff9,stroke:#333,stroke-width:2px
```

---

## 2. Detailed Component Architecture

### 2.1 Pre-Deployment Layer

```mermaid
graph LR
    subgraph "Local Development"
        TF[Terraform Code]
        HOOK[Pre-commit Hook]

        subgraph "Static Analyzers"
            CHK[Checkov]
            TFS[tfsec]
            TFLINT[TFLint]
        end
    end

    subgraph "CI Pipeline"
        GHA[GitHub Actions]

        subgraph "IaC Scanners"
            CHK2[Checkov Full Scan]
            TFS2[tfsec Full Scan]
            CONF[Conftest/OPA]
        end

        PLAN[Terraform Plan]
        JSON[Plan JSON]
    end

    TF -->|git commit| HOOK
    HOOK --> CHK
    HOOK --> TFS
    HOOK --> TFLINT
    CHK -->|Pass| TF
    TFS -->|Pass| TF
    TF -->|git push| GHA

    GHA --> PLAN
    PLAN --> JSON
    JSON --> CHK2
    JSON --> TFS2
    JSON --> CONF

    CHK2 -->|Results| AGGREGATE[Aggregate Results]
    TFS2 -->|Results| AGGREGATE
    CONF -->|Results| AGGREGATE

    AGGREGATE -->|Pass/Fail| DECISION{Quality Gate}
    DECISION -->|Pass| DEPLOY[Deploy to AWS]
    DECISION -->|Fail| BLOCK[Block PR + Comment]

    style DECISION fill:#f96,stroke:#333,stroke-width:3px
    style BLOCK fill:#f66,stroke:#333,stroke-width:2px
    style DEPLOY fill:#6f6,stroke:#333,stroke-width:2px
```

### 2.2 Runtime Monitoring Layer

```mermaid
graph TB
    subgraph "AWS Resources"
        RES1[S3 Buckets]
        RES2[EC2 Instances]
        RES3[RDS Databases]
        RES4[IAM Users/Roles]
        RES5[VPC/Network]
        RES6[CloudTrail]
    end

    subgraph "Scanning Engines"
        subgraph "InSpec"
            PROFILE1[CIS AWS Profile]
            PROFILE2[CIS Linux Profile]
            RUNNER[InSpec Runner]
        end

        subgraph "AWS Config"
            RULES[Config Rules]
            RECORDER[Config Recorder]
        end

        subgraph "ScoutSuite"
            SCOUT1[Cloud Posture Scan]
        end
    end

    subgraph "Orchestration"
        SCHED[EventBridge Scheduler]
        LAMBDA1[Scan Trigger Lambda]
        LAMBDA2[Result Processor Lambda]
    end

    subgraph "Results Storage"
        S3RAW[S3 Raw Results]
        NORMALIZE[Result Normalizer]
        S3NORM[S3 Normalized]
    end

    %% Resource to Scanner connections
    RES1 & RES2 & RES3 & RES4 & RES5 -.->|API Calls| RUNNER
    RES1 & RES2 & RES3 & RES4 & RES5 -.->|Config Changes| RECORDER
    RES1 & RES2 & RES3 & RES4 & RES5 -.->|Scan| SCOUT1
    RES6 -.->|Events| RECORDER

    %% Orchestration
    SCHED -->|Trigger| LAMBDA1
    LAMBDA1 -->|Run| RUNNER
    LAMBDA1 -->|Run| SCOUT1

    %% Results flow
    RUNNER -->|JSON| S3RAW
    SCOUT1 -->|JSON| S3RAW
    RULES -->|Compliance| S3RAW

    S3RAW -->|Trigger| LAMBDA2
    LAMBDA2 -->|Process| NORMALIZE
    NORMALIZE -->|Store| S3NORM

    style RUNNER fill:#6cf,stroke:#333,stroke-width:2px
    style NORMALIZE fill:#fc6,stroke:#333,stroke-width:2px
```

### 2.3 Enforcement & Remediation Layer

```mermaid
graph TB
    subgraph "Violation Detection"
        FINDINGS[Normalized Findings]
        SEVERITY[Severity Classifier]
        EXCEPTION[Exception Checker]
    end

    subgraph "Decision Engine"
        DECISION{Remediation Decision}
        POLICY[Remediation Policy]
    end

    subgraph "Auto-Remediation"
        CUSTODIAN[Cloud Custodian]
        CONFIG_REM[Config Remediation]
        LAMBDA_REM[Lambda Remediation]
    end

    subgraph "Manual Remediation"
        TICKET[Create Jira Ticket]
        ASSIGN[Assign to Team]
        TRACK[Track SLA]
    end

    subgraph "Notification"
        CRITICAL[Critical Alert]
        HIGH[High Alert]
        MEDIUM[Medium Alert]
    end

    subgraph "Verification"
        RESCAN[Re-scan Resource]
        VERIFY{Verification}
        CLOSE[Close Violation]
        ESCALATE[Escalate]
    end

    FINDINGS --> SEVERITY
    SEVERITY --> EXCEPTION
    EXCEPTION -->|No Exception| DECISION
    EXCEPTION -->|Has Exception| TRACK

    DECISION -->|Auto-Remediate| POLICY
    DECISION -->|Manual Review| TICKET
    DECISION -->|Alert Only| CRITICAL

    POLICY -->|S3/EC2/RDS| CUSTODIAN
    POLICY -->|AWS Native| CONFIG_REM
    POLICY -->|Custom Logic| LAMBDA_REM

    CUSTODIAN -->|Execute| RESCAN
    CONFIG_REM -->|Execute| RESCAN
    LAMBDA_REM -->|Execute| RESCAN

    TICKET --> ASSIGN
    ASSIGN --> TRACK

    CRITICAL --> SNS1[SNS Topic]
    HIGH --> SNS2[SNS Topic]
    MEDIUM --> SNS3[SNS Topic]

    RESCAN --> VERIFY
    VERIFY -->|Fixed| CLOSE
    VERIFY -->|Not Fixed| ESCALATE

    style DECISION fill:#f96,stroke:#333,stroke-width:3px
    style CUSTODIAN fill:#69f,stroke:#333,stroke-width:2px
    style CRITICAL fill:#f66,stroke:#333,stroke-width:2px
```

---

## 3. Data Flow Diagrams

### 3.1 End-to-End Data Flow

```mermaid
sequenceDiagram
    participant Dev as Developer
    participant Git as GitHub
    participant CI as CI/CD Pipeline
    participant AWS as AWS Account
    participant Scan as Scanner (InSpec)
    participant Engine as Compliance Engine
    participant Rem as Remediation
    participant Evidence as S3 Evidence
    participant Dashboard as Kibana Dashboard

    Note over Dev,Dashboard: Phase 1: Pre-Deployment
    Dev->>Git: Push Terraform code
    Git->>CI: Trigger workflow
    CI->>CI: Run Checkov
    CI->>CI: Run tfsec
    CI->>CI: Run OPA/Conftest

    alt Compliance Check PASS
        CI->>AWS: Deploy infrastructure
        Note over AWS: Resources created
    else Compliance Check FAIL
        CI->>Git: Block PR + Post comment
        CI->>Dev: Notification
    end

    Note over Dev,Dashboard: Phase 2: Runtime Scanning
    AWS->>Scan: Scheduled scan (hourly/daily)
    Scan->>Scan: Execute CIS AWS profile
    Scan->>Scan: Execute CIS Linux profile
    Scan->>Evidence: Store raw results (JSON)

    Note over Dev,Dashboard: Phase 3: Analysis & Decision
    Evidence->>Engine: Process findings
    Engine->>Engine: Classify severity
    Engine->>Engine: Check exceptions

    alt Critical Violation
        Engine->>Rem: Auto-remediate
        Rem->>AWS: Fix resource
        Rem->>Evidence: Log remediation
        Engine->>Dashboard: Update metrics
    else High Violation
        Engine->>Rem: Create Jira ticket
        Engine->>Dev: Alert via Slack
    else Medium/Low
        Engine->>Dashboard: Record finding
    end

    Note over Dev,Dashboard: Phase 4: Verification
    Rem->>Scan: Trigger re-scan
    Scan->>Evidence: Store verification result
    Evidence->>Dashboard: Update compliance score

    Note over Dev,Dashboard: Phase 5: Reporting
    Dashboard->>Dashboard: Generate compliance report
    Dashboard->>Dev: Weekly digest
```

### 3.2 Detailed Scan Data Flow

```mermaid
graph TB
    subgraph "1. Trigger"
        T1[EventBridge Schedule]
        T2[Manual Trigger]
        T3[Config Change Event]
    end

    subgraph "2. Scan Orchestrator"
        LAMBDA[Scan Orchestrator Lambda]
        PARAMS[Scan Parameters]
        TARGET[Target Selection]
    end

    subgraph "3. Scan Execution"
        subgraph "InSpec Scan"
            I1[Load CIS Profile]
            I2[Query AWS APIs]
            I3[Execute Controls]
            I4[Collect Results]
        end

        subgraph "Parallel: AWS Config"
            C1[Evaluate Rules]
            C2[Check Compliance]
        end
    end

    subgraph "4. Raw Results"
        R1[InSpec JSON Output]
        R2[Config Evaluation]
        S3RAW[S3://raw-results/]
    end

    subgraph "5. Normalization"
        N1[S3 Event Trigger]
        N2[Normalizer Lambda]
        N3[Schema Validation]
        N4[Enrichment]
    end

    subgraph "6. Canonical Format"
        JSON[Normalized JSON]
        SCHEMA{
            control_id: CIS-AWS-X.X
            resource_id: arn:aws:...
            status: PASS/FAIL
            severity: CRITICAL/HIGH/MEDIUM/LOW
            timestamp: ISO8601
            evidence: {...}
            remediation: {...}
        }
    end

    subgraph "7. Storage & Indexing"
        S3NORM[S3://normalized-results/]
        ES[Elasticsearch Index]
        PARTITION[Partition by date/severity]
    end

    subgraph "8. Analysis Pipeline"
        STREAM[Kinesis Stream]
        ANALYTICS[Lambda Analytics]
        AGGREGATOR[Metrics Aggregator]
    end

    T1 & T2 & T3 --> LAMBDA
    LAMBDA --> PARAMS
    PARAMS --> TARGET
    TARGET --> I1
    TARGET --> C1

    I1 --> I2 --> I3 --> I4 --> R1
    C1 --> C2 --> R2

    R1 & R2 --> S3RAW
    S3RAW --> N1
    N1 --> N2
    N2 --> N3
    N3 --> N4
    N4 --> JSON
    JSON -.->|Conforms to| SCHEMA
    JSON --> S3NORM
    S3NORM --> ES
    ES --> PARTITION

    S3NORM --> STREAM
    STREAM --> ANALYTICS
    ANALYTICS --> AGGREGATOR

    style SCHEMA fill:#ff9,stroke:#333,stroke-width:2px
    style LAMBDA fill:#6cf,stroke:#333,stroke-width:2px
    style N2 fill:#fc6,stroke:#333,stroke-width:2px
```

### 3.3 Remediation Data Flow

```mermaid
graph TB
    subgraph "Input: Violations"
        V1[S3 Public Bucket]
        V2[Unencrypted EBS]
        V3[Root Access Key]
        V4[No MFA on IAM]
        V5[Open Security Group]
    end

    subgraph "Classification"
        CLASS[Violation Classifier]
        SEV[Severity: CRITICAL]
        AUTO{Auto-remediable?}
        SAFE{Safe to auto-fix?}
    end

    subgraph "Decision Matrix"
        MATRIX{
            CRITICAL + Auto-remediable + Safe
            → Auto-remediate

            CRITICAL + Auto-remediable + Unsafe
            → Create ticket + Alert

            CRITICAL + Not auto-remediable
            → Alert + Ticket

            HIGH/MEDIUM
            → Ticket
        }
    end

    subgraph "Remediation Execution"
        subgraph "Cloud Custodian"
            CUS1[Load Policy]
            CUS2[Apply Filters]
            CUS3[Execute Action]
            CUS4[Verify]
        end

        subgraph "AWS Config"
            CFG1[SSM Automation Doc]
            CFG2[Execute Runbook]
            CFG3[Verify]
        end

        subgraph "Custom Lambda"
            LAM1[Custom Logic]
            LAM2[AWS SDK Calls]
            LAM3[Verify]
        end
    end

    subgraph "Verification & Evidence"
        VERIFY[Re-scan Resource]
        BEFORE[Before State]
        AFTER[After State]
        DIFF[State Diff]
        LOG[Remediation Log]
    end

    subgraph "Evidence Storage"
        EVD{
            remediation_id: uuid
            control_id: CIS-AWS-X.X
            resource_arn: arn:aws:...
            violation_detected: timestamp
            remediation_started: timestamp
            remediation_completed: timestamp
            method: custodian/config/lambda
            before_state: {...}
            after_state: {...}
            success: true/false
            triggered_by: auto/manual
        }
        S3EVD[S3://evidence/remediations/]
    end

    V1 & V2 & V3 & V4 & V5 --> CLASS
    CLASS --> SEV
    SEV --> AUTO
    AUTO -->|Yes| SAFE
    AUTO -->|No| MATRIX
    SAFE -->|Yes| MATRIX
    SAFE -->|No| MATRIX

    MATRIX -->|S3 Public| CUS1
    MATRIX -->|EBS Encryption| CFG1
    MATRIX -->|Custom Fix| LAM1

    CUS1 --> CUS2 --> CUS3 --> CUS4
    CFG1 --> CFG2 --> CFG3
    LAM1 --> LAM2 --> LAM3

    CUS4 & CFG3 & LAM3 --> VERIFY
    VERIFY --> BEFORE
    VERIFY --> AFTER
    BEFORE & AFTER --> DIFF
    DIFF --> LOG
    LOG -.->|Structure| EVD
    LOG --> S3EVD

    style MATRIX fill:#f96,stroke:#333,stroke-width:3px
    style EVD fill:#ff9,stroke:#333,stroke-width:2px
    style VERIFY fill:#6f9,stroke:#333,stroke-width:2px
```

---

## 4. Deployment Architecture

### 4.1 AWS Multi-Account Setup

```mermaid
graph TB
    subgraph "AWS Organization"
        ORG[Management Account]

        subgraph "Security Account"
            SEC[Security Tooling]
            SCANNER[Scanner IAM Role]
            REMEDIATE[Remediation IAM Role]
            S3SEC[Evidence S3 Bucket]
            ELASTIC[Elasticsearch Domain]
            KIBANA[Kibana]
        end

        subgraph "Production Account"
            PROD[Production Workloads]
            PRODRES[AWS Resources]
            PRODLOG[CloudTrail]
            PRODCONF[AWS Config]
        end

        subgraph "Staging Account"
            STAGE[Staging Workloads]
            STAGERES[AWS Resources]
            STAGELOG[CloudTrail]
            STAGECONF[AWS Config]
        end

        subgraph "Development Account"
            DEV[Development Workloads]
            DEVRES[AWS Resources]
            DEVLOG[CloudTrail]
            DEVCONF[AWS Config]
        end
    end

    subgraph "CI/CD Account"
        GITHUB[GitHub Actions Runner]
        CICD[CI/CD Pipeline]
    end

    ORG -->|Manages| SEC
    ORG -->|Manages| PROD
    ORG -->|Manages| STAGE
    ORG -->|Manages| DEV

    %% Scanner role assumes into each account
    SCANNER -.->|AssumeRole| PRODRES
    SCANNER -.->|AssumeRole| STAGERES
    SCANNER -.->|AssumeRole| DEVRES

    %% Remediation role
    REMEDIATE -.->|AssumeRole + Fix| PRODRES
    REMEDIATE -.->|AssumeRole + Fix| STAGERES
    REMEDIATE -.->|AssumeRole + Fix| DEVRES

    %% Logs flow to security account
    PRODLOG -->|Aggregate| S3SEC
    STAGELOG -->|Aggregate| S3SEC
    DEVLOG -->|Aggregate| S3SEC

    %% Config to Elasticsearch
    PRODCONF -->|Findings| ELASTIC
    STAGECONF -->|Findings| ELASTIC
    DEVCONF -->|Findings| ELASTIC

    %% CI/CD deploys
    CICD -->|Deploy| PROD
    CICD -->|Deploy| STAGE
    CICD -->|Deploy| DEV

    style SEC fill:#f96,stroke:#333,stroke-width:3px
    style SCANNER fill:#6cf,stroke:#333,stroke-width:2px
    style REMEDIATE fill:#fc6,stroke:#333,stroke-width:2px
```

### 4.2 Security Account Detail

```mermaid
graph TB
    subgraph "Security Account: Compliance Tooling"
        subgraph "Compute"
            LAMBDA1[Scan Orchestrator Lambda]
            LAMBDA2[Result Processor Lambda]
            LAMBDA3[Remediation Lambda]
            LAMBDA4[Report Generator Lambda]
        end

        subgraph "Storage"
            S3RAW[S3: Raw Scan Results]
            S3NORM[S3: Normalized Results]
            S3EVD[S3: Evidence Archive]
            S3REPORTS[S3: Reports]
        end

        subgraph "Analytics"
            ES[Elasticsearch Cluster]
            KIBANA[Kibana Dashboard]
        end

        subgraph "Orchestration"
            EB[EventBridge Rules]
            SFN[Step Functions]
        end

        subgraph "Notifications"
            SNS1[SNS: Critical Alerts]
            SNS2[SNS: High Alerts]
            SNS3[SNS: Daily Digest]
        end

        subgraph "IAM Roles"
            ROLE1[ScannerRole]
            ROLE2[RemediatorRole]
            ROLE3[ReporterRole]
        end

        subgraph "Secrets"
            SECRETS[Secrets Manager]
            KMS[KMS Keys]
        end
    end

    subgraph "External Integrations"
        SLACK[Slack Webhooks]
        JIRA[Jira API]
        EMAIL[Email/SES]
    end

    %% EventBridge triggers
    EB -->|Hourly| LAMBDA1
    EB -->|Daily| LAMBDA4

    %% Lambda workflows
    LAMBDA1 -->|Assume| ROLE1
    LAMBDA1 -->|Store| S3RAW
    S3RAW -->|Trigger| LAMBDA2
    LAMBDA2 -->|Store| S3NORM
    LAMBDA2 -->|Index| ES

    LAMBDA3 -->|Assume| ROLE2
    LAMBDA3 -->|Log| S3EVD

    LAMBDA4 -->|Query| ES
    LAMBDA4 -->|Generate| S3REPORTS

    %% Notifications
    LAMBDA2 -->|Violations| SNS1
    SNS1 --> SLACK
    SNS1 --> JIRA
    SNS1 --> EMAIL

    %% Visualization
    ES --> KIBANA

    %% Security
    LAMBDA1 & LAMBDA2 & LAMBDA3 -->|Get secrets| SECRETS
    SECRETS -->|Encrypt| KMS
    S3EVD -->|Encrypt| KMS

    style ES fill:#6cf,stroke:#333,stroke-width:2px
    style ROLE1 fill:#fc6,stroke:#333,stroke-width:2px
    style ROLE2 fill:#f96,stroke:#333,stroke-width:2px
```

---

## 5. Sequence Diagrams

### 5.1 Pre-Deployment Compliance Check

```mermaid
sequenceDiagram
    actor Dev as Developer
    participant Local as Local Machine
    participant Hook as Pre-commit Hook
    participant Git as GitHub
    participant GHA as GitHub Actions
    participant Check as Checkov
    participant OPA as OPA/Conftest
    participant Gate as Quality Gate
    participant PR as Pull Request

    Dev->>Local: Edit main.tf
    Dev->>Local: git add main.tf
    Dev->>Local: git commit -m "..."

    Local->>Hook: Trigger pre-commit
    Hook->>Hook: Run terraform fmt
    Hook->>Hook: Run terraform validate
    Hook->>Check: Run checkov
    Check->>Check: Scan Terraform files

    alt All checks PASS
        Check-->>Hook: ✓ No violations
        Hook-->>Local: ✓ Commit allowed
        Dev->>Git: git push
    else Checkov finds violations
        Check-->>Hook: ✗ Found violations
        Hook-->>Local: ✗ Commit blocked
        Hook-->>Dev: Show violations
        Note over Dev,Local: Fix issues and retry
    end

    Git->>GHA: Webhook trigger
    GHA->>GHA: Checkout code
    GHA->>GHA: terraform init
    GHA->>GHA: terraform plan -out=tfplan
    GHA->>GHA: terraform show -json > plan.json

    par Parallel Scans
        GHA->>Check: Run full Checkov scan
        GHA->>OPA: Run Conftest with plan.json
    end

    Check-->>Gate: Checkov results
    OPA-->>Gate: Conftest results

    Gate->>Gate: Aggregate results
    Gate->>Gate: Check severity threshold

    alt No CRITICAL/HIGH violations
        Gate->>PR: ✓ Comment: All checks passed
        Gate->>PR: Allow merge
    else Found CRITICAL/HIGH violations
        Gate->>PR: ✗ Comment: Violations found
        Gate->>PR: Block merge
        PR-->>Dev: Notification
    end
```

### 5.2 Runtime Scan & Remediation

```mermaid
sequenceDiagram
    participant EB as EventBridge
    participant Lambda as Scan Lambda
    participant InSpec as InSpec
    participant AWS as AWS Account
    participant S3 as S3 Results
    participant Processor as Result Processor
    participant Engine as Compliance Engine
    participant Custodian as Cloud Custodian
    participant SNS as SNS Topic
    participant Slack as Slack

    Note over EB,Slack: Every Hour: Scheduled Scan
    EB->>Lambda: Trigger scan (cron)
    Lambda->>Lambda: Assume ScannerRole
    Lambda->>InSpec: Execute CIS AWS profile

    InSpec->>AWS: Describe S3 buckets
    AWS-->>InSpec: List of buckets
    InSpec->>InSpec: Check CIS-AWS-2.1.4

    loop For each bucket
        InSpec->>AWS: Get public access block
        AWS-->>InSpec: Configuration
        InSpec->>InSpec: Evaluate control
    end

    InSpec->>InSpec: Generate JSON report
    InSpec->>S3: Upload results.json

    S3->>Processor: S3 Event trigger
    Processor->>Processor: Parse InSpec JSON
    Processor->>Processor: Normalize to canonical format

    loop For each finding
        Processor->>Engine: Send violation
        Engine->>Engine: Check severity
        Engine->>Engine: Check exceptions DB

        alt CRITICAL + Auto-remediable
            Engine->>Custodian: Trigger remediation policy
            Custodian->>AWS: Set public access block
            AWS-->>Custodian: Success
            Custodian->>S3: Log remediation
            Custodian-->>Engine: Remediation complete
            Engine->>SNS: Publish alert (remediated)
        else HIGH + Manual review needed
            Engine->>SNS: Publish alert (action required)
            Engine->>Engine: Create Jira ticket
        else MEDIUM/LOW
            Engine->>S3: Store finding
        end
    end

    SNS->>Slack: Send notification
    Slack-->>Slack: Display in #security-alerts
```

### 5.3 Evidence Collection & Reporting

```mermaid
sequenceDiagram
    participant Scan as Scanner
    participant S3Raw as S3 Raw Results
    participant Norm as Normalizer
    participant S3Norm as S3 Normalized
    participant ES as Elasticsearch
    participant Kibana as Kibana
    participant Report as Report Generator
    participant Auditor as Auditor

    Note over Scan,Auditor: Phase 1: Collection
    Scan->>S3Raw: Upload raw InSpec JSON
    S3Raw->>S3Raw: Object versioning
    S3Raw->>S3Raw: Object lock (immutable)

    Note over Scan,Auditor: Phase 2: Normalization
    S3Raw->>Norm: S3 event trigger
    Norm->>Norm: Load JSON
    Norm->>Norm: Extract metadata
    Norm->>Norm: Map to canonical schema
    Norm->>Norm: Enrich with tags
    Norm->>S3Norm: Store normalized JSON

    Note over Scan,Auditor: Phase 3: Indexing
    S3Norm->>ES: Bulk index documents
    ES->>ES: Create index by date
    ES->>ES: Apply retention policy

    Note over Scan,Auditor: Phase 4: Visualization
    Kibana->>ES: Query: Show violations by severity
    ES-->>Kibana: Aggregated results
    Kibana->>Kibana: Render dashboard

    Note over Scan,Auditor: Phase 5: Reporting
    Report->>ES: Query: Get monthly compliance data
    ES-->>Report: Time-series data
    Report->>Report: Calculate compliance score
    Report->>Report: Generate PDF report
    Report->>S3Norm: Store report

    Note over Scan,Auditor: Phase 6: Audit
    Auditor->>S3Raw: Request evidence for Q4 2025
    S3Raw-->>Auditor: Download original scan results
    Auditor->>S3Norm: Request remediation logs
    S3Norm-->>Auditor: Download remediation evidence
    Auditor->>Kibana: View compliance trends
    Kibana-->>Auditor: Interactive dashboard
```

---

## Summary

### Key Architecture Principles

1. **Defense in Depth**: Multiple layers (pre-deploy, runtime, remediation)
2. **Immutable Evidence**: All scan results stored with versioning and object lock
3. **Automated Remediation**: Safe fixes applied automatically, risky ones require approval
4. **Real-time Monitoring**: Continuous scanning and alerting
5. **Audit-Ready**: Complete evidence trail with timestamps and signatures

### Data Flow Summary

```
Terraform Code
    → Pre-commit Hooks (Local)
    → CI/CD Pipeline (Checkov/OPA)
    → Quality Gate
    → Deploy to AWS

AWS Resources
    → Runtime Scan (InSpec/Config)
    → Raw Results (S3)
    → Normalization
    → Compliance Engine
    → Auto-remediation / Alerts
    → Evidence Storage
    → Dashboard / Reports
```

### Critical Components

1. **Scanner IAM Role**: Cross-account read-only access
2. **Remediation IAM Role**: Specific write permissions per service
3. **Evidence S3 Bucket**: Versioned, encrypted, object-locked
4. **Elasticsearch**: Centralized compliance data store
5. **Cloud Custodian**: Auto-remediation engine

---

**Document Version**: 1.0
**Last Updated**: 2025-12-07
**Focus**: CIS Benchmark (AWS + Linux)
