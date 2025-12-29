---
marp: true
theme: gaia
class: lead
backgroundColor: #fff
backgroundImage: url('https://marp.app/assets/hero-background.svg')
paginate: true
_paginate: false
style: |
  section {
    font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    font-size: 30px;
  }
  h1 {
    color: #0f3460;
  }
  h2 {
    color: #1a1a2e;
  }
  strong {
    color: #e94560;
  }
---

<!-- _class: lead -->

# 🛡️ Compliance-as-Code for OpenStack
## Automating CIS Benchmark Security

### Building a "Robot Inspector" for Your Private Cloud

---

# 1. The Problem: "The Manual Inspection Nightmare" 🏠🏃‍♂️

Imagine you manage a **massive apartment complex** (OpenStack Cloud) with hundreds of units.

### The Old Way (Manual Audit):
*   👮‍♂️ **Inspector**: Walks to *every single door*.
*   📝 **Checklist**: Manually writes down "Locked" or "Unlocked".
*   ⏳ **Time**: Takes **days or weeks** to finish.
*   😫 **Result**: Exhausting, error-prone, and outdated the moment it's done.

> **"Is the cloud secure?"** -> *No one really knows for sure.*

---

# 2. The Solution: "The Robot Inspector" 🤖⚡

We built a **Compliance-as-Code Framework**.

### The New Way (Automated Audit):
*   🤖 **Robot**: Instantly checks *all units* simultaneously.
*   💻 **Digital Report**: Updates in **real-time**.
*   ⚡ **Time**: Takes **minutes**.
*   ✅ **Result**: 100% accurate, continuous visibility.

> **"Is the cloud secure?"** -> *Yes, checked 5 minutes ago.*

---

# 3. How It Works: The 3-Step Flow 🔄

Our framework automates the entire security lifecycle using three key actions:

1.  **👁️ SCAN (The Eyes)**
    *   Tool: **Chef InSpec**
    *   Action: Checks configurations against CIS Benchmarks.

2.  **🧠 REPORT (The Brain)**
    *   Tool: **Grafana & Prometheus**
    *   Action: Visualizes scores and alerts on violations.

3.  **🔧 FIX (The Hands)**
    *   Tool: **Ansible**
    *   Action: Automatically remediates known issues.

---

# Step 1: SCAN (The Eyes) 👁️

**Tool:** Chef InSpec

We translated the **CIS OpenStack Benchmark** PDF (hundreds of pages) into executable code.

**What it checks:**
*   ✅ Is **Keystone** using secure Tokens?
*   ✅ Is **Nova** using VNC over SSL?
*   ✅ Is **Neutron** firewall configured correctly?
*   ✅ Are **Config Files** (noval.conf, etc.) owned by root?

> *It visits every service and asks: "Are you safe?"*

---

# Step 2: REPORT (The Brain) 🧠

**Tool:** Grafana Dashboard

Data is useless if you can't see it. We built a real-time dashboard.

**Key Metrics:**
*   🎯 **Compliance Score**: e.g., **78%** (Overall health).
*   🔴 **Critical Failures**: Immediate attention needed.
*   📉 **Trend Analysis**: Are we getting better or worse?

> *The dashboard gives Management and Security Teams a single source of truth.*

---

# Step 3: FIX (The Hands) 🔧

**Tool:** Ansible Playbooks

Why just *find* problems when you can *fix* them?

**Auto-Remediation Examples:**
*   **Found:** `keystone.conf` has permission `777` (Public).
*   **Action:** Ansible runs `chmod 640 /etc/keystone/keystone.conf`.
*   **Result:** **FIXED** ✅.

> *Self-healing infrastructure that aims for 100% compliance.*

---

# Business Value & ROI 💰

Why does this matter to the Enterprise?

1.  **🚀 Speed**: Audit time reduced from **Weeks → Minutes**.
2.  **🛡️ Security**: Continuous protection, not just "once a year".
3.  **📉 Cost**: Eliminates hundreds of hours of manual labor.
4.  **📝 Audit Ready**: Instant reports for ISO/PCI auditors.

---

# Conclusion 🏁

**Compliance-as-Code** is not just a tool; it's a mindset shift.

*   From **Reactive** -> **Proactive**
*   From **Manual** -> **Automated**
*   From **Uncertainty** -> **Confidence**

### ✅ The Framework is Ready.
### ✅ The Dashboard is Live.
### ✅ The Cloud is Secure.

**Thank You! Q&A**
