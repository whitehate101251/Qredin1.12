# Qredin: Simple Guide for Everyone

---

## What Is Qredin? (In Plain English)

**Qredin is a Dynamic Identity & Access Management system.**

Think of it like a **smart security guard** that doesn't just check ID cards—it decides *in real-time* exactly what each person (or AI agent/server/app) can do based on **who they are, where they are, what they're asking for, and what's happening right now**.

| Traditional IAM | Qredin (Dynamic IAM) |
|-----------------|----------------------|
| Static roles (admin, user, readonly) | **Dynamic permissions** based on exact context |
| "You're an admin, you can do everything" | "You're an AI agent *from this server*, *at this time*, *for this specific row in this specific table*" |
| Permissions updated manually | **Permissions computed in real-time per request** |
| "Trust but verify" once | **"Never trust, always verify" every single request** |
| Certificates valid for months | **SVIDs valid for hours, auto-rotated** |

---

## The Core Problem: Why Static Permissions Are Dangerous

### The AI Agent Example (Your Exact Scenario)

**Scenario**: An AI agent needs to delete the **206th line** from the **5th table** inside **database B**.

| Approach | What Happens |
|----------|--------------|
| **Static Permissions (Old Way)** | Give agent **full admin rights** to database B. Agent can now: delete ANY line, drop ANY table, exfiltrate ALL data, corrupt schema. **If agent is compromised/hallucinates → entire database destroyed.** |
| **Qredin Dynamic Permissions** | Agent gets permission for **EXACTLY ONE OPERATION**: `DELETE FROM db_b.table_5 WHERE id = 206`. **Nothing else.** Agent can't read other tables, can't delete other rows, can't drop tables. **If agent goes rogue → blast radius = 1 row.** |

```
┌─────────────────────────────────────────────────────────────────┐
│  WITHOUT QREDIN (Static)           │  WITH QREDIN (Dynamic)     │
├────────────────────────────────────┼────────────────────────────┤
│ Agent asks: "Delete line 206"      │ Agent asks: "Delete line   │
│                                    │ 206 from table_5 in db_b"  │
├────────────────────────────────────┼────────────────────────────┤
│ System: "Here's admin password"    │ Qredin: "Checking policy..."│
│                                    │                              │
│ Agent now has:                     │ Policy checks:               │
│ ✓ DELETE any row                   │ ✓ Agent identity verified   │
│ ✓ DROP any table                   │ ✓ Exact operation: DELETE   │
│ ✓ TRUNCATE tables                  │ ✓ Exact table: table_5      │
│ ✓ SELECT all data                  │ ✓ Exact database: db_b      │
│ ✓ ALTER schema                     │ ✓ Exact row: id=206         │
│ ✓ GRANT permissions                │ ✓ Time: maintenance window  │
│                                    │ ✓ Risk score: low           │
├────────────────────────────────────┼────────────────────────────┤
│ **Blast radius: ENTIRE DATABASE**  │ **Blast radius: 1 ROW**     │
└────────────────────────────────────┴────────────────────────────┘
```

---

## How It Works (The Simple Version)

```
┌─────────────────────────────────────────────────────────────┐
│                    YOUR INFRASTRUCTURE                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌──────────────┐         ┌──────────────┐                │
│   │  AI Agent    │         │  Database B  │                │
│   │  (needs to   │         │  table_5     │                │
│   │   delete 1   │         │  row 206     │                │
│   │   row)       │         │              │                │
│   └──────┬───────┘         └──────┬───────┘                │
│          │                        │                          │
│          ▼                        ▼                          │
│   ┌──────────────────────────────────────────┐              │
│   │         NODE AGENT (on agent's server)   │              │
│   │  • Proves "I am AI-Agent-X on Server-Y"  │              │
│   │  • Requests: "DELETE db_b.table_5 id=206"│              │
│   │  • Gets dynamic SVID with EXACT perms    │              │
│   └──────────────────┬───────────────────────┘              │
│                      │                                      │
│          "Who am I?  │  "What EXACTLY can I do?"            │
│          ▼            ▼                                      │
│   ┌──────────────────────────────────────────┐              │
│   │         IDENTITY SERVER (brain)          │              │
│   │  1. VERIFIES: Is this really Agent X?    │              │
│   │  2. CHECKS: Is operation EXACTLY allowed?│              │
│   │  3. ISSUES SVID with ONE permission      │              │
│   │  4. EXPIRES in 1 hour (auto-renews)      │              │
│   └──────────────────────────────────────────┘              │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### The Decision Happens Every Single Request

```
AI Agent Request:
  • Who: spiffe://company.io/ai-agent-x (verified via attestation)
  • Where: Server-Y in us-east-1 (hardware attested)
  • When: 2024-01-15 14:30 UTC (maintenance window)
  • What: DELETE FROM db_b.table_5 WHERE id = 206
  • Context: Scheduled cleanup job, approved by human

Qredin Policy Engine Evaluates (in milliseconds):
  1. Is Agent X registered and attested? ✓
  2. Is Server-Y healthy and authorized? ✓
  3. Is this EXACT operation allowed? ✓ (DELETE db_b.table_5 id=206)
  4. Is this EXACT resource allowed? ✓ (db_b, table_5, row 206)
  5. Is this EXACT time allowed? ✓ (maintenance window)
  6. Any risk signals? ✓ (low - approved job)
  
RESULT: ISSUE SVID with permission: "DELETE db_b.table_5 WHERE id=206"
        Valid for: 1 hour
        Next request: Re-evaluated from scratch
```

---

## What Makes It "Dynamic" - The 8 Dimensions

| Dimension | Static (Old Way) | Dynamic (Qredin) |
|-----------|------------------|------------------|
| **Identity** | "Admin role" | "AI-Agent-X on Server-Y, attested via TPM" |
| **Location** | Ignored | "us-east-1, Server-Y, verified hardware" |
| **Time** | 24/7 | "Maintenance window: Jan 15, 14:00-16:00 UTC" |
| **Resource** | "Database B" | "db_b → table_5 → row WHERE id=206" |
| **Action** | "Full CRUD" | "DELETE ONLY (not SELECT, not UPDATE)" |
| **Conditions** | None | "Only during approved maintenance window" |
| **Risk** | Ignored | "Risk score < 0.1, human-approved job" |
| **Revocation** | Manual, hours | **Instant** (next request = denied) |

---

## Three Pillars That Make This Work

### 1. **Attestation** (Proving Identity Without Secrets)
```
Agent proves identity WITHOUT passwords/keys:
  ✓ Hardware TPM proves "I am Server-Y"
  ✓ Container hash proves "I am Agent-X binary"  
  ✓ Process PID proves "I am the running process"
  ✓ Registration record proves "Agent-X is allowed here"

NO SECRETS EXCHANGED. Identity = cryptographic proof.
```

### 2. **Dynamic Policy** (Code, Not Config)
```yaml
# Policy is evaluated AT REQUEST TIME
policy:
  - name: ai-agent-cleanup
    rules:
      - id: delete-specific-row
        effect: allow
        action: "DELETE"
        resource: "db_b.table_5"
        condition: "row.id == 206"          # EXACT row
        condition: "time in maintenance_window"
        condition: "job.approved_by == 'human'"
        condition: "risk_score < 0.1"
```
**Change policy → takes effect on NEXT request. No restart.**

### 3. **Short-Lived Credentials (SVIDs)**
```
SVID = "Permission slip" valid for 1 hour:
  • Identity: AI-Agent-X
  • Permission: DELETE db_b.table_5 WHERE id=206
  • Expiry: 1 hour (auto-renews if still valid)
  • Revocation: INSTANT via bundle update

Agent uses SVID → Database checks SVID → Allows ONLY that DELETE
```

---

## Architecture: The Flow

```
┌──────────────────────────────────────────────────────────────┐
│                     QREDIN: DYNAMIC IAM                       │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  AI AGENT                          DATABASE B                 │
│  ┌─────────────┐                  ┌──────────────────┐       │
│  │  Request:   │                  │  Receives SVID   │       │
│  │  DELETE     │                  │  Validates:      │       │
│  │  db_b.t5    │                  │  • Signature     │       │
│  │  id=206     │                  │  • Expiry        │       │
│  └──────┬──────┘                  │  • Permission    │       │
│         │                         │    = EXACT match │       │
│         │ 1. "Who am I?"          │  • Allows ONLY   │       │
│         ▼                         │    that DELETE   │       │
│  ┌─────────────┐                  └──────────────────┘       │
│  │ Node Agent  │                                                │
│  │ (attests)   │                                                │
│  └──────┬──────┘                                                │
│         │ 2. "Prove it"                                         │
│         ▼                                                        │
│  ┌──────────────────────────────────────────────┐              │
│  │              IDENTITY SERVER                  │              │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐   │              │
│  │  │ Attest   │→ │  Policy  │→ │   CA     │   │              │
│  │  │ Verify   │  │  Engine  │  │  Signs   │   │              │
│  │  └──────────┘  └──────────┘  └──────────┘   │              │
│  └──────────────────────────────────────────────┘              │
│                    │                    │                      │
│                    ▼                    ▼                      │
│  ┌──────────────────────────────────────────────────────┐    │
│  │  POSTGRES (State)          │  HSM (Keys - never leave) │ │
│  └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

---

## What You Get (That Matters)

| Feature | Your Scenario |
|---------|---------------|
| **Row-level permissions** | Agent ONLY touches row 206 |
| **Operation-specific** | DELETE only, not SELECT/UPDATE/DROP |
| **Time-bounded** | Only during maintenance window |
| **Auto-expiring** | SVID dies in 1 hour |
| **Instant revoke** | Kill switch = next request denied |
| **Full audit** | "Agent X deleted row 206 at 14:30:05" |
| **No admin creds** | Agent NEVER gets database password |
| **Policy as code** | Change rules → instant effect |

---

## Quick Start for Your Use Case

### 1. Define the Exact Permission
```yaml
# /etc/qredin/policies/ai-cleanup.yaml
policies:
  - name: ai-agent-row-deletion
    scope:
      tenant: platform
      environment: production
    rules:
      - id: delete-row-206-table-5-db-b
        effect: allow
        action: "DELETE"
        resource: "db_b.table_5"
        conditions:
          - "row.id == 206"                           # EXACT row
          - "time in maintenance_window"              # Time window
          - "identity == 'spiffe://co.io/ai-agent-x'" # Exact agent
          - "job.id == 'cleanup-2024-01-15'"          # Job ID
          - "risk_score < 0.1"                        # Low risk
```

### 2. Apply Policy (Instant)
```bash
qredin-operator --config server.yaml policy apply -f ai-cleanup.yaml
# Policy live immediately. Next agent request gets new permissions.
```

### 3. Agent Runs (No Code Changes)
```python
# Your AI agent code - unchanged!
# It just gets an SVID from local Node Agent
svid = get_svid_from_local_agent()  # Automatic

# Uses SVID for database connection
conn = db.connect(tls_config=svid)  # SVID has EXACT permission

# This works:
conn.execute("DELETE FROM table_5 WHERE id = 206")

# This FAILS (permission denied):
conn.execute("SELECT * FROM table_5")           # Not allowed
conn.execute("DELETE FROM table_5 WHERE id=207") # Wrong row
conn.execute("DROP TABLE table_5")               # Not allowed
```

---

## TL;DR for Everyone

> **Qredin gives AI agents (and servers/apps) permission for EXACTLY what they need, WHEN they need it, for HOW LONG they need it.**
> 
> - **Old way**: "Here's admin access, don't mess up" → **Disaster waiting**
> - **Qredin way**: "Here's permission to delete row 206 from table_5 in db_b between 2-4pm today" → **Safe by design**
> 
> - **Blast radius**: Entire database → **1 row**
> - **Credentials**: Permanent admin password → **Hourly expiring SVID**
> - **Revocation**: Manual, hours → **Instant (next request)**
> - **Policy changes**: Ticket, deploy, restart → **Live instantly**
> 
> **Developers**: Zero code changes. Your app gets an SVID with exact permissions.
> 
> **Security**: Sleep better. Rogue agent = 1 row affected, not entire database.
> 
> **Compliance**: "Who deleted row 206?" → Immutable audit log with exact context.

---

*Version: 3.0 | Qredin Dynamic IAM - Row-Level Permissions | For Qredin v1.x*