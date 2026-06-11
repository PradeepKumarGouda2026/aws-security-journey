# 📚 AWS Security Specialist — Days 49–52
## Section 1 (Theory) + Section 2 (Exam Deep Dive)
### Pradeep Kumar | Study Plan Continuation

---

> **Coverage:**
> - Day 49: Forensics on AWS
> - Day 50: AWS Systems Manager
> - Day 51: Automated Remediation
> - Day 52: Real-World Scenarios

---

# 📅 Day 49 — Forensics on AWS

---

# SECTION 1 — THEORY BLOCK

---

## 1.1 Service Overview & Purpose

### What is Digital Forensics on AWS?
Digital forensics on AWS is the process of **collecting, preserving, analyzing, and reporting** on digital evidence from AWS resources after a security incident — without contaminating evidence or disrupting production. AWS provides native capabilities that make forensics faster, more scalable, and auditable compared to traditional on-premises approaches.

### Forensic Principles Applied to AWS
```
Traditional Forensics Principle → AWS Implementation
──────────────────────────────────────────────────────
Preserve original evidence      → EBS snapshot (immutable copy)
Maintain chain of custody       → CloudTrail + S3 object versioning
Work on a copy, not the original→ Attach snapshot to forensics instance
Isolate subject from network    → Forensics security group (all blocked)
Use controlled environment      → Isolated forensics account + VPC
Document everything             → CloudTrail, SSM Session Manager logs
Time-stamp all actions          → CloudTrail event timestamps
```

### Exam Weight & Importance
- **Domain 1: Incident Response** (14%)
- Expect **2–3 questions** specifically on forensics
- Commonly tested: EBS snapshot forensics workflow, memory acquisition, forensics account pattern, chain of custody

---

## 1.2 Core Architecture — AWS Forensics Environment

```
┌──────────────────────────────────────────────────────────────┐
│                  AWS FORENSICS ARCHITECTURE                   │
│                                                              │
│  PRODUCTION ACCOUNT                                          │
│  ├── Compromised EC2 (isolated via forensics SG)            │
│  ├── EBS Volume (original — DO NOT MODIFY)                  │
│  └── EBS Snapshot ──────────────────────────────────┐       │
│                                                      │       │
│                                          Share snapshot      │
│                                                      │       │
│  FORENSICS ACCOUNT (isolated)            ◀───────────┘       │
│  ├── No internet gateway                                     │
│  ├── No peering to production                               │
│  ├── Forensics VPC (private only)                           │
│  ├── Forensics EC2 (analyst workstation)                    │
│  │   └── Attach snapshot as secondary volume               │
│  ├── S3 bucket (evidence store, versioned, locked)          │
│  └── CloudTrail (all analyst actions logged)                │
│                                                              │
│  EVIDENCE FLOW:                                              │
│  Original EBS → Snapshot → Cross-account share →            │
│  Volume in forensics account → Analysis → Findings in S3    │
└──────────────────────────────────────────────────────────────┘
```

---

## 1.3 Deep Dive — Every Sub-Topic

### A. EBS Snapshot Forensics (Core Workflow)

**Step-by-step forensic disk acquisition:**

```
1. ISOLATE (before snapshot):
   └── Replace compromised EC2 security group with forensics SG
       (all inbound/outbound blocked)

2. SNAPSHOT:
   └── aws ec2 create-snapshot \
         --volume-id vol-XXXXXXXX \
         --description "FORENSICS-$(date +%Y%m%d-%H%M%S)-IR-TICKET-1234"
   └── Tag snapshot: Evidence=True, CaseID=IR-1234, Analyst=PradeepKumar

3. LOCK THE SNAPSHOT (prevent modification):
   └── aws ec2 enable-snapshot-block-public-access
   └── Use S3 Object Lock style: don't share write access to snapshot

4. SHARE TO FORENSICS ACCOUNT:
   └── aws ec2 modify-snapshot-attribute \
         --snapshot-id snap-XXXXXXXX \
         --attribute createVolumePermission \
         --operation-type add \
         --user-ids FORENSICS-ACCOUNT-ID

5. IN FORENSICS ACCOUNT — CREATE VOLUME:
   └── aws ec2 create-volume \
         --snapshot-id snap-XXXXXXXX \
         --availability-zone ap-south-1a

6. ATTACH TO FORENSICS EC2 (as secondary — NOT boot volume):
   └── aws ec2 attach-volume \
         --volume-id vol-FORENSICS \
         --instance-id i-FORENSICS-EC2 \
         --device /dev/sdf

7. MOUNT READ-ONLY (critical — never write to evidence):
   └── mount -o ro,noexec /dev/xvdf1 /mnt/evidence

8. ANALYZE:
   └── File system analysis, log review, malware artifacts
   └── Hash all evidence files (sha256sum)

9. EXPORT FINDINGS TO S3 (versioned, locked bucket):
   └── Evidence preserved with integrity
```

⚠️ **Gotcha:** Always mount the evidence volume **read-only** (`-o ro`). Writing to the evidence volume contaminates it and may invalidate chain of custody.

⚠️ **Gotcha:** Tag snapshots at creation time with case metadata — you cannot rely on memory for evidence association later.

---

### B. Memory Forensics on AWS

Unlike traditional forensics, EC2 instances don't expose raw memory access. Options:

| Method | How | Limitation |
|---|---|---|
| SSM Run Command | Run memory dump tools (LiME, winpmem) via SSM | Requires SSM agent, runs in OS context |
| EC2 hibernation | Hibernate instance → memory written to EBS | Not all instance types support hibernation |
| OS-level dumps | `/proc/kcore`, `dd` of `/dev/mem` | Limited by OS permissions |
| Forensic AMI with memory tools | Pre-built AMI with LiME/Volatility | Most reliable if pre-planned |

**Best practice:** Capture memory BEFORE stopping or isolating if volatile evidence is needed. Memory is lost on stop/terminate.

⚠️ **Gotcha:** Memory evidence is **volatile** — it is lost when the instance is stopped or terminated. If memory forensics is needed, capture it before any power state change.

---

### C. Log Sources for Forensics

| Log Source | What It Tells You | Location |
|---|---|---|
| CloudTrail | All AWS API calls (who, what, when, from where) | S3 / CloudWatch Logs |
| VPC Flow Logs | Network connections (src/dst IP, port, bytes) | S3 / CloudWatch Logs |
| CloudWatch Logs | Application logs, OS logs, Lambda output | CloudWatch Logs |
| S3 Access Logs | Object-level S3 access (bucket + key) | S3 bucket |
| CloudTrail Data Events | S3 GetObject/PutObject, Lambda Invoke | S3 |
| ALB Access Logs | HTTP requests to load balancer | S3 |
| Route53 Resolver Logs | DNS queries from VPC resources | CloudWatch / S3 |
| GuardDuty Findings | Analyzed threat intelligence findings | GuardDuty / S3 |
| SSM Session Manager Logs | All commands run in SSM sessions | S3 / CloudWatch Logs |

**Forensic query example using Athena:**
```sql
-- Find all API calls made by a compromised access key
SELECT eventtime, eventname, sourceipaddress, useragent,
       requestparameters, responseelements
FROM cloudtrail_logs
WHERE useridentity.accesskeyid = 'AKIAEXAMPLECOMPROMISED'
  AND eventtime BETWEEN '2024-01-01T00:00:00Z' AND '2024-01-07T23:59:59Z'
ORDER BY eventtime;
```

---

### D. Chain of Custody on AWS

Chain of custody documents the handling of evidence from collection to court/report.

**AWS mechanisms for chain of custody:**

| Requirement | AWS Implementation |
|---|---|
| Integrity proof | SHA-256 hash of snapshots/exported files |
| Immutability | S3 Object Lock (WORM), snapshot read-only |
| Access audit | CloudTrail logging all forensics account actions |
| Timestamping | CloudTrail event timestamps (UTC) |
| Authorization | IAM policies — only forensics team accesses forensics account |
| Documentation | SSM Session Manager logs all analyst CLI commands |

---

### E. Forensics Account Pattern

The forensics account is a **separate AWS account** used exclusively for incident investigation.

**Why separate account:**
- SCPs can lock it down completely (no internet, no peering to prod)
- Compromised credentials in production can't reach forensics account
- Analyst mistakes can't affect production
- Clear audit boundary — all forensics actions logged separately
- Evidence S3 bucket in forensics account isolated from production

**Forensics account setup:**
```
Forensics Account:
├── No Internet Gateway (forensics VPC is fully private)
├── No VPC peering to production accounts
├── VPC endpoints only (EC2, S3, SSM, KMS)
├── S3 evidence bucket: versioned + Object Lock + access logging
├── KMS CMK: forensics-only key for evidence encryption
├── IAM: only forensics team roles have access
├── CloudTrail: enabled (log all analyst actions)
└── SCP: deny all except forensics-required services
```

---

### F. Automated Forensics Triggering

**EventBridge → Step Functions IR automation:**
```
GuardDuty finding
    │
    ▼ EventBridge Rule
Step Functions Workflow:
    ├── 1. Create EBS snapshot of affected instance
    ├── 2. Tag snapshot with case metadata
    ├── 3── Share snapshot to forensics account
    ├── 4. Isolate instance (swap security group)
    ├── 5. Capture instance metadata (tags, SG, IAM role)
    ├── 6. Notify IR team via SNS
    └── 7. Create ticket in ITSM (Lambda → API)
```

This automation runs within seconds of GuardDuty finding — before a human even reads the alert.

---

## 1.4 Comparison Tables

### Evidence Preservation Methods

| Method | Volatility | Integrity | Use Case |
|---|---|---|---|
| EBS Snapshot | Non-volatile | ✅ Immutable copy | Disk forensics |
| Memory dump (SSM) | Volatile (capture live) | Medium | Malware analysis |
| VPC Flow Logs | Non-volatile (S3) | ✅ | Network forensics |
| CloudTrail S3 | Non-volatile | ✅ Log file validation | API forensics |
| CloudWatch Logs | Non-volatile | Medium | App log forensics |

### Forensics Tooling on AWS

| Tool | Purpose |
|---|---|
| Amazon Athena | SQL query over CloudTrail/VPC Flow S3 logs |
| Amazon Detective | Relationship/entity visualization |
| AWS Security Hub | Finding aggregation and triage |
| SSM Session Manager | Live instance access without SSH |
| SSM Run Command | Remote forensic tool execution |
| GuardDuty | Initial finding with threat intel context |
| Macie | Identify sensitive data in accessed S3 objects |

---

## 1.5 Security & Compliance Angles

### Forensics Readiness Checklist

1. CloudTrail org trail enabled (all regions, all accounts)
2. VPC Flow Logs enabled for all VPCs
3. S3 data events enabled in CloudTrail
4. Forensics account pre-provisioned with forensics VPC
5. Forensics EC2 AMI with tools pre-installed (Volatility, sleuthkit, etc.)
6. S3 evidence bucket with Object Lock configured
7. Automated snapshot/isolation playbook (Step Functions) ready
8. Athena tables created over CloudTrail and VPC Flow Log S3 buckets
9. IR team has IAM roles in forensics account

### Compliance Requirements

| Framework | Forensics Requirement |
|---|---|
| ISO 27001 | A.16.1.7 — Collection of evidence |
| NIST SP 800-86 | Full forensics guide for IT systems |
| PCI-DSS | Req 12.10.5 — Evidence collection procedures |
| CERT-In (India) | 6-hour reporting, 180-day log retention |

---

## 1.6 Integration Patterns

```
┌──────────────────────────────────────────────────────┐
│            FORENSICS INTEGRATION MAP                  │
├──────────────────┬───────────────────────────────────┤
│ GuardDuty        │ Trigger for forensics automation   │
│ EventBridge      │ Route findings to Step Functions   │
│ Step Functions   │ Orchestrate forensics workflow     │
│ EC2 Snapshots    │ Primary disk evidence              │
│ SSM              │ Live access + command execution    │
│ Athena           │ Log querying at scale              │
│ S3 Object Lock   │ Evidence immutability (WORM)       │
│ KMS              │ Evidence encryption at rest        │
│ CloudTrail       │ Analyst action audit               │
│ Detective        │ Entity relationship investigation  │
│ VPC Flow Logs    │ Network evidence                   │
│ Macie            │ Sensitive data in accessed objects │
└──────────────────┴───────────────────────────────────┘
```

---

# SECTION 2 — EXAM DEEP DIVE

---

## 2.1 Scenario-Based Q&A (20 Questions)

---

**Q1.** A forensic analyst needs to examine the disk of a compromised EC2 instance without modifying evidence or affecting production. What is the correct procedure?

A) SSH into the instance and run investigation tools directly  
B) Create an EBS snapshot → share to forensics account → create volume → attach read-only to forensics EC2  
C) Stop the instance and attach its volume directly  
D) Terminate and restore from backup  

**Answer: B**

The correct forensics workflow preserves evidence integrity: snapshot creates an immutable copy, sharing to a forensics account maintains isolation, attaching read-only ensures no contamination. SSH directly modifies volatile state. Stopping then attaching may alter evidence. Termination destroys it.

---

**Q2.** An analyst mounts a forensic EBS volume and runs `mount /dev/xvdf1 /mnt/evidence` (without read-only flag). What is the forensic concern?

A) The volume won't mount  
B) The OS may write metadata (access timestamps, journal entries) to the evidence volume — contaminating it  
C) The volume will be deleted  
D) No concern — mounting doesn't modify data  

**Answer: B**

Mounting a filesystem without `ro` (read-only) flag allows the OS to write: access timestamps (`atime`), journal recovery entries, and swap data. This modifies the evidence, potentially invalidating chain of custody and obscuring the original filesystem state. Always mount with `-o ro,noexec`.

---

**Q3.** You need to query 6 months of CloudTrail logs to identify all actions taken by a compromised IAM role. The logs are in S3. What is the most efficient approach?

A) Download all log files and search with grep  
B) Create an Athena table over the S3 CloudTrail prefix and query with SQL  
C) Use CloudTrail Event History in the console  
D) Enable GuardDuty retrospective analysis  

**Answer: B**

Athena can query terabytes of compressed CloudTrail logs in S3 using SQL in seconds. CloudTrail Event History is limited to 90 days and read events only. Grep requires downloading gigabytes of data locally. GuardDuty doesn't provide historical API call querying.

---

**Q4.** Memory forensics is required on a compromised EC2 instance. The instance has just been isolated (security group changed to block all traffic). What is the concern about memory evidence?

A) Memory is safe — isolation preserves it  
B) Memory evidence is volatile — it is only preserved as long as the instance remains RUNNING. Stopping or terminating will lose it.  
C) Memory is automatically snapshotted by GuardDuty  
D) Memory can be recovered from EBS after termination  

**Answer: B**

RAM is volatile — it exists only while the instance is powered on. Isolation (SG change) doesn't affect memory. The instance must remain RUNNING for memory capture. Use SSM Run Command to execute memory capture tools (e.g., LiME for Linux) immediately after isolation, before any stop/restart.

---

**Q5.** Why is a dedicated forensics AWS account recommended over performing forensics in the production account?

A) Forensics tools only work in separate accounts  
B) Isolation prevents compromised production credentials from reaching forensic evidence; analyst mistakes can't affect production; clean audit trail; evidence integrity maintained  
C) It is cheaper  
D) AWS requires it by policy  

**Answer: B**

Separate forensics account: (1) compromised production IAM credentials can't access forensics evidence, (2) analyst's investigative actions are audited separately from production, (3) accidental commands (rm -rf) can't hit production, (4) clear chain of custody boundary. This is the AWS Well-Architected security best practice.

---

**Q6.** What AWS feature provides immutable, tamper-proof storage for forensic evidence in S3?

A) S3 versioning only  
B) S3 Object Lock with WORM (Write Once Read Many) mode  
C) S3 encryption with CMK  
D) S3 bucket policy with Deny Delete  

**Answer: B**

**S3 Object Lock** (WORM) prevents objects from being deleted or overwritten for a specified retention period — even by root/admin. In Governance mode (admins can override with specific permissions) or Compliance mode (no one can override — true WORM). Critical for forensic evidence that must be legally defensible.

---

**Q7.** A forensics analyst needs to run commands on an isolated EC2 instance (security group blocks all traffic). No SSH keys are available. How is this possible?

A) It's not possible with all traffic blocked  
B) AWS SSM Session Manager — communicates via outbound HTTPS to SSM service endpoints, not through the instance's blocked inbound rules  
C) Via AWS console serial access  
D) By temporarily opening port 22  

**Answer: B**

SSM Session Manager uses outbound HTTPS from the SSM agent to the SSM service endpoint. The forensics security group needs to allow **outbound** HTTPS (port 443) to SSM endpoints (or use a VPC endpoint for SSM). No inbound ports needed. No SSH keys needed. All session activity is logged.

---

**Q8.** Which log source would you query to determine if a compromised EC2 instance exfiltrated data via DNS tunneling?

A) CloudTrail  
B) VPC Flow Logs  
C) Route 53 Resolver Query Logs  
D) S3 Access Logs  

**Answer: C**

**Route 53 Resolver Query Logs** capture all DNS queries made by resources in the VPC. DNS tunneling (data encoded in DNS queries to attacker-controlled domains) is only visible in DNS logs — VPC Flow Logs only show IP/port traffic, not DNS query content. CloudTrail logs AWS API calls, not DNS.

---

**Q9.** During forensics, you need to prove that an EBS snapshot has not been modified since collection. What technique provides this?

A) Tagging the snapshot  
B) SHA-256 hash of the snapshot data at collection time, stored separately in evidence log  
C) Encrypting the snapshot  
D) Taking a second snapshot  

**Answer: B**

Cryptographic hashing (SHA-256) of the evidence at collection time creates a fingerprint. If the hash matches at any later point, the evidence is unchanged. Store the hash in a separately controlled, immutable location (e.g., a write-once log). This is the standard forensic integrity verification technique.

---

**Q10.** What does Amazon Detective provide that GuardDuty alone does not?

A) More threat types detection  
B) Visual relationship mapping between AWS entities — showing connections between IP addresses, IAM users, EC2 instances, API calls over time  
C) More frequent scanning  
D) Network packet capture  

**Answer: B**

GuardDuty detects and generates findings. Detective takes those findings and the underlying data (CloudTrail, VPC Flow, GuardDuty) and builds a **behavior graph** — visual maps of entity relationships, activity timelines, and statistical baselines. This dramatically speeds up root cause analysis.

---

**Q11.** A forensics team needs to share an EBS snapshot from the production account to the forensics account. What is required?

A) The forensics account must be in the same region  
B) Modify the snapshot's `createVolumePermission` attribute to add the forensics account ID  
C) The forensics account must be in the same Organization  
D) Only same-account snapshot operations are supported  

**Answer: B**

EBS snapshots can be shared cross-account using `ec2:ModifySnapshotAttribute` to add the target account ID to `createVolumePermission`. The forensics account can then create a volume from the shared snapshot in the same region. Cross-region sharing requires copying the snapshot first.

---

**Q12.** VPC Flow Logs show repeated outbound connections from EC2 instance i-abc123 to 185.x.x.x:443. GuardDuty flags this as C&C traffic. What additional log source confirms what data was sent?

A) CloudTrail  
B) VPC Flow Logs already show this  
C) Application logs in CloudWatch Logs + SSL inspection (if available) — Flow Logs only show bytes transferred, not content  
D) Config  

**Answer: C**

VPC Flow Logs show **metadata** (src/dst IP, port, bytes, accept/reject) — NOT packet content. To determine what data was sent, you need application-level logs (CloudWatch Logs) and potentially SSL/TLS inspection via a proxy or firewall. Flow Logs confirm the connection occurred and volume transferred.

---

**Q13.** What is the purpose of tagging forensic snapshots with case metadata at creation time?

A) Required by AWS for billing  
B) Enables filtering, searching, and chain of custody documentation; tags become part of the immutable snapshot record in CloudTrail  
C) Improves snapshot performance  
D) Required for cross-account sharing  

**Answer: B**

Forensic tags (CaseID, Analyst, DateTime, InstanceID) serve as documentation embedded with the evidence. The `ec2:CreateSnapshot` CloudTrail event records both the snapshot creation and its tags — creating an auditable chain of custody record. Later, analysts can filter snapshots by case ID across accounts.

---

**Q14.** An analyst accidentally terminates the compromised EC2 instance before capturing memory. What evidence is still available?

A) Nothing — all evidence is lost  
B) EBS snapshot (if created before termination) + CloudTrail API logs + VPC Flow Logs + CloudWatch Logs (if configured with log group retention)  
C) Only CloudTrail  
D) Memory is preserved in the EBS snapshot  

**Answer: B**

Memory is lost on termination. However: (1) EBS snapshot if taken before termination preserves disk, (2) CloudTrail shows all API calls, (3) VPC Flow Logs show network behavior, (4) CloudWatch Logs show application output if the agent was running. The lesson: always capture memory first, then snapshot, then isolate, then terminate.

---

**Q15.** A company needs to meet CERT-In (India) requirements for log retention. What is the minimum retention period required?

A) 30 days  
B) 90 days  
C) 180 days  
D) 365 days  

**Answer: C**

**CERT-In** (Indian Computer Emergency Response Team) requires organizations to retain logs for a minimum of **180 days** and report incidents within 6 hours of detection. Configure S3 lifecycle policies on CloudTrail, VPC Flow Log, and other log buckets for at least 180-day retention.

---

**Q16.** A forensics analyst uses SSM Session Manager to investigate a live EC2 instance. Why is this preferable to SSH for forensics?

A) SSM is faster  
B) SSM Session Manager logs all commands and output to S3/CloudWatch Logs automatically — providing a complete audit trail of analyst actions; no inbound ports needed  
C) SSM is encrypted; SSH is not  
D) SSM works on Windows only  

**Answer: B**

SSM Session Manager provides: automatic session logging (all keystrokes + output to S3 or CloudWatch Logs), no open inbound ports (reduces attack surface), IAM-controlled access (no SSH key management), and CloudTrail records session start/end. This creates a complete chain of custody for analyst actions.

---

**Q17.** During forensic analysis, you discover the attacker created a Lambda function as a persistence mechanism. What logs reveal this?

A) VPC Flow Logs  
B) CloudTrail — `lambda:CreateFunction` event with caller identity, timestamp, and function configuration  
C) CloudWatch Metrics  
D) Config snapshots  

**Answer: B**

CloudTrail captures all AWS API calls including `lambda:CreateFunction`. The event includes: caller ARN (the compromised identity), function name, runtime, code location, execution role, and timestamp. This reveals both the persistence mechanism and the actions taken by the compromised credential.

---

**Q18.** What S3 Object Lock mode prevents anyone — including root — from deleting forensic evidence for the defined retention period?

A) Governance Mode  
B) Compliance Mode  
C) Legal Hold  
D) Versioning Lock  

**Answer: B**

**Compliance Mode** is the strictest S3 Object Lock mode. No user (including root, account admin) can delete or overwrite objects or change the retention period until it expires. **Governance Mode** allows users with specific permissions to override. **Legal Hold** has no expiry date but can be removed by users with `s3:PutObjectLegalHold`.

---

**Q19.** An incident occurred in ap-south-1. CloudTrail is enabled only for ap-south-1. Later it is found some attacker activity occurred in us-east-1 (creating IAM users — a global service). Will this be in CloudTrail?

A) No — CloudTrail only covers ap-south-1  
B) Yes — IAM events are global and are captured in us-east-1 trail AND the trail for the home region (us-east-1 for global services)  
C) IAM events are not captured in CloudTrail  
D) Yes — all regions always log to ap-south-1  

**Answer: B**

IAM, STS, Route53, and other global services log to the **us-east-1 region** in CloudTrail (the global service region). If you only have a regional trail in ap-south-1, you will MISS IAM events. This is why **multi-region CloudTrail** (or an organization trail) is critical — it captures global service events.

---

**Q20.** What is the recommended order of operations for EC2 forensics to maximize evidence collection?

A) Terminate → snapshot → analyze  
B) Isolate (SG) → capture memory → create EBS snapshot → investigate live (SSM) → terminate  
C) Stop → snapshot → terminate → analyze  
D) Snapshot → terminate → restore → analyze  

**Answer: B**

Correct order:
1. **Isolate** (forensics SG) — contain immediately, stop C&C
2. **Capture memory** — volatile, must be done while running
3. **Create EBS snapshot** — non-volatile disk preservation
4. **Investigate live** (SSM) — while instance still running
5. **Terminate** — only after all evidence captured

Stopping before snapshot risks losing some volatile state. Terminating first destroys memory and may disrupt snapshot consistency.

---

## 2.2 Common Exam Traps & Distractors (10)

**Trap 1: Terminate first for containment**
> ❌ Wrong: "Terminate the instance to stop the attack"
> ✅ Right: ISOLATE (forensics SG), THEN terminate AFTER evidence collection

**Trap 2: Mount without read-only = no problem**
> ❌ Wrong: "Mounting the forensic volume normally is fine"
> ✅ Right: Always mount `ro,noexec` — prevents OS from writing atime/journal to evidence

**Trap 3: Memory survives instance stop**
> ❌ Wrong: "Stop the instance and capture memory later"
> ✅ Right: Memory is lost on STOP. Capture memory while instance is RUNNING.

**Trap 4: S3 Governance Mode = true WORM**
> ❌ Wrong: "Governance mode prevents all deletion"
> ✅ Right: Governance mode can be overridden by privileged users. Use Compliance mode for true WORM.

**Trap 5: CloudTrail Event History = complete log history**
> ❌ Wrong: "CloudTrail Event History shows all API calls for investigation"
> ✅ Right: Event History = 90 days, read events only. Full forensic queries need Athena on S3.

**Trap 6: VPC Flow Logs show packet content**
> ❌ Wrong: "Flow Logs show what data was exfiltrated"
> ✅ Right: Flow Logs show metadata only (IP, port, bytes). Not packet content.

**Trap 7: IAM events logged to regional trail only**
> ❌ Wrong: "ap-south-1 CloudTrail captures all IAM events"
> ✅ Right: IAM/STS/Route53 are global services — logged to us-east-1. Need multi-region trail.

**Trap 8: Detective = GuardDuty replacement**
> ❌ Wrong: "Use Detective instead of GuardDuty"
> ✅ Right: GuardDuty detects threats. Detective investigates and visualizes relationships. Complementary.

**Trap 9: SSM Session Manager needs inbound port 22**
> ❌ Wrong: "Open port 22 for SSM Session Manager"
> ✅ Right: SSM uses outbound HTTPS (443) only. No inbound ports needed.

**Trap 10: Snapshot sharing requires same Organization**
> ❌ Wrong: "Can only share snapshots within same AWS Organization"
> ✅ Right: EBS snapshots can be shared to any AWS account ID — no org requirement

---

## 2.3 Key Facts Cheat Sheet

```
┌────────────────────────────────────────────────────────────┐
│          AWS FORENSICS — EXAM CHEAT SHEET                  │
├──────────────────────────────────┬─────────────────────────┤
│ Evidence preservation tool       │ EBS Snapshot            │
│ Immutable evidence storage       │ S3 Object Lock          │
│ True WORM (no override)          │ Compliance Mode         │
│ Admin-overrideable WORM          │ Governance Mode         │
│ Mount flag for evidence          │ -o ro,noexec            │
│ Memory volatility                │ Lost on stop/terminate  │
│ Large-scale log query            │ Amazon Athena (S3)      │
│ Entity relationship viz          │ Amazon Detective        │
│ Live access without SSH          │ SSM Session Manager     │
│ DNS query log source             │ Route53 Resolver Logs   │
│ Session logging (analyst actions)│ SSM Session Manager     │
│ Network metadata source          │ VPC Flow Logs           │
│ IAM event region                 │ us-east-1 (global svc)  │
│ CERT-In log retention (India)    │ 180 days                │
│ CERT-In incident reporting       │ 6 hours                 │
│ Chain of custody proof           │ SHA-256 hash + CT logs  │
│ Forensics account purpose        │ Isolated analysis env   │
│ Cross-account snapshot sharing   │ ModifySnapshotAttribute │
│ Forensic order (EC2)             │ Isolate→Mem→Snap→Live→Term│
└──────────────────────────────────┴─────────────────────────┘
```

---

## 2.4 Elimination Strategies

**Strategy 1: Disk forensics → EBS Snapshot (read-only)**
Examine compromised disk → eliminate "SSH directly" → **EBS snapshot → attach read-only to forensics EC2**

**Strategy 2: Evidence immutability → S3 Object Lock Compliance**
Legally defensible evidence storage → eliminate "versioning alone" → **S3 Object Lock (Compliance mode)**

**Strategy 3: Memory capture → before stop/terminate**
Need memory evidence → eliminate "stop first" → **capture while RUNNING via SSM Run Command**

**Strategy 4: Large log query → Athena**
90+ days CloudTrail analysis → eliminate "Event History" → **Athena on S3 CloudTrail data**

**Strategy 5: DNS forensics → Route53 Resolver Logs**
DNS tunneling / C&C via DNS → eliminate "Flow Logs" → **Route53 Resolver Query Logs**

**Strategy 6: Live access to isolated instance → SSM Session Manager**
No SSH, all traffic blocked → eliminate "open port 22" → **SSM Session Manager (outbound 443 only)**

---

---

# 📅 Day 50 — AWS Systems Manager

---

# SECTION 1 — THEORY BLOCK

---

## 1.1 Service Overview & Purpose

### What is AWS Systems Manager?
AWS Systems Manager (SSM) is an **operations and management service** that provides unified operational visibility and control across AWS resources. From a security perspective, SSM is essential for: patch management, secure remote access (no SSH), configuration compliance, secrets retrieval, and automated remediation.

### Why It Matters for Security
```
Security Use Cases for SSM:
├── Patch Manager: keep EC2/hybrid instances patched (CVE remediation)
├── Session Manager: SSH-less secure access (no open ports)
├── Run Command: execute scripts remotely for forensics/remediation
├── Parameter Store: store configs and secrets securely
├── Automation: orchestrate multi-step remediation runbooks
├── Compliance: assess OS configuration vs. baseline
├── Inventory: track installed software (detect unauthorized)
└── State Manager: enforce desired OS configuration state
```

### Exam Weight & Importance
- **Domain 3: Infrastructure Security** + **Domain 1: Incident Response**
- Expect **3–4 questions** on SSM
- Commonly tested: Session Manager (vs SSH), Patch Manager, Parameter Store, Run Command for IR

---

## 1.2 Core Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                  AWS SYSTEMS MANAGER                          │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                 SSM AGENT (on EC2/hybrid)             │   │
│  │  Communicates outbound HTTPS to SSM endpoints         │   │
│  │  No inbound ports required                            │   │
│  └──────────────────────────────────────────────────────┘   │
│                           │                                  │
│          ┌────────────────┼────────────────┐                │
│          ▼                ▼                ▼                │
│  ┌──────────────┐ ┌─────────────┐ ┌──────────────┐        │
│  │Session Manager│ │Patch Manager│ │ Run Command  │        │
│  │(secure shell) │ │(CVE patches)│ │(remote exec) │        │
│  └──────────────┘ └─────────────┘ └──────────────┘        │
│          ▼                ▼                ▼                │
│  ┌──────────────┐ ┌─────────────┐ ┌──────────────┐        │
│  │  Parameter   │ │  Automation │ │  Compliance  │        │
│  │    Store     │ │  (runbooks) │ │  (Inspector) │        │
│  └──────────────┘ └─────────────┘ └──────────────┘        │
└──────────────────────────────────────────────────────────────┘
```

---

## 1.3 Deep Dive — Every Sub-Topic

### A. Session Manager (Security Focus)

Provides interactive shell access to EC2 instances **without SSH**.

**Security advantages over SSH:**

| Aspect | SSH | Session Manager |
|---|---|---|
| Inbound ports | Port 22 open | No inbound ports |
| Key management | SSH key files | IAM policies |
| Session logging | Manual syslog | Automatic (S3/CW Logs) |
| Access control | Key possession | IAM + CloudTrail |
| Bastion host | Required for private instances | Not needed |
| Audit trail | Limited | Full CloudTrail record |

**Session logging configuration (critical for IR/forensics):**
- Log session input/output to **S3** (with KMS encryption)
- Log to **CloudWatch Logs**
- CloudTrail records session start/end with user identity

**IAM permissions for Session Manager:**
```json
{
  "Effect": "Allow",
  "Action": ["ssm:StartSession"],
  "Resource": "arn:aws:ec2:region:account:instance/i-*",
  "Condition": {
    "StringEquals": { "ssm:resourceTag/Environment": "Production" }
  }
}
```

⚠️ **Gotcha:** Session Manager requires the **SSM Agent** running on the instance AND an **instance profile** with `AmazonSSMManagedInstanceCore` policy. Without either, sessions won't work.

---

### B. Patch Manager

Automates OS and application patching across EC2 and hybrid instances.

**Key concepts:**

| Concept | Description |
|---|---|
| Patch Baseline | Defines which patches are approved/rejected |
| Patch Group | Tag-based instance grouping (e.g., `Patch Group: Production`) |
| Maintenance Window | Scheduled time for patching operations |
| Compliance Report | Post-patching compliance status |

**AWS-provided default baselines:**
- `AWS-AmazonLinux2DefaultPatchBaseline`
- `AWS-WindowsServerDefaultPatchBaseline`
- `AWS-UbuntuDefaultPatchBaseline`

**Custom baseline example:**
```
Baseline: Production-Critical
├── Auto-approve: Critical patches after 0 days
├── Auto-approve: Important patches after 7 days
├── Reject: KB123456 (known problematic patch)
└── Include: Security + BugFix categories
```

⚠️ **Gotcha:** Patch Manager **does not reboot** instances by default after patching. Set `RebootOption: RebootIfNeeded` in the run command to handle kernel patches that require reboot.

---

### C. Run Command

Execute commands or scripts on one or many instances without SSH.

**Security use cases:**

| Use Case | SSM Document |
|---|---|
| Collect forensic artifacts | `AWS-RunShellScript` |
| Install/remove software | `AWS-RunShellScript` |
| Rotate application credentials | `AWS-RunShellScript` |
| Check running processes | `AWS-RunShellScript` |
| Configure OS security settings | `AWS-ApplyPatchBaseline` |
| Join Active Directory | `AWS-JoinDirectoryServiceDomain` |

**Rate limiting for large fleets:**
- `MaxConcurrency`: percentage or count of instances to target simultaneously
- `MaxErrors`: stop execution after N errors (prevents runaway changes)

---

### D. Parameter Store (Security Deep Dive)

Hierarchical key-value store for configuration and secrets.

**Two tiers:**

| Feature | Standard | Advanced |
|---|---|---|
| Cost | Free | $0.05/param/month |
| Max size | 4KB | 8KB |
| Throughput | 40 TPS | 1,000 TPS |
| Parameter policies | ❌ | ✅ (expiry, notifications) |

**Parameter types:**

| Type | Encryption | Use For |
|---|---|---|
| String | None | Non-sensitive config |
| StringList | None | Comma-separated values |
| SecureString | KMS | Passwords, API keys |

**Hierarchical organization:**
```
/prod/app1/db/host
/prod/app1/db/port
/prod/app1/db/password    ← SecureString
/staging/app1/db/host
/staging/app1/db/password ← SecureString
```

**IAM scoped to path:**
```json
{
  "Effect": "Allow",
  "Action": "ssm:GetParameter",
  "Resource": "arn:aws:ssm:region:account:parameter/prod/app1/*"
}
```

⚠️ **Gotcha:** Parameter Store SecureString requires `kms:Decrypt` permission in addition to `ssm:GetParameter`. Missing KMS permission = access denied even with SSM permission.

---

### E. Automation (Runbooks)

SSM Automation executes multi-step operational and security runbooks.

**Security automation examples:**

| Runbook | Purpose |
|---|---|
| `AWS-DisablePublicS3Bucket` | Block public access on S3 bucket |
| `AWS-StopEC2Instance` | Stop non-compliant instance |
| `AWS-CreateSnapshot` | Forensic snapshot creation |
| `AWS-EnableCloudTrail` | Re-enable disabled CloudTrail |
| `AWS-RevokeSecurityGroupIngress` | Remove insecure SG rule |
| `AWS-IsolateEC2Instance` | Attach isolating security group |

**Custom automation document (YAML):**
```yaml
schemaVersion: '0.3'
description: Isolate compromised EC2 instance
parameters:
  InstanceId:
    type: String
mainSteps:
  - name: IsolateInstance
    action: aws:executeAwsApi
    inputs:
      Service: ec2
      Api: ModifyInstanceAttribute
      InstanceId: "{{ InstanceId }}"
      Groups:
        - sg-forensics-all-blocked
```

---

### F. Compliance (SSM)

Scans instances for compliance against patch baselines and custom rules.

- Reports per-instance compliance: COMPLIANT / NON_COMPLIANT
- Integrates with **Security Hub** (findings forwarded)
- Uses **AWS Config** for resource inventory

---

## 1.4 Comparison Tables

### SSM Session Manager vs Bastion Host vs SSH

| Aspect | SSH Direct | Bastion Host | Session Manager |
|---|---|---|---|
| Open inbound ports | Port 22 on instance | Port 22 on bastion | None required |
| Key management | Per-instance SSH keys | Bastion key | IAM policies |
| Cost | Free (EC2) | Additional EC2 cost | Free |
| Session logging | Manual | Manual | Automatic |
| Private instance access | VPN/bastion needed | Yes | Yes (via SSM) |
| Audit trail | Limited | Limited | Full CloudTrail |
| Security | Medium | Medium | High |

### Parameter Store vs Secrets Manager (Revisit in SSM context)

| Feature | SSM Parameter Store | Secrets Manager |
|---|---|---|
| Native ECS injection | ✅ (ARN reference) | ✅ (ARN reference) |
| Lambda env var | ✅ via code | ✅ via code |
| EC2 user data | ✅ `aws ssm get-parameter` | ✅ via CLI |
| Auto-rotation | ❌ | ✅ |
| Cross-account | ❌ natively | ✅ resource policy |

---

## 1.5 Security & Compliance Angles

### SSM Hardening Checklist

1. Enable SSM Session Manager logging (S3 + CloudWatch Logs)
2. Remove port 22 from all production security groups — use Session Manager
3. Require MFA for Session Manager (`aws:MultiFactorAuthPresent: true` condition)
4. Patch Manager: target all instances with Patch Groups + Maintenance Windows
5. Parameter Store: use SecureString with CMK for all sensitive values
6. Use IAM conditions to restrict Session Manager to specific instance tags
7. Enable SSM Inventory to track installed software

### Compliance Mapping

| Framework | SSM Control |
|---|---|
| CIS AWS Benchmark | Patch management, no open SSH |
| PCI-DSS | 6.3 (patching), 2.2 (no open ports), 10.x (logging) |
| NIST 800-53 | SI-2 (patch), AC-17 (remote access), AU-2 (audit) |
| ISO 27001 | A.12.6 (patch), A.9.4 (access control) |

### Common Misconfigurations

1. No session logging configured — no audit trail for analyst actions
2. Port 22 still open alongside Session Manager — redundant attack surface
3. Parameter Store SecureString missing KMS decrypt permission
4. Patch Manager without reboot option — kernel patches ineffective
5. Run Command with no MaxErrors — one bad command runs on entire fleet
6. SSM agent not installed on all instances — gaps in coverage

---

## 1.6 Integration Patterns

```
┌──────────────────────────────────────────────────────┐
│              SSM INTEGRATION MAP                      │
├──────────────────┬───────────────────────────────────┤
│ CloudTrail       │ Session start/end, Run Command exec│
│ CloudWatch Logs  │ Session output, Automation logs    │
│ S3               │ Session logs, Patch compliance     │
│ KMS              │ SecureString encryption            │
│ IAM              │ Access control for all SSM actions │
│ Config           │ Compliance findings integration    │
│ Security Hub     │ SSM compliance → SH findings       │
│ EventBridge      │ Trigger Automation on events       │
│ GuardDuty        │ Finding → EventBridge → SSM Auto  │
│ Lambda           │ Custom remediation from Automation │
│ EC2              │ Target of all SSM operations       │
│ Secrets Manager  │ Complement to Parameter Store      │
└──────────────────┴───────────────────────────────────┘
```

---

# SECTION 2 — EXAM DEEP DIVE

---

## 2.1 Scenario-Based Q&A (20 Questions)

---

**Q1.** A company wants to eliminate all SSH access to EC2 instances while maintaining secure administrative access. What is the recommended replacement?

A) VPN with SSH  
B) AWS Systems Manager Session Manager  
C) EC2 Instance Connect  
D) Direct console access  

**Answer: B**

Session Manager provides interactive shell access without any open inbound ports, without SSH keys, with full IAM-based access control and automatic session logging. It's the AWS-recommended replacement for SSH in security-hardened environments.

---

**Q2.** An EC2 instance has `AmazonSSMManagedInstanceCore` in its instance profile but Session Manager is not working. What is the likely cause?

A) The instance is in a private subnet  
B) The SSM Agent is not installed or not running on the instance  
C) The IAM user doesn't have EC2 permissions  
D) Session Manager requires port 22  

**Answer: B**

Session Manager requires: (1) SSM Agent running on the instance, AND (2) instance profile with `AmazonSSMManagedInstanceCore`. If the agent is not installed/running, the instance won't appear in SSM Fleet Manager. For private subnet instances, VPC endpoints for SSM are needed.

---

**Q3.** A security team wants all Session Manager sessions logged with full input/output capture. Where should this be configured?

A) CloudTrail settings  
B) SSM → Session Manager Preferences → S3 bucket and/or CloudWatch Logs group  
C) EC2 instance userdata  
D) IAM policy condition  

**Answer: B**

Session Manager Preferences in the SSM console allows configuring: S3 bucket for session logs (with optional KMS encryption), CloudWatch Logs group, and whether to encrypt session data. This is a one-time configuration that applies to all sessions across the account.

---

**Q4.** A company has 500 EC2 instances and needs all Critical CVE patches applied within 24 hours. What is the correct SSM Patch Manager configuration?

A) SSH into each instance and patch manually  
B) Create a Patch Baseline with `Critical` patches auto-approved with 0-day delay + Maintenance Window with 24-hour trigger + Patch Group tag on all instances  
C) Enable GuardDuty patching  
D) Use Config remediation  

**Answer: B**

Patch Baseline with 0-day auto-approval for Critical patches + Maintenance Window triggered within 24 hours covers all 500 instances via Patch Groups (tag-based targeting). Manual SSH at 500-instance scale is impractical. GuardDuty doesn't patch. Config detects but doesn't patch.

---

**Q5.** What is the difference between SSM Patch Manager's `Scan` and `Install` operations?

A) Scan is faster; Install is more accurate  
B) Scan assesses compliance (reports missing patches without applying); Install applies approved patches  
C) Scan works on Linux only; Install on Windows  
D) They are identical  

**Answer: B**

**Scan** — evaluates instances against the patch baseline and reports compliance status (how many patches are missing) without making any changes. **Install** — applies the approved patches from the baseline. Use Scan first to assess impact, then Install in a maintenance window.

---

**Q6.** A developer accidentally stored a plaintext database password in an SSM Parameter Store String (not SecureString). What is the immediate remediation?

A) Delete the parameter — no further action needed  
B) Delete the plaintext parameter, rotate the database password, create a new SecureString parameter with the new password  
C) Convert the String parameter to SecureString in-place  
D) Add a parameter policy to encrypt it retroactively  

**Answer: B**

Parameters cannot be converted between types in-place. The compromised password must be rotated (assume it was exposed). Create a new SecureString parameter with the new password. Delete the plaintext one. Parameters cannot be retroactively encrypted.

---

**Q7.** SSM Run Command is used to execute a script on 1,000 instances. After 10 failures, the team wants execution to stop. What parameter controls this?

A) `MaxConcurrency`  
B) `MaxErrors`  
C) `TimeoutSeconds`  
D) `StopOnError`  

**Answer: B**

`MaxErrors` sets the threshold for failures after which Run Command stops sending to additional instances. `MaxErrors: 10` stops execution after 10 instance failures — preventing a bad script from propagating across the entire fleet. `MaxConcurrency` controls how many instances run simultaneously.

---

**Q8.** An EC2 instance in a private subnet (no NAT Gateway, no internet) needs to use SSM Session Manager. What is required?

A) Add a NAT Gateway  
B) Create VPC Interface Endpoints for SSM: `ssm`, `ssmmessages`, and `ec2messages`  
C) Move instance to public subnet  
D) Open port 443 outbound  

**Answer: B**

For SSM in a private subnet without internet access, three VPC Interface Endpoints are required:
- `com.amazonaws.region.ssm`
- `com.amazonaws.region.ssmmessages`  
- `com.amazonaws.region.ec2messages`

These allow the SSM Agent to communicate with the SSM service through the AWS private network.

---

**Q9.** A compliance requirement mandates that all remote sessions to production EC2 instances must have MFA. How is this enforced with Session Manager?

A) Configure MFA on the EC2 instance OS  
B) Add IAM condition `aws:MultiFactorAuthPresent: true` to the `ssm:StartSession` permission  
C) Enable MFA in Session Manager preferences  
D) This is not possible with Session Manager  

**Answer: B**

IAM condition keys can require MFA for SSM session initiation:
```json
"Condition": {
  "Bool": { "aws:MultiFactorAuthPresent": "true" }
}
```
Users without active MFA session cannot start sessions. This is enforced at the IAM policy level — no instance-level changes needed.

---

**Q10.** What is the SSM Inventory feature used for in a security context?

A) Billing inventory  
B) Tracks installed software, running services, and OS configuration across all managed instances — enabling detection of unauthorized software  
C) Tracks S3 bucket contents  
D) Records IAM policy changes  

**Answer: B**

SSM Inventory collects metadata: installed applications, running services, network configuration, OS details, Windows registry keys, and more. From a security perspective: detect unauthorized software (crypto miners, backdoors), verify expected security agents are running, identify instances missing required tools.

---

**Q11.** What must be true for an EC2 instance to be managed by SSM?

A) Must be in a public subnet  
B) Must have SSM Agent running + instance profile with SSM permissions (`AmazonSSMManagedInstanceCore`)  
C) Must be running Amazon Linux  
D) Must have port 22 open  

**Answer: B**

SSM management requires: (1) SSM Agent installed and running — pre-installed on Amazon Linux 2, Windows Server 2016+, Ubuntu 16.04+; manual installation otherwise. (2) Instance profile with `AmazonSSMManagedInstanceCore` — grants permissions for SSM Agent to call SSM APIs. No public subnet, no port 22, OS-agnostic.

---

**Q12.** A security automation triggers an SSM Automation document when GuardDuty detects a threat. What is the triggering architecture?

A) GuardDuty → Lambda → SSM  
B) GuardDuty → EventBridge rule → SSM Automation  
C) GuardDuty → SNS → SSM  
D) GuardDuty → Config → SSM  

**Answer: B**

GuardDuty findings generate EventBridge events. An EventBridge rule targeting specific finding types can directly trigger **SSM Automation** as a target — no Lambda intermediary needed for simple runbooks. For complex logic, EventBridge → Lambda → SSM is also valid.

---

**Q13.** What is the purpose of Patch Groups in SSM Patch Manager?

A) Group patches by severity  
B) Tag-based grouping of instances to associate them with specific patch baselines and maintenance windows  
C) Group patching operations by region  
D) Track patch download groups  

**Answer: B**

Patch Groups use a tag `Patch Group: <value>` on EC2 instances. Patch baselines are associated with Patch Groups — allowing different instances (production vs. dev, Windows vs. Linux) to use different baselines and maintenance windows. Without Patch Groups, all instances use the default baseline.

---

**Q14.** An SSM Parameter Store SecureString parameter is encrypted with a CMK. A Lambda function tries to read it. What permissions does the Lambda execution role need?

A) `ssm:GetParameter` only  
B) `ssm:GetParameter` AND `kms:Decrypt` on the specific CMK  
C) `ssm:*` and `kms:*`  
D) `secretsmanager:GetSecretValue`  

**Answer: B**

Reading a SecureString requires two permissions: `ssm:GetParameter` (to retrieve the encrypted value from Parameter Store) AND `kms:Decrypt` on the specific KMS CMK used for encryption (to decrypt the value). Missing either causes access denied.

---

**Q15.** A company uses SSM Run Command to execute a forensic script on a compromised instance. Where are the command execution results stored by default?

A) Instance local disk only  
B) S3 (if configured in Run Command output settings) and viewable in the SSM console for 30 days  
C) CloudTrail  
D) DynamoDB  

**Answer: B**

Run Command execution output is available in the SSM console for 30 days. For long-term retention and large outputs, configure an S3 bucket in Run Command settings. CloudTrail records that Run Command was executed (with document name and instance IDs) but not the command output.

---

**Q16.** What is the security risk of not configuring `MaxConcurrency` and `MaxErrors` in Run Command operations?

A) No risk  
B) A failing command could cascade to all instances simultaneously — potentially causing a fleet-wide outage or widespread misconfiguration  
C) Run Command becomes slower  
D) CloudTrail stops logging  

**Answer: B**

Without limits: if the command has a bug (e.g., stops a critical service), it executes on all instances simultaneously. `MaxConcurrency` limits the blast radius to N% of fleet at a time. `MaxErrors` stops execution after N failures, containing the impact before it spreads fleet-wide.

---

**Q17.** How does SSM State Manager differ from Run Command?

A) They are identical  
B) Run Command is one-time/on-demand execution; State Manager continuously enforces a desired configuration state — re-applying if drift is detected  
C) State Manager is for patching only  
D) Run Command is scheduled; State Manager is on-demand  

**Answer: B**

**Run Command** — executes once, on demand. **State Manager** — defines desired state (e.g., antivirus installed, specific packages present) and continuously monitors and re-enforces it on a schedule. If an instance drifts (package removed), State Manager re-applies the association to bring it back to desired state.

---

**Q18.** A company wants to use SSM Parameter Store for database credentials shared across multiple accounts in an Organization. What is the limitation?

A) Parameter Store is limited to 10 parameters  
B) SSM Parameter Store does not support cross-account access natively — use Secrets Manager with resource-based policy for cross-account secret sharing  
C) Parameter Store only works in us-east-1  
D) Cross-account requires a VPN  

**Answer: B**

SSM Parameter Store lacks native cross-account access (no resource-based policy support). For cross-account secret sharing, **Secrets Manager** (which supports resource-based policies) is the correct choice. Parameter Store is intended for single-account use.

---

**Q19.** SSM Patch Manager reports an instance as NON_COMPLIANT for patches. What does this mean?

A) The instance has a critical security breach  
B) The instance has missing patches that are approved in its patch baseline but not yet installed  
C) The SSM Agent is not running  
D) The instance is in an unsupported OS  

**Answer: B**

NON_COMPLIANT in Patch Manager means: the instance has one or more patches that are **approved in the associated patch baseline** but are **not currently installed**. The instance is still running — just not up to the desired patch level. The remediation is to run the Install operation.

---

**Q20.** What is the benefit of using SSM Session Manager over EC2 Instance Connect for security-sensitive environments?

A) Instance Connect is less secure  
B) Session Manager: full session logging (input+output), no inbound ports, works on private instances without NAT, long-term session support. Instance Connect: browser-based SSH, temporary key pushed, requires port 22 accessible.  
C) They are equivalent  
D) Session Manager is only for Windows  

**Answer: B**

Session Manager is preferred for security-sensitive use: (1) no inbound ports (port 22 not needed), (2) full session content logging to S3/CloudWatch, (3) works on fully private instances via VPC endpoints, (4) IAM-controlled with tag-based conditions. EC2 Instance Connect pushes a temporary SSH key and requires port 22 accessible from EC2 Connect IP ranges.

---

## 2.2 Common Exam Traps & Distractors (10)

**Trap 1: Session Manager requires port 22**
> ❌ Wrong: "Open port 22 for SSM Session Manager"
> ✅ Right: Session Manager needs NO inbound ports — outbound 443 to SSM endpoints only

**Trap 2: SSM alone = instance managed**
> ❌ Wrong: "Enabling SSM service auto-manages all EC2 instances"
> ✅ Right: Instance must have SSM Agent running + instance profile with `AmazonSSMManagedInstanceCore`

**Trap 3: Patch Manager reboots by default**
> ❌ Wrong: "Patch Manager automatically reboots after patching"
> ✅ Right: `RebootOption: RebootIfNeeded` must be explicitly set — default is no reboot

**Trap 4: SecureString = ssm:GetParameter is sufficient**
> ❌ Wrong: "ssm:GetParameter gives access to SecureString values"
> ✅ Right: Need `ssm:GetParameter` AND `kms:Decrypt` on the CMK

**Trap 5: Parameter Store supports cross-account**
> ❌ Wrong: "Use Parameter Store to share secrets across accounts"
> ✅ Right: Parameter Store has no resource-based policy — use Secrets Manager for cross-account

**Trap 6: Run Command = real-time interactive session**
> ❌ Wrong: "Use Run Command for interactive debugging"
> ✅ Right: Run Command is non-interactive script/document execution. Session Manager = interactive.

**Trap 7: State Manager = one-time enforcement**
> ❌ Wrong: "State Manager applies configuration once"
> ✅ Right: State Manager continuously enforces — detects drift and re-applies

**Trap 8: SSM Compliance = Config rules**
> ❌ Wrong: "SSM Compliance is the same as AWS Config"
> ✅ Right: SSM Compliance is specifically for patch and association compliance on managed instances

**Trap 9: Patch baseline = automatic patching**
> ❌ Wrong: "Creating a patch baseline automatically patches instances"
> ✅ Right: Baseline defines WHICH patches are approved. Maintenance Window + Run Command actually APPLIES them.

**Trap 10: Session Manager logs = CloudTrail**
> ❌ Wrong: "CloudTrail captures all Session Manager session content"
> ✅ Right: CloudTrail captures session START/END. Session content (commands/output) goes to S3/CloudWatch via Session Manager Preferences.

---

## 2.3 Key Facts Cheat Sheet

```
┌────────────────────────────────────────────────────────────┐
│        AWS SYSTEMS MANAGER — EXAM CHEAT SHEET              │
├──────────────────────────────────┬─────────────────────────┤
│ SSM managed instance requires    │ Agent + instance profile │
│ Session Manager inbound ports    │ None (outbound 443 only)│
│ Session logging config location  │ SSM Preferences         │
│ Private subnet SSM access        │ 3 VPC endpoints         │
│ Patch Scan vs Install            │ Scan=assess, Install=fix│
│ Patch Group mechanism            │ EC2 tag: Patch Group    │
│ Reboot after patching            │ Manual: RebootIfNeeded  │
│ SecureString needs               │ ssm:Get + kms:Decrypt   │
│ Cross-account secrets            │ Secrets Manager (not PS)│
│ Run Command stop on error        │ MaxErrors parameter     │
│ Run Command concurrency          │ MaxConcurrency param    │
│ State Manager vs Run Command     │ Continuous vs one-time  │
│ Inventory security use           │ Detect unauthorized SW  │
│ Session Manager vs SSH           │ No port 22 needed       │
│ MFA for sessions                 │ IAM condition on StartSess│
│ Automation trigger from GD       │ EventBridge → SSM Auto  │
│ Session content logs             │ S3 / CloudWatch Logs    │
│ API call audit for SSM           │ CloudTrail              │
└──────────────────────────────────┴─────────────────────────┘
```

---

## 2.4 Elimination Strategies

**Strategy 1: SSH-less secure access → Session Manager**
Eliminate SSH, open ports → eliminate bastion/port 22 → **SSM Session Manager**

**Strategy 2: Fleet-wide patching → Patch Manager**
OS/app patching at scale → eliminate manual → **SSM Patch Manager + Maintenance Windows**

**Strategy 3: Remote script execution → Run Command**
Execute commands on multiple instances → eliminate SSH scripting → **SSM Run Command**

**Strategy 4: Configuration drift enforcement → State Manager**
Continuously enforce OS config → eliminate one-time scripts → **SSM State Manager**

**Strategy 5: Private subnet SSM → VPC Endpoints**
SSM in private subnet no NAT → eliminate NAT GW → **3 VPC Interface Endpoints (ssm, ssmmessages, ec2messages)**

**Strategy 6: SecureString IAM → ssm:Get + kms:Decrypt**
Access encrypted parameter → eliminate "ssm:Get alone" → **both ssm:GetParameter AND kms:Decrypt**

---

---

# 📅 Day 51 — Automated Remediation

---

# SECTION 1 — THEORY BLOCK

---

## 1.1 Service Overview & Purpose

### What is Automated Remediation on AWS?
Automated remediation is the capability to **automatically detect and fix security misconfigurations or threats** without human intervention — using AWS-native services orchestrated together. It closes the gap between detection and response from hours to seconds.

### Why It Matters
```
Manual Remediation Gap:
Detection (GuardDuty/Config) → Alert → Human review → Ticket → Fix
= Minutes to hours to days

Automated Remediation:
Detection → EventBridge → Lambda/SSM/Step Functions → Fix
= Seconds to minutes, 24/7, consistent
```

### Key Automation Patterns

| Pattern | Services | Latency |
|---|---|---|
| Config → SSM Automation | Config rule + SSM runbook | Minutes |
| GuardDuty → EventBridge → Lambda | GD finding + EB rule + Lambda | Seconds |
| Security Hub → EventBridge → Step Functions | SH finding + EB + SF | Seconds–minutes |
| CloudWatch Alarm → SNS → Lambda | CW alarm + SNS + Lambda | Seconds |

### Exam Weight & Importance
- **Domain 1: Incident Response** + **Domain 3: Infrastructure Security**
- Expect **3–4 questions** on automated remediation architecture
- Commonly tested: Config + SSM remediation, GuardDuty → EventBridge → Lambda, Step Functions for IR orchestration

---

## 1.2 Core Architecture

```
┌──────────────────────────────────────────────────────────────┐
│              AUTOMATED REMEDIATION ARCHITECTURE              │
│                                                              │
│  DETECTION SOURCES                                           │
│  ├── AWS Config (NON_COMPLIANT resource)                    │
│  ├── GuardDuty (threat finding)                             │
│  ├── Security Hub (aggregated finding)                      │
│  ├── CloudWatch Alarm (metric threshold)                    │
│  └── CloudTrail (specific API call)                         │
│              │                                               │
│              │ Event / Finding                               │
│              ▼                                               │
│  ┌───────────────────────────────────────────────┐         │
│  │            Amazon EventBridge                  │         │
│  │  Rules match event patterns → route to targets │         │
│  └───────────────────────────────────────────────┘         │
│              │                                               │
│    ┌─────────┼──────────┬─────────────┐                    │
│    ▼         ▼          ▼             ▼                    │
│  Lambda  SSM Auto  Step Functions  SNS+PagerDuty           │
│  (code)  (runbook) (workflow)      (notify)                │
│    │         │          │                                   │
│    └─────────┴──────────┘                                  │
│              │                                               │
│              ▼                                               │
│  REMEDIATION ACTIONS                                         │
│  ├── Isolate EC2 (SG swap)                                 │
│  ├── Revoke IAM credentials                                │
│  ├── Block S3 public access                                │
│  ├── Delete unauthorized IAM user                          │
│  ├── Disable access key                                    │
│  ├── Snapshot + preserve evidence                          │
│  └── Notify incident response team                         │
└──────────────────────────────────────────────────────────────┘
```

---

## 1.3 Deep Dive — Every Sub-Topic

### A. Config + SSM Automation Remediation

The native Config remediation pattern — no custom code needed.

**Setup:**
1. Config rule detects NON_COMPLIANT resource
2. Config rule has remediation action configured → points to SSM Automation document
3. Mode: Manual (admin clicks) or Automatic (fires without human)

**Common Config rule + SSM Automation pairs:**

| Config Rule | SSM Automation Document |
|---|---|
| `s3-bucket-public-read-prohibited` | `AWS-DisableS3BucketPublicReadWrite` |
| `encrypted-volumes` | Create encrypted snapshot + replace volume |
| `restricted-ssh` | `AWS-DisablePublicAccessForSecurityGroup` |
| `cloudtrail-enabled` | `AWS-EnableCloudTrail` |
| `root-account-mfa-enabled` | Notify only (cannot auto-enable MFA) |

**Auto-remediation with retry:**
```
Config Non-Compliant → SSM Automation
├── RetryAttempts: 3
├── RetryInterval: 60 seconds
└── On failure: SNS notification to team
```

⚠️ **Gotcha:** Auto-remediation without testing can cause outages. Always test with Manual remediation first. Use `retryAttempts` and consider excluding critical resources from auto-remediation using Config rule scope.

---

### B. GuardDuty → EventBridge → Lambda Pattern

Real-time automated response to GuardDuty threats.

**EventBridge rule for GuardDuty findings:**
```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "severity": [{ "numeric": [">=", 7.0] }],
    "type": ["UnauthorizedAccess:EC2/SSHBruteForce",
              "Backdoor:EC2/C&CActivity.B",
              "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"]
  }
}
```

**Lambda remediation functions by finding type:**

| Finding | Lambda Action |
|---|---|
| `UnauthorizedAccess:EC2/SSHBruteForce` | Add source IP to WAF IP set or NACL |
| `Backdoor:EC2/C&CActivity` | Isolate instance (forensics SG) + snapshot |
| `CryptoCurrency:EC2/BitcoinTool` | Isolate + notify + ticket |
| `UnauthorizedAccess:IAMUser/ConsoleLogin` | Force logout + notify |
| `CredentialAccess:IAMUser/AnomalousBehavior` | Deactivate access key + TokenIssueTime deny |

**Lambda isolation function (simplified):**
```python
import boto3

def lambda_handler(event, context):
    instance_id = event['detail']['resource']['instanceDetails']['instanceId']
    ec2 = boto3.client('ec2')

    # Swap to forensics security group
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=['sg-forensics-all-blocked']
    )

    # Create snapshot
    volumes = ec2.describe_instances(InstanceIds=[instance_id])
    # ... snapshot creation logic

    # Notify team
    sns = boto3.client('sns')
    sns.publish(TopicArn='arn:aws:sns:...:security-alerts',
                Message=f'Isolated instance {instance_id}')
```

---

### C. Step Functions for Multi-Step IR Orchestration

For complex IR workflows requiring sequential steps, error handling, and human approval gates.

**Step Functions IR workflow:**
```
State Machine: EC2 Compromise Response
│
├── Step 1: CreateForensicSnapshot
│           (EC2 CreateSnapshot API)
│
├── Step 2: IsolateInstance
│           (EC2 ModifyInstanceAttribute → forensics SG)
│
├── Step 3: ShareSnapshotToForensicsAccount
│           (EC2 ModifySnapshotAttribute)
│
├── Step 4: NotifyIRTeam
│           (SNS Publish)
│
├── Step 5: WaitForApproval [Human Gate]
│           (Callback task token — waits for IR lead to approve)
│
└── Step 6: TerminateInstance (if approved)
            (EC2 TerminateInstances)
```

**Why Step Functions over Lambda alone:**
- **Error handling** — retry logic per step, catch failures
- **Human approval gates** — pause workflow for approval
- **Visibility** — visual execution graph, step-by-step status
- **Audit trail** — every state transition logged
- **Long-running workflows** — up to 1 year execution

---

### D. Security Hub Custom Actions

Security Hub allows defining **Custom Actions** that trigger EventBridge events when a security analyst clicks them on a finding.

**Use case:** Analyst reviews a finding → clicks "Isolate Instance" Custom Action → EventBridge rule triggers Lambda → isolation occurs.

This provides human-in-the-loop automation — the action is automated but requires human initiation.

---

### E. CloudWatch Alarms → Automated Response

For metric-based triggers (not finding-based):

```
CloudWatch Metric Alarm:
├── Alarm: EC2 CPU > 95% for 10 min (crypto mining indicator)
├── Action: SNS → Lambda → investigate instance
│
├── Alarm: GuardDuty findings/hour > 50 (attack wave)
├── Action: SNS → PagerDuty → on-call engineer
│
└── Alarm: IAM ConsoleLogin from new country
    Action: SNS → Lambda → force MFA re-auth
```

---

### F. AWS Security Hub Automated Response and Remediation (SHARR)

AWS Solution for automated Security Hub finding remediation.

- Pre-built runbooks for CIS, PCI-DSS, NIST findings
- EventBridge + Step Functions + Lambda + SSM
- Deployment via CloudFormation
- Covers 50+ automated remediation playbooks

---

## 1.4 Comparison Tables

### Remediation Orchestration Options

| Tool | Best For | Complexity | Human Gate |
|---|---|---|---|
| Config + SSM Automation | Config compliance fixes | Low | Optional |
| Lambda (direct) | Simple, single-step remediations | Low-Medium | No |
| Step Functions | Multi-step, complex IR workflows | High | ✅ Yes |
| Security Hub Custom Actions | Human-initiated automated response | Low | ✅ Yes |
| CloudWatch → SNS → Lambda | Metric-based triggers | Low | Optional |

---

## 1.5 Security & Compliance Angles

### Guardrails for Automated Remediation

1. **Test before auto-enable** — always test with manual mode first
2. **Scope carefully** — use Config rule scope to exclude production/critical resources initially
3. **Add human gates** — Step Functions approval for destructive actions (terminate, delete)
4. **Set retry limits** — `retryAttempts: 3` with delays
5. **Notify always** — even on auto-fix, notify the IR team via SNS
6. **Idempotent remediations** — ensure running the same remediation twice doesn't cause issues
7. **Log everything** — CloudTrail + CloudWatch Logs for all automation execution

### Common Misconfigurations

1. Auto-remediation without testing — causes production outages
2. Lambda with overly broad execution role — can be exploited
3. No human gate on destructive actions (EC2 terminate, RDS delete)
4. No retry logic — transient API failures cause remediation to fail silently
5. SNS notification not configured — team unaware of automated actions taken

---

## 1.6 Integration Patterns

```
┌──────────────────────────────────────────────────────┐
│       AUTOMATED REMEDIATION INTEGRATION MAP           │
├──────────────────┬───────────────────────────────────┤
│ Config           │ NON_COMPLIANT → SSM Automation     │
│ GuardDuty        │ Finding → EventBridge → Lambda     │
│ Security Hub     │ Finding → Custom Action → EB       │
│ EventBridge      │ Central routing/orchestration hub  │
│ Lambda           │ Custom remediation code            │
│ SSM Automation   │ Pre-built runbooks                 │
│ Step Functions   │ Multi-step IR orchestration        │
│ SNS              │ Team notification                  │
│ CloudTrail       │ Audit all automated actions        │
│ IAM              │ Least-privilege execution roles    │
│ KMS              │ Encrypt evidence + logs            │
└──────────────────┴───────────────────────────────────┘
```

---

# SECTION 2 — EXAM DEEP DIVE

---

## 2.1 Scenario-Based Q&A (20 Questions)

---

**Q1.** A GuardDuty finding `Backdoor:EC2/C&CActivity.B` is generated at 2 AM. No one is on-call. The company wants the EC2 instance automatically isolated. What is the architecture?

A) GuardDuty → SNS → email team  
B) GuardDuty finding → EventBridge rule → Lambda function (isolates instance by swapping SG + creates EBS snapshot)  
C) GuardDuty → Config → SSM  
D) GuardDuty → CloudWatch → Step Functions  

**Answer: B**

GuardDuty generates EventBridge events for all findings. An EventBridge rule matching `Backdoor:EC2/C&CActivity.B` triggers a Lambda function that: modifies instance security group to forensics SG (all blocked), creates EBS snapshot, and sends SNS notification. This all happens in seconds — no human required.

---

**Q2.** AWS Config finds an S3 bucket with public read enabled. The company wants this automatically blocked. What is the SIMPLEST architecture?

A) Config → EventBridge → Lambda  
B) Config rule with automatic SSM Automation remediation action (`AWS-DisableS3BucketPublicReadWrite`)  
C) GuardDuty → Lambda  
D) Macie → Config  

**Answer: B**

Config has **native SSM Automation integration** for remediation — no Lambda or custom code needed. The `AWS-DisableS3BucketPublicReadWrite` pre-built SSM document is exactly the right remediation for this rule. Configure in automatic mode with Config rule remediation settings.

---

**Q3.** A company wants a multi-step IR workflow: snapshot EC2 → isolate → notify team → wait for human approval → terminate instance. Which service orchestrates this workflow with a human approval gate?

A) Lambda (single function)  
B) AWS Step Functions with a task token callback step  
C) SSM Automation  
D) EventBridge Pipes  

**Answer: B**

Step Functions supports **human approval gates** via task token callback: the workflow pauses at the approval step and sends a token to the reviewer (via SNS or API Gateway). The workflow only continues when the reviewer calls `SendTaskSuccess` (approve) or `SendTaskFailure` (reject). Lambda alone can't pause for human input. SSM Automation has limited human gate support.

---

**Q4.** A Security Hub finding indicates an IAM user has no MFA. The company wants this automatically remediated. What is the limitation?

A) Security Hub can't see IAM findings  
B) MFA cannot be programmatically enabled for IAM users — the user must set it up themselves; automation can only notify or disable the user  
C) IAM doesn't support MFA  
D) Config rules cover this automatically  

**Answer: B**

MFA requires the user to physically scan a QR code with their authenticator app — this cannot be automated. The automated remediation can: (1) disable the IAM user's access, (2) send the user a notification to set up MFA, (3) remove permissions until MFA is configured. The MFA enrollment itself requires human action.

---

**Q5.** What is the risk of an auto-remediation Lambda function with an overly broad execution role?

A) Lambda runs slower  
B) If the Lambda function is compromised (e.g., through code injection via event data), the attacker gains broad AWS permissions via the execution role  
C) CloudTrail stops logging  
D) Config rules stop evaluating  

**Answer: B**

The Lambda execution role for remediation functions should follow least privilege — only the specific actions needed (e.g., `ec2:ModifyInstanceAttribute` for isolation). A broad role (e.g., `AdministratorAccess`) means a compromised function becomes a privilege escalation vector. Event data from GuardDuty/Config could potentially be manipulated in event injection attacks.

---

**Q6.** A Config auto-remediation runs three times but the resource remains NON_COMPLIANT. What should the automation do on the final failure?

A) Keep retrying indefinitely  
B) Send an SNS notification to the security team indicating that manual intervention is required  
C) Delete the non-compliant resource  
D) Disable the Config rule  

**Answer: B**

After exhausting retry attempts, escalation to a human is the correct approach. SNS notification to the security team triggers manual review. Some resources may have legitimate reasons for the configuration, or the remediation may be failing due to a dependency. Never auto-delete on remediation failure.

---

**Q7.** An EventBridge rule is configured to route GuardDuty findings with severity ≥ 7.0 to a Lambda function. A finding with severity 6.8 is generated. What happens?

A) The Lambda is triggered  
B) The finding is not routed to Lambda — severity 6.8 does not match the `>= 7.0` condition  
C) The finding is discarded  
D) EventBridge routes all findings regardless of rules  

**Answer: B**

EventBridge rules use pattern matching — only events matching ALL conditions in the rule pattern are routed to the target. Severity 6.8 does not satisfy `>= 7.0`. The finding still exists in GuardDuty but is not automatically remediated. Consider separate rules for Medium severity findings routed to notification-only targets.

---

**Q8.** What is the AWS Security Hub Automated Response and Remediation (SHARR) solution?

A) A GuardDuty feature  
B) An AWS-provided solution with pre-built remediation runbooks for CIS, PCI-DSS, and NIST findings from Security Hub — deployed via CloudFormation  
C) A third-party tool  
D) An IAM feature for auto-rotating credentials  

**Answer: B**

SHARR is an AWS Solutions Library deployment that provides ~50 pre-built automated remediation playbooks for Security Hub findings mapped to compliance frameworks. It uses EventBridge + Step Functions + Lambda + SSM and is deployed as a CloudFormation stack.

---

**Q9.** Why is Step Functions preferred over a monolithic Lambda function for multi-step IR workflows?

A) Step Functions is cheaper  
B) Step Functions provides: step-by-step visibility, independent retry per step, human approval gates, long-running workflow support, and error handling — Lambda has a 15-minute max timeout and no native human gate  
C) Lambda doesn't support IR  
D) Step Functions runs faster  

**Answer: B**

Key Step Functions advantages for IR: (1) visual execution graph, (2) per-step error handling with catch/retry, (3) task token for human approval, (4) executions can run for up to 1 year, (5) auditable state transitions. Lambda's 15-minute max timeout is a hard constraint for long-running IR workflows.

---

**Q10.** A Security Hub Custom Action is configured. When does it trigger?

A) Automatically on every new finding  
B) Only when a security analyst manually selects a finding and clicks the Custom Action button  
C) Daily at midnight  
D) When severity exceeds 8.0  

**Answer: B**

Custom Actions in Security Hub are **human-initiated** — they appear as buttons in the Security Hub console. The analyst selects one or more findings and clicks the Custom Action. This generates an EventBridge event that triggers automation. This provides human-in-the-loop control over automated remediation.

---

**Q11.** A Lambda remediation function isolates an EC2 instance by modifying its security group. The isolation happens successfully but the team receives no notification. What was missed?

A) CloudTrail notification  
B) SNS publish step was not included in the Lambda function  
C) EventBridge confirmation  
D) Config acknowledgment  

**Answer: B**

Automated remediation should always include notification — the team needs to know what was automatically done. Add an SNS `Publish` call at the end of the Lambda function to send details: which instance was isolated, which finding triggered it, timestamp, and case reference. Silent automation creates operational confusion.

---

**Q12.** Config auto-remediation accidentally stops a production RDS instance. How could this have been prevented?

A) Disable Config  
B) Use Config rule scope to exclude the production RDS instance or tag group from the rule's evaluation; test with manual remediation first  
C) Use a different region for Config  
D) This cannot happen with Config  

**Answer: B**

Config rule **scope** allows restricting which resources a rule evaluates (by tag, resource type, or resource ID). Exclude production resources initially, test in non-production, then gradually expand scope. Manual remediation mode first allows human review before automation is enabled.

---

**Q13.** What IAM permissions does a Lambda function need to isolate an EC2 instance by modifying its security groups?

A) `ec2:*`  
B) `ec2:ModifyInstanceAttribute` and `ec2:DescribeInstances` (least privilege)  
C) `iam:PassRole`  
D) `ssm:StartSession`  

**Answer: B**

Least privilege for EC2 isolation Lambda: `ec2:ModifyInstanceAttribute` (to change security groups) and `ec2:DescribeInstances` (to get current instance details). No other EC2 permissions needed. `ec2:*` is over-privileged — the Lambda execution role should be narrowly scoped.

---

**Q14.** An auto-remediation script calls `ec2:TerminateInstances` on a flagged instance. The instance turns out to be a false positive and is permanently deleted. What safeguard prevents this?

A) GuardDuty severity filtering  
B) Step Functions human approval gate before termination step  
C) Config rule exclusion  
D) Security Hub suppression  

**Answer: B**

Termination is irreversible — it must have a human approval gate. Step Functions task token callback pauses execution at the termination step and requires explicit human confirmation. This is the correct architecture for any destructive automated action.

---

**Q15.** How does automated remediation for a GuardDuty finding differ from a Config rule remediation architecturally?

A) They use the same architecture  
B) GuardDuty: event-driven via EventBridge (finding → EB → Lambda); Config: polling-based via SSM Automation (rule NON_COMPLIANT → SSM runbook). GuardDuty is real-time threats; Config is configuration compliance.  
C) Config uses Lambda; GuardDuty uses SSM  
D) Only Config supports automated remediation  

**Answer: B**

GuardDuty findings are real-time threat events → EventBridge routing → Lambda/Step Functions for immediate response. Config is configuration compliance → native SSM Automation integration → remediation on compliance state changes. Both paths ultimately take corrective action but are triggered differently and serve different purposes.

---

**Q16.** What EventBridge source identifier is used to match GuardDuty findings?

A) `aws.security`  
B) `aws.guardduty`  
C) `aws.findings`  
D) `guardduty.amazonaws.com`  

**Answer: B**

EventBridge event pattern for GuardDuty:
```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"]
}
```
`aws.guardduty` is the source identifier for all GuardDuty events in EventBridge.

---

**Q17.** A company wants to auto-disable IAM access keys that haven't been used in 90 days. What is the architecture?

A) GuardDuty finding → Lambda  
B) Config rule (`access-keys-rotated`) → SSM Automation (custom document that calls `iam:UpdateAccessKey` to deactivate)  
C) CloudWatch daily alarm → SNS  
D) Trusted Advisor → Lambda  

**Answer: B**

Config rule `access-keys-rotated` detects keys older than the threshold. A custom SSM Automation document that calls `iam:UpdateAccessKey` with `Status=Inactive` can be configured as the auto-remediation action. This cleanly connects detection (Config) to remediation (SSM) without custom Lambda code.

---

**Q18.** Automated remediation executes and calls `s3:PutBucketPublicAccessBlock`. CloudTrail records this as called by `ssm.amazonaws.com`. Why?

A) SSM is the bucket owner  
B) SSM Automation uses a service role to execute AWS API calls — the call appears in CloudTrail attributed to the SSM Automation service principal, not a human user  
C) CloudTrail has an error  
D) S3 is blocking the audit  

**Answer: B**

When SSM Automation executes actions, the API calls are made by the SSM Automation execution role. CloudTrail records the call with the SSM service principal as the userIdentity, along with the automation execution ID. This is normal and expected — the automation's CloudTrail entry includes enough context to trace it back to the Config rule that triggered it.

---

**Q19.** A company uses AWS Organizations. They want automated remediation deployed to all 100 member accounts with the same Config rules and SSM runbooks. What is the most efficient deployment?

A) Deploy to each account manually  
B) Organization Conformance Pack (for Config rules) + CloudFormation StackSets (for SSM Automation documents and Lambda functions)  
C) AWS Control Tower only  
D) One Lambda function in the management account  

**Answer: B**

Organization Conformance Pack deploys Config rules org-wide in one action. CloudFormation StackSets deploys SSM Automation documents, Lambda functions, EventBridge rules, and IAM roles to all member accounts simultaneously. Together they provide organization-wide automated remediation.

---

**Q20.** What is an idempotent remediation action and why is it important?

A) A remediation that runs only once  
B) A remediation that produces the same result whether run once or multiple times — important because auto-remediation may be triggered multiple times for the same resource without causing additional harm  
C) A remediation that only works in one region  
D) A remediation that requires human approval  

**Answer: B**

Idempotency means: running `PutBucketPublicAccessBlock` on an already-blocked bucket produces the same (safe) result. Running `DisableAccessKey` on an already-disabled key is harmless. Non-idempotent remediation (e.g., creating a new security group each time) can produce duplicate resources or broken state if triggered multiple times.

---

## 2.2 Common Exam Traps & Distractors (10)

**Trap 1: Auto-remediation is always safe**
> ❌ Wrong: "Enable auto-remediation for all Config rules immediately"
> ✅ Right: Test with manual first; use scope exclusions; never auto-terminate without human gate

**Trap 2: Lambda alone handles multi-step IR**
> ❌ Wrong: "Use one Lambda function for the full IR workflow"
> ✅ Right: Lambda = simple steps. Step Functions = multi-step with error handling, retries, human gates

**Trap 3: GuardDuty auto-remediates by default**
> ❌ Wrong: "GuardDuty automatically isolates compromised instances"
> ✅ Right: GuardDuty only DETECTS. You must build EventBridge → Lambda for automated response.

**Trap 4: Security Hub Custom Actions = automatic**
> ❌ Wrong: "Custom Actions trigger automatically on new findings"
> ✅ Right: Custom Actions are manually clicked by analysts — human-initiated

**Trap 5: Remediation Lambda needs broad permissions**
> ❌ Wrong: "Give remediation Lambda AdministratorAccess for flexibility"
> ✅ Right: Least privilege — only the specific actions the function needs. Broad role = privilege escalation risk.

**Trap 6: Config remediates in real-time**
> ❌ Wrong: "Config detects and remediates in seconds like GuardDuty"
> ✅ Right: Config evaluation can take minutes. GuardDuty → EventBridge is near real-time.

**Trap 7: Silent remediation is fine**
> ❌ Wrong: "Auto-remediation doesn't need notifications if it works"
> ✅ Right: Always notify the team of automated actions — silent automation creates operational blind spots

**Trap 8: Step Functions only for long workflows**
> ❌ Wrong: "Step Functions is overkill for short IR steps"
> ✅ Right: Step Functions provides visibility, error handling, and human gates even for short workflows — valuable for IR

**Trap 9: EventBridge routes all findings automatically**
> ❌ Wrong: "All GuardDuty findings are automatically routed to Lambda"
> ✅ Right: EventBridge rules must be explicitly created with matching patterns and targets

**Trap 10: SSM Automation and Lambda are interchangeable**
> ❌ Wrong: "Use Lambda instead of SSM Automation for Config remediation"
> ✅ Right: Config has NATIVE SSM Automation integration — use it for Config remediation. Lambda is for custom logic triggered via EventBridge.

---

## 2.3 Key Facts Cheat Sheet

```
┌────────────────────────────────────────────────────────────┐
│      AUTOMATED REMEDIATION — EXAM CHEAT SHEET              │
├──────────────────────────────────┬─────────────────────────┤
│ Config native remediation        │ SSM Automation          │
│ GuardDuty remediation path       │ GD → EventBridge → Lambda│
│ Multi-step IR orchestration      │ Step Functions          │
│ Human approval gate              │ SF task token callback  │
│ Human-initiated automation       │ SH Custom Actions       │
│ EventBridge GD source            │ aws.guardduty           │
│ Pre-built SH remediation         │ SHARR (AWS Solution)    │
│ Org-wide Config rules            │ Org Conformance Pack    │
│ Org-wide Lambda/SSM deployment   │ CloudFormation StackSets│
│ Idempotent = safe to repeat      │ ✅ Required for auto    │
│ Test mode for Config remediation │ Manual mode first       │
│ Exclude prod from auto-remediate │ Config rule scope/tags  │
│ Silent remediation risk          │ Team unaware of actions │
│ Lambda role for isolation        │ ec2:ModifyInstanceAttr  │
│ Never auto-do without human gate │ Terminate/Delete actions│
│ Remediation failure escalation   │ SNS to security team    │
└──────────────────────────────────┴─────────────────────────┘
```

---

## 2.4 Elimination Strategies

**Strategy 1: Config compliance auto-fix → SSM Automation (native)**
Config NON_COMPLIANT → eliminate Lambda → **Config + SSM Automation remediation**

**Strategy 2: Real-time threat response → EventBridge → Lambda**
GuardDuty finding instant response → eliminate Config → **EventBridge rule → Lambda**

**Strategy 3: Multi-step with human gate → Step Functions**
Complex IR + human approval → eliminate Lambda alone → **Step Functions with task token**

**Strategy 4: Human-initiated Security Hub remediation → Custom Actions**
Analyst-triggered automation → eliminate auto-trigger → **Security Hub Custom Actions**

**Strategy 5: Org-wide automation deployment → StackSets + Conformance Pack**
All accounts same rules + automation → eliminate per-account → **Org Conformance Pack + CF StackSets**

---

---

# 📅 Day 52 — Real-World Scenarios

---

# SECTION 1 — THEORY BLOCK

---

## 1.1 Overview & Purpose

### What is Day 52?
Day 52 consolidates all previous weeks into **integrated, real-world security scenarios** that mirror the complexity of AWS Security Specialty exam questions. These scenarios require combining multiple AWS security services together — no single-service questions.

The AWS exam frequently tests your ability to architect end-to-end security solutions spanning IAM, networking, detection, response, data protection, and compliance.

### Scenario Categories

```
Real-World Scenarios Covered:
├── A. Multi-account security architecture (Org + CT + GD + SH)
├── B. Compromised credential response (end-to-end)
├── C. Data exfiltration prevention + detection
├── D. Ransomware resilience architecture
├── E. Zero Trust architecture on AWS
├── F. Regulatory compliance (CERT-In / RBI / PCI-DSS)
├── G. Secure CI/CD pipeline
└── H. Container security at scale (ECS/EKS)
```

---

## 1.2 Scenario A — Multi-Account Security Architecture

### The Ask
"Design a security architecture for a 200-account AWS Organization with centralized logging, threat detection, compliance monitoring, and automated response."

### Solution Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                MULTI-ACCOUNT SECURITY ARCHITECTURE            │
│                                                              │
│  Management Account                                          │
│  ├── AWS Organizations (root)                               │
│  ├── Control Tower (landing zone)                           │
│  ├── SCPs at root: deny region outside ap-south-1/us-east-1 │
│  │   SCPs: deny GuardDuty/CT/Config delete                  │
│  └── IAM Identity Center (SSO for all accounts)             │
│                                                              │
│  Security OU                                                 │
│  ├── Security Tooling Account                               │
│  │   ├── GuardDuty admin (delegated, org-wide)              │
│  │   ├── Security Hub admin (delegated, org-wide)           │
│  │   ├── Macie admin (delegated, org-wide)                  │
│  │   ├── Config Aggregator (org-wide compliance view)       │
│  │   ├── EventBridge → Lambda/Step Functions (auto-response)│
│  │   └── Forensics VPC                                      │
│  └── Log Archive Account                                    │
│      ├── Org CloudTrail → S3 (all 200 accounts)            │
│      ├── Config history → S3                               │
│      ├── VPC Flow Logs → S3                                │
│      └── S3: versioned + Object Lock + MFA delete          │
│                                                              │
│  Workload Accounts (200)                                    │
│  ├── GuardDuty enabled (auto by org integration)           │
│  ├── Config recorder enabled                               │
│  ├── CloudTrail (org trail covers all)                     │
│  └── Security Hub enabled (findings → Security Tooling)    │
└──────────────────────────────────────────────────────────────┘
```

**Key design decisions:**
- Management account: governance ONLY — no workloads
- Security tooling account: delegated admin for all security services
- Log archive: separate account, immutable logs, no delete
- SCPs: guardrails at root protect security services
- GuardDuty + Security Hub: org integration auto-enables in new accounts

---

## 1.3 Scenario B — Compromised Credential End-to-End Response

### The Incident
GuardDuty generates: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` at 03:00 IST.

### End-to-End Response

```
T+0s: GuardDuty finding generated
      └── Severity: 8.0 (High)

T+5s: EventBridge rule matches → Lambda triggered
      Lambda actions:
      ├── Read finding: EC2 instance i-abc123, access key AKIAXXXXX
      ├── Create EBS snapshot (evidence)
      ├── Swap instance SG to forensics-all-blocked
      ├── Attach inline deny policy to IAM role:
      │   {"Effect":"Deny","Action":"*","Resource":"*",
      │    "Condition":{"DateLessThan":{"aws:TokenIssueTime":"2024-01-15T03:00:00Z"}}}
      └── SNS notification → PagerDuty → on-call engineer

T+2min: On-call engineer wakes up, reviews finding

T+10min: Athena query on CloudTrail:
         SELECT * FROM ct_logs WHERE useridentity.accesskeyid='AKIAXXXXX'
         AND eventtime > '2024-01-14T00:00:00Z'
         → Finds: 3 S3 buckets accessed, 1 IAM user created, 1 access key created

T+20min: Eradication:
         ├── Delete backdoor IAM user created by attacker
         ├── Delete attacker's access key
         ├── Review all IAM changes in attack window
         └── Verify no other persistence mechanisms

T+30min: Recovery:
         ├── Launch replacement EC2 from clean AMI
         ├── Rotate all application credentials
         └── Review why IMDS credentials were accessible externally

T+24hr: Post-incident:
         ├── Root cause: IMDSv1 on instance (no hop limit enforcement)
         ├── Remediation: enforce IMDSv2 via SCP
         │   "ec2:MetadataHttpTokens": "required"
         └── Lessons learned documented
```

---

## 1.4 Scenario C — Data Exfiltration Prevention + Detection

### Architecture for preventing S3 data exfiltration

```
PREVENTION LAYER:
├── S3 Block Public Access (account + org level)
├── S3 VPC Endpoint + endpoint policy (only allow approved S3 buckets)
├── SCP: deny s3:PutBucketPolicy allowing external principals
├── SCP: deny s3:PutBucketAcl with public grants
├── Macie: enabled on all sensitive buckets
└── KMS CMK: bucket encryption (data useless without key)

DETECTION LAYER:
├── S3 data events in CloudTrail (object-level logging)
├── GuardDuty S3 protection: anomalous access patterns
├── Macie: PII/sensitive data classification + access alerts
├── CloudWatch metric filter: high GetObject rate alarm
└── VPC Flow Logs: unusual outbound traffic volumes

RESPONSE LAYER:
├── GuardDuty Exfiltration finding → EventBridge → Lambda
│   ├── Apply bucket policy deny for identified principal
│   └── Revoke principal's IAM credentials
├── Macie finding → SNS → IR team notification
└── CloudTrail Athena query: full list of accessed objects
```

**VPC Endpoint policy to restrict S3 access:**
```json
{
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:*",
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "aws:ResourceAccount": ["YOUR-ACCOUNT-ID"]
    }
  }
}
```
This prevents EC2 instances from using the VPC endpoint to access S3 buckets in other accounts — a common data exfiltration technique.

---

## 1.5 Scenario D — Ransomware Resilience

### Defense-in-Depth Architecture

```
PREVENTION (stop ransomware entering):
├── AWS WAF + Shield: protect web-facing workloads
├── GuardDuty Malware Protection: scan EC2/EBS for malware
├── SSM Patch Manager: zero unpatched CVEs
├── ECR Enhanced Scanning: no vulnerable container images
└── S3 Block Public Access: no public exposure

ISOLATION (limit blast radius):
├── VPC segmentation: dev/staging/prod isolated
├── Security Groups: minimal inter-tier communication
├── NACLs: block known malicious IP ranges
└── No EC2 → EC2 broad access (least privilege SGs)

BACKUP & RECOVERY (survive ransomware):
├── AWS Backup: daily snapshots of all EBS/RDS/EFS
├── Backup Vault Lock (WORM): backups in separate account
│   ├── Min retention: 7 days
│   └── Cannot be deleted even by admin (compliance mode)
├── Cross-region backup replication
├── RDS automated backups (point-in-time recovery)
└── Restore testing: quarterly verified restore exercises

DETECTION:
├── GuardDuty: Trojan/ransomware finding types
├── CloudWatch: disk I/O spike anomaly
└── AWS Backup: backup job failure alarm
```

**Backup Vault Lock (key concept):**
- Prevents deletion of backups even by account root
- Compliance mode = immutable backups
- Minimum retention enforced — critical for ransomware recovery

⚠️ **Gotcha:** Backups in the SAME account as the production workload are vulnerable to ransomware operators who gain account access. Always replicate backups to a **separate, isolated account**.

---

## 1.6 Scenario E — Zero Trust Architecture on AWS

### Zero Trust Principles Applied to AWS

```
Zero Trust: "Never trust, always verify"

AWS Implementation:
├── IDENTITY: IAM Identity Center + MFA for all access
│   ├── No standing admin access (use temporary role assumption)
│   ├── JIT (just-in-time) access via temporary credentials
│   └── PIM-equivalent: require approval for privileged roles
│
├── DEVICE: AWS Verified Access (device posture checks)
│   └── Only compliant devices access internal apps
│
├── NETWORK: No implicit trust between services
│   ├── VPC segmentation + private subnets
│   ├── Security Groups: deny all, allow specific
│   ├── VPC Endpoints: services don't traverse internet
│   ├── mTLS between services (App Mesh)
│   └── AWS Network Firewall: east-west traffic inspection
│
├── APPLICATION: IAM auth for every API call
│   ├── IRSA / Task Roles: per-workload IAM
│   ├── Secrets Manager: no hardcoded credentials
│   └── Code signing: trusted deployments only
│
└── DATA: Classify, encrypt, audit all data access
    ├── Macie: data classification
    ├── KMS CMK: per-workload encryption
    └── CloudTrail + Athena: every access audited
```

---

## 1.7 Scenario F — Indian Regulatory Compliance (CERT-In / RBI / DPDPA)

### Key Requirements

| Regulation | Key Security Requirements | AWS Implementation |
|---|---|---|
| CERT-In (2022) | 6-hr breach reporting, 180-day log retention, VPN/proxy log retention | CloudTrail + S3 (180-day lifecycle), Route53 Resolver Logs, VPC Flow Logs |
| RBI (Digital Payment Security) | Encryption in transit/rest, MFA, WAF, DDoS protection | KMS, TLS enforcement, Shield Advanced, WAF |
| DPDPA (2023) | Data minimization, consent, data localization consideration | Macie, S3 bucket policies, ap-south-1 region enforcement via SCP |
| PCI-DSS | Encryption, network segmentation, access control, logging | VPC segmentation, KMS, CloudTrail, Config conformance pack |

**CERT-In specific AWS config:**
```
Log Retention (180 days minimum):
├── CloudTrail → S3 lifecycle: 180 days S3 Standard → Glacier
├── VPC Flow Logs → S3 lifecycle: 180 days
├── Route53 Resolver Logs: 180 days
└── Application logs (CloudWatch): 180-day retention policy

6-hour Reporting:
├── GuardDuty + Security Hub → PagerDuty
├── EventBridge rule: critical findings → SNS → immediate alert
└── Runbook: CERT-In notification template ready

VPN/Proxy Logs:
├── VPC Flow Logs: network connection metadata
└── ALB Access Logs: HTTP request details
```

---

## 1.8 Scenario G — Secure CI/CD Pipeline

### Threat Model for CI/CD

```
CI/CD Security Threats:
├── Secret exposure in source code (hardcoded creds)
├── Malicious dependencies (supply chain)
├── Insecure pipeline with write access to production
├── Unscanned container images deployed
└── No code integrity verification

Secure CI/CD Architecture:
│
CodeCommit/GitHub
├── Branch protection (no direct main commits)
├── CodeGuru Reviewer (detect hardcoded secrets)
└── Signed commits (code integrity)
        │
        ▼
CodePipeline / CodeBuild
├── Secrets via Secrets Manager (not env vars)
├── ECR image scan (Inspector) before deployment
├── SAST/DAST tools in pipeline
├── Code signing via AWS Signer
└── IAM: pipeline role least privilege (no prod write unless approved)
        │
        ▼
    Approval gate (manual for production)
        │
        ▼
CodeDeploy → Production
├── Blue/green deployment (rollback capability)
├── CloudTrail: all deployment events logged
└── Config: post-deployment compliance check
```

---

## 1.9 Scenario H — Container Security at Scale

### EKS Production Security Checklist

```
CONTROL PLANE:
├── Private API server endpoint (no public endpoint)
├── KMS envelope encryption for etcd
├── EKS audit logs → CloudWatch
└── RBAC: no ClusterAdmin for service accounts

DATA PLANE:
├── IRSA: all pods with scoped IAM roles (no node instance profile usage)
├── Pod Security Standards: Restricted profile
├── Network Policies: Calico/Cilium (deny all, allow specific)
├── Security Groups for Pods: restrict to required AWS services
├── No privileged containers
└── Read-only root filesystem

IMAGE SECURITY:
├── ECR Enhanced Scanning (Inspector): continuous
├── ECR tag immutability: no latest tag overwrite
├── Image signing (Notation/Sigstore)
├── Admission controller: block unscanned/unsigned images
└── No public base images (use approved internal registry)

SECRETS:
├── AWS Secrets Store CSI Driver (no K8s Secrets for sensitive data)
├── KMS envelope encryption for etcd (if K8s Secrets used)
└── No secrets in ConfigMaps or env vars in pod specs

RUNTIME:
├── GuardDuty EKS Runtime Monitoring
├── Falco (runtime anomaly detection)
└── AWS Security Hub: EKS findings aggregation
```

---

# SECTION 2 — EXAM DEEP DIVE

---

## 2.1 Scenario-Based Q&A (20 Questions)

---

**Q1.** A company needs centralized security monitoring across 300 AWS accounts. GuardDuty findings, Config compliance data, and Inspector findings must all appear in one dashboard. What is the architecture?

A) Create IAM cross-account roles from each account to a central account  
B) Security Hub with Organizations integration (delegated admin in security tooling account) aggregating findings from all accounts; Config Aggregator for compliance data  
C) CloudTrail org trail only  
D) Manual export from each account  

**Answer: B**

Security Hub with org integration automatically collects findings from all member accounts into the delegated admin account. Config Aggregator provides org-wide compliance data. Together in the security tooling account, they provide a single-pane-of-glass. GuardDuty org integration ensures all accounts generate findings that flow to Security Hub.

---

**Q2.** An attacker gains access to an EC2 instance role and creates a new IAM admin user at 2 AM. The company wants automated detection and response. What is the architecture?

A) Daily CloudTrail review  
B) CloudTrail → EventBridge rule matching `CreateUser` + `AttachUserPolicy(AdminAccess)` → Lambda (disables new user + notifies IR team)  
C) GuardDuty alone  
D) Config rule for IAM  

**Answer: B**

CloudTrail generates EventBridge events for API calls. An EventBridge rule matching `iam:CreateUser` followed by `iam:AttachUserPolicy` with AdminAccess triggers a Lambda that: disables the new user, captures its details for investigation, and notifies the IR team. GuardDuty may also detect this as `UnauthorizedAccess:IAMUser/AnomalousBehavior`.

---

**Q3.** A fintech company processing RBI-regulated payment data needs to ensure all encryption keys are customer-controlled, rotated annually, and audited on every use. What AWS service satisfies this?

A) AWS-managed KMS keys  
B) Customer-managed KMS keys (CMK) with annual automatic rotation enabled and CloudTrail logging for all key usage  
C) SSE-S3 (AES-256)  
D) TLS certificates from ACM  

**Answer: B**

CMKs provide: customer control over key policy, annual automatic rotation, CloudTrail logs every `kms:Decrypt`/`kms:Encrypt` call with caller identity. AWS-managed keys have limited customer control and audit. SSE-S3 uses AWS-managed keys. ACM is for TLS certificates, not data encryption.

---

**Q4.** A company's CERT-In compliance requires 180-day log retention and 6-hour breach reporting. Which combination meets both requirements?

A) CloudWatch Logs with 7-day retention  
B) CloudTrail + VPC Flow Logs → S3 with 180-day lifecycle policy; GuardDuty + Security Hub → EventBridge → PagerDuty for 6-hour reporting SLA  
C) GuardDuty alone  
D) AWS Config conformance pack  

**Answer: B**

180-day retention: S3 lifecycle policy on CloudTrail + VPC Flow Log buckets (S3 Standard 180 days → Glacier). 6-hour reporting: GuardDuty finding → EventBridge → SNS → PagerDuty/on-call (seconds, well within 6 hours). Also need Route53 Resolver Logs for DNS/VPN logging requirement.

---

**Q5.** A company uses EKS on Fargate. A pod needs to write to DynamoDB. The node has no IAM instance profile. How does the pod authenticate to DynamoDB?

A) Hardcode AWS credentials in the pod spec  
B) IRSA — associate the pod's Kubernetes service account with an IAM role via OIDC; pod uses projected service account token to assume the role  
C) Use a shared IAM user access key stored in a Kubernetes Secret  
D) EKS Fargate uses the management account credentials automatically  

**Answer: B**

IRSA is the correct pattern — no instance profile available on Fargate. The pod's service account is annotated with the IAM role ARN. The EKS OIDC provider federated with IAM allows the pod to assume the role using its projected JWT token. The AWS SDK automatically uses these credentials.

---

**Q6.** A security architect needs to prevent EC2 instances from using IMDSv1 (which allows SSRF-based credential theft). What is the organization-wide enforcement?

A) Update each instance manually  
B) SCP with condition: `"StringNotEquals": {"ec2:MetadataHttpTokens": "required"}` → Deny `ec2:RunInstances` for non-IMDSv2 launches  
C) Config rule only  
D) Security Group rule blocking 169.254.169.254  

**Answer: B**

An SCP denying `ec2:RunInstances` unless `ec2:MetadataHttpTokens` = `required` forces all new instances to use IMDSv2. For existing instances, use SSM Run Command to update IMDS settings fleet-wide. Config rule `ec2-imdsv2-check` can detect non-compliant existing instances.

---

**Q7.** A company wants backups to be protected from ransomware operators who gain AWS account access. What architecture achieves this?

A) Enable versioning on the backup S3 bucket  
B) AWS Backup with Vault Lock (Compliance mode) in a separate, isolated AWS account with SCP denying backup deletion  
C) Backup to an EC2 attached EBS volume  
D) Copy backups to on-premises  

**Answer: B**

Backup Vault Lock in Compliance mode prevents deletion even by account root. Storing in a **separate account** means compromised production account credentials can't reach the backup account. SCP on the backup account denying `backup:DeleteBackupVault` + `backup:DeleteRecoveryPoint` adds an additional layer. This is the ransomware-resilient backup architecture.

---

**Q8.** An application on ECS Fargate needs to connect to an RDS database. The database password must be rotated every 30 days automatically with zero application downtime. What is the architecture?

A) Store password as ECS environment variable, update task definition monthly  
B) Secrets Manager with multi-user rotation (30-day schedule) + ECS task references SM ARN in secrets[] field + application code calls GetSecretValue at connection time (not cached)  
C) SSM Parameter Store with manual rotation  
D) Hardcode in application config file  

**Answer: B**

Multi-user SM rotation ensures zero-downtime rotation. ECS task definition references the SM ARN (not the value). Application code calls `GetSecretValue` at each connection or on connection error (not cached) — ensures it picks up rotated credentials. Fargate doesn't support SSH for manual rotation. SSM has no auto-rotation.

---

**Q9.** A cloud security team wants to detect when any IAM policy is changed to include `"Effect":"Allow","Action":"*","Resource":"*"`. What is the detection architecture?

A) GuardDuty  
B) CloudTrail → EventBridge rule matching `iam:PutUserPolicy` / `iam:PutRolePolicy` / `iam:CreatePolicy` → Lambda analyzes policy document for wildcard patterns → SNS notification  
C) Config rule `iam-no-inline-policy-check`  
D) Macie  

**Answer: B**

CloudTrail captures IAM policy events including the policy document in `requestParameters`. EventBridge routes these to Lambda which inspects the policy JSON for `"Action":"*"` and `"Resource":"*"` patterns. If found, SNS alert to security team. Config rule `iam-no-inline-policy-check` detects inline policies but may not catch specific wildcard patterns.

---

**Q10.** A multi-tier application has web, app, and DB tiers in separate subnets. How should Security Groups be configured for least-privilege network access?

A) One security group for all tiers  
B) Web SG: allow 443 from internet. App SG: allow only from Web SG (port 8080). DB SG: allow only from App SG (port 5432). All SGs: deny all other inbound.  
C) All tiers in public subnets with port 22 open  
D) One NACL blocking all traffic  

**Answer: B**

Tier-specific SGs with SG referencing (allow from source SG ID, not CIDR) provides tight east-west isolation: internet → web only; web → app only; app → DB only. No direct internet → app or DB. SG referencing is preferred over CIDR — auto-adapts as instances scale.

---

**Q11.** A company's CloudTrail is accidentally deleted by a developer. How does the organization prevent this from happening again while ensuring rapid detection if it does?

A) Password-protect the CloudTrail configuration  
B) SCP denying `cloudtrail:DeleteTrail` + `cloudtrail:StopLogging` for all non-management accounts; Config rule `cloudtrail-enabled` with auto-remediation `AWS-EnableCloudTrail`  
C) MFA delete on the S3 bucket  
D) Use Config to back up CloudTrail config  

**Answer: B**

SCP prevents the deletion from happening (preventive). Config rule `cloudtrail-enabled` with auto-remediation `AWS-EnableCloudTrail` detects and re-enables if somehow bypassed (detective + corrective). MFA delete protects the S3 logs but not the trail itself.

---

**Q12.** A penetration tester reports they can access EC2 instance metadata from a web application via SSRF. What is the immediate technical fix?

A) Add a WAF rule blocking internal IP access  
B) Enforce IMDSv2 on the instance (`aws ec2 modify-instance-metadata-options --http-tokens required`) — IMDSv2 requires a PUT request to get a session token before accessing metadata, blocking simple SSRF  
C) Terminate the instance  
D) Change the instance's IAM role  

**Answer: B**

IMDSv2 requires a session-oriented approach: first a PUT request (SSRF can only do GET/POST typically) to get a session token, then use that token for metadata requests. Most SSRF attacks use simple GET requests — IMDSv2 breaks this attack vector. Enforce org-wide via SCP.

---

**Q13.** A company needs to ensure all S3 objects containing PII are encrypted with a specific CMK and that any unencrypted PII objects trigger an alert. What is the architecture?

A) S3 default encryption only  
B) Macie (detect PII in S3) + Config rule `s3-default-encryption-kms` + KMS CMK for bucket encryption + CloudTrail S3 data events for object-level audit  
C) GuardDuty only  
D) IAM policy requiring KMS  

**Answer: B**

Macie continuously scans S3 for PII — alerts when found in unexpected buckets. Config rule ensures bucket-level CMK encryption. KMS CMK encrypts all objects. CloudTrail data events audit every object access. Together: detect PII, enforce encryption, audit access.

---

**Q14.** A company uses AWS Organizations. A member account's admin disables GuardDuty. What prevents this?

A) Config rule  
B) SCP: `"Effect":"Deny","Action":"guardduty:DeleteDetector"` at root; GuardDuty org integration where management account auto-enables and member accounts cannot opt out  
C) IAM policy  
D) CloudTrail  

**Answer: B**

Two defenses: (1) SCP at root denying `guardduty:DeleteDetector` and `guardduty:DisassociateFromMasterAccount` prevents member account admins from deleting their GuardDuty detector. (2) GuardDuty Organizations integration with `AutoEnable: ALL` means even if somehow disabled, the org management re-enables it.

---

**Q15.** A developer's laptop is lost. They had AWS CLI configured with long-term access keys. What is the response procedure?

A) Change the developer's IAM password  
B) Immediately deactivate and delete the access key → CloudTrail audit for any unauthorized usage → review any resources created → rotate application secrets the key had access to → issue new key after verifying laptop recovery/wipe  
C) Wait to see if unauthorized activity occurs  
D) Disable the IAM user  

**Answer: B**

Access key deactivation immediately stops new API calls. CloudTrail audit identifies if the key was used while the laptop was missing (unusual IP, unusual time). Review created/modified resources. Rotate any downstream secrets the key touched. Issue a new key only after device is confirmed wiped. Disabling the user (option D) is also valid but more disruptive to the developer.

---

**Q16.** A company runs microservices on EKS. They want all inter-service communication encrypted. What is the architecture?

A) Security Groups between pods  
B) Service mesh (AWS App Mesh or Istio) with mTLS enforced between all services; ACM Private CA issues certificates  
C) TLS at the ALB only  
D) KMS encryption for all network traffic  

**Answer: B**

A service mesh provides mTLS (mutual TLS) for pod-to-pod communication — both sides present certificates and authenticate each other. ACM Private CA (or cert-manager with Let's Encrypt) issues the certificates. Security Groups control network access but don't encrypt/authenticate. ALB TLS only covers edge traffic.

---

**Q17.** A Security Hub finding indicates "S3 bucket versioning not enabled on a bucket with sensitive data." Why is versioning important for security?

A) Improves S3 performance  
B) Protects against ransomware and accidental deletion — versioning retains previous object versions; combined with Object Lock, provides recovery point after ransomware encryption or deletion  
C) Required for S3 replication  
D) Enables S3 data events  

**Answer: B**

S3 versioning + MFA delete + Object Lock provides a ransomware-resilient data store. Even if an attacker (or ransomware) overwrites all objects, previous versions remain recoverable. Without versioning, a `PutObject` overwrites the only copy permanently.

---

**Q18.** An organization wants to ensure that no AWS resources are ever created outside of ap-south-1 and us-east-1 (for CERT-In data residency). What is the control?

A) Config rule for each resource type  
B) SCP at root: `"Effect":"Deny","Action":"*","Resource":"*","Condition":{"StringNotEquals":{"aws:RequestedRegion":["ap-south-1","us-east-1"]}}` with exemptions for global services  
C) VPC restriction  
D) IAM policy in each account  

**Answer: B**

SCP with `aws:RequestedRegion` condition blocks all API calls outside the approved regions. Note: global services (IAM, STS, Route53, CloudFront) use `us-east-1` as their region and must be exempted: add `"NotAction": ["iam:*","sts:*","route53:*","cloudfront:*"]` or use `aws:RequestedRegion` condition with `StringNotEqualsIfExists`.

---

**Q19.** A company's audit finds that developers have direct access to production databases using admin credentials. What architectural changes address this?

A) Add stronger passwords  
B) Remove direct DB access; implement bastion-less access via SSM Session Manager + Secrets Manager for credential retrieval; DB credentials rotated via SM; access logged via CloudTrail + SSM session logs; break-glass process for emergency access  
C) Add MFA to database  
D) Encrypt the database  

**Answer: B**

Zero-standing access to production: (1) SSM Session Manager replaces SSH bastion, (2) SM provides time-limited, audited credential access, (3) SM rotation removes long-lived shared passwords, (4) CloudTrail + SSM session logs provide full audit. Break-glass for emergencies with heightened alerting on use.

---

**Q20.** A company is designing a new multi-account AWS environment from scratch. They want maximum security, minimal operational overhead, and compliance with ISO 27001 and PCI-DSS. What is the starting point?

A) Build everything manually with CloudFormation  
B) AWS Control Tower landing zone → ISO 27001 + PCI-DSS Conformance Packs → GuardDuty org integration → Security Hub org integration → SCPs for guardrails → IAM Identity Center for SSO → Centralized logging in Log Archive account  
C) Deploy a single hardened account  
D) Purchase a third-party CASB  

**Answer: B**

Control Tower provides the compliant landing zone foundation in hours. Org-level conformance packs apply ISO/PCI Config rules across all accounts. GuardDuty + Security Hub org integration covers all accounts automatically. SCPs enforce preventive guardrails. IAM Identity Center provides federated SSO. Log Archive centralizes all logs. This is the fastest path to a compliant, secure multi-account environment.

---

## 2.2 Common Exam Traps & Distractors (10)

**Trap 1: Single account = simpler to secure**
> ❌ Wrong: "One account is easier to manage and secure"
> ✅ Right: Multi-account provides security boundaries, blast radius limitation, and compliance separation

**Trap 2: GuardDuty auto-remediates**
> ❌ Wrong: "GuardDuty will automatically isolate the compromised EC2"
> ✅ Right: GuardDuty DETECTS only. Build EventBridge → Lambda for automated response.

**Trap 3: IMDSv1 SSRF is just a low-risk finding**
> ❌ Wrong: "SSRF to IMDS is theoretical — low priority"
> ✅ Right: SSRF + IMDSv1 = credential theft = full account compromise. Enforce IMDSv2 immediately.

**Trap 4: CloudTrail alone provides complete security monitoring**
> ❌ Wrong: "CloudTrail covers all security monitoring needs"
> ✅ Right: CloudTrail = API calls. Add GuardDuty (threats), Config (compliance), VPC Flow (network), Macie (data) for complete coverage.

**Trap 5: Backup in same account = protected**
> ❌ Wrong: "AWS Backup in the same account protects against ransomware"
> ✅ Right: Ransomware operators with account access can delete same-account backups. Use separate isolated account + Vault Lock.

**Trap 6: TLS at ALB = all traffic encrypted**
> ❌ Wrong: "ALB TLS encrypts all inter-service communication"
> ✅ Right: ALB TLS covers edge only. Use service mesh with mTLS for pod-to-pod encryption.

**Trap 7: SCP with region restriction breaks global services**
> ❌ Wrong: "Region SCP will break IAM and STS"
> ✅ Right: Exempt global services (iam:*, sts:*, route53:*, cloudfront:*) from region restrictions

**Trap 8: CERT-In = 24-hour reporting**
> ❌ Wrong: "CERT-In requires 24-hour breach reporting"
> ✅ Right: CERT-In (India, 2022 directive) requires 6-hour incident reporting

**Trap 9: IAM user deactivation = all sessions terminated**
> ❌ Wrong: "Disabling IAM user stops all active sessions"
> ✅ Right: Disabling stops new console logins. Existing STS sessions remain valid until expiry. Use TokenIssueTime deny for full revocation.

**Trap 10: Macie detects threats like GuardDuty**
> ❌ Wrong: "Use Macie for threat detection"
> ✅ Right: Macie = data classification + sensitive data discovery in S3. GuardDuty = threat detection. Different purposes.

---

## 2.3 Key Facts Cheat Sheet

```
┌────────────────────────────────────────────────────────────┐
│        REAL-WORLD SCENARIOS — EXAM CHEAT SHEET             │
├──────────────────────────────────┬─────────────────────────┤
│ Multi-account security hub       │ Security Tooling Account│
│ Centralized logs account         │ Log Archive Account     │
│ All accounts GD auto-enable      │ Org integration         │
│ IMDSv2 SSRF protection           │ ec2:MetadataHttpTokens  │
│ Ransomware backup protection     │ Vault Lock + sep account│
│ mTLS between microservices       │ App Mesh / Istio        │
│ Pod AWS access                   │ IRSA                    │
│ CERT-In reporting SLA            │ 6 hours                 │
│ CERT-In log retention            │ 180 days                │
│ Region restriction SCP           │ aws:RequestedRegion     │
│ Global service exemption         │ iam/sts/route53/cf      │
│ SSRF fix                         │ IMDSv2 enforcement      │
│ Zero-downtime secret rotation    │ SM multi-user rotation  │
│ Org-wide GuardDuty disable prev. │ SCP + Org auto-enable   │
│ Compliance from scratch          │ Control Tower first     │
│ Container image supply chain     │ ECR + Inspector + sign  │
│ Standing privilege removal       │ JIT via temp roles      │
│ S3 ransomware protection         │ Versioning + Object Lock│
│ Direct DB access removal         │ SSM + Secrets Manager   │
│ PII detection in S3              │ Amazon Macie            │
└──────────────────────────────────┴─────────────────────────┘
```

---

## 2.4 Elimination Strategies

**Strategy 1: Multi-account visibility → Security Hub + Aggregator**
Single pane across all accounts → eliminate per-account review → **Security Hub org + Config Aggregator**

**Strategy 2: Ransomware-proof backups → Vault Lock + separate account**
Protect backups from account compromise → eliminate same-account backup → **Vault Lock + isolated backup account**

**Strategy 3: SSRF credential theft → IMDSv2**
SSRF attack on instance metadata → eliminate "block SG" → **IMDSv2 required (SCP enforcement)**

**Strategy 4: Pod AWS access (EKS Fargate) → IRSA**
No instance profile available → eliminate hardcoded keys → **IRSA with OIDC**

**Strategy 5: Zero-standing production access → SSM + SM**
No direct SSH / no long-lived DB creds → eliminate bastion/shared creds → **SSM Session Manager + Secrets Manager rotation**

**Strategy 6: Indian compliance (CERT-In) → 6hr alert + 180-day logs**
CERT-In requirements → eliminate 24hr SLA → **GuardDuty → PagerDuty (6hr) + S3 lifecycle 180-day**

---

# 🎯 Days 49–52 Complete — What's Next

```
Week 8 (Days 53–56): Practice Exams
├── Day 53: Full Practice Exam 1 + Review
├── Day 54: Full Practice Exam 2 + Review
├── Day 55: Full Practice Exam 3 + Review
└── Day 56: Weak Areas Deep Dive + Flashcards

Recommended before exams:
├── Review all cheat sheets from Days 40–52
├── Focus on your weak areas from practice exams
├── Master the elimination strategies
└── Schedule exam when consistently scoring 80%+

You're on the final stretch, Pradeep — the hard work is done. 🚀
```
