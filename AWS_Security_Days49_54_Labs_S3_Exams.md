# 📚 AWS Security Specialist — Days 49–54
## Section 3: Labs + Practice Exams
### Pradeep Kumar | Study Plan

---

> **Coverage:**
> - Lab 49: Forensics on AWS
> - Lab 50: AWS Systems Manager
> - Lab 51: Automated Remediation
> - Lab 52: Real-World Scenarios
> - Day 53: Full Practice Exam 1 (25 Questions)
> - Day 54: Full Practice Exam 2 (25 Questions)

---

# 📅 Day 49 — Section 3: Lab 119
## Forensics on AWS — Evidence Collection + Investigation

---

## 🎯 Lab Objective
In this lab you will:
- Create an isolated forensics environment (VPC + SG)
- Launch a simulated "compromised" EC2 instance
- Create forensic EBS snapshot with chain-of-custody tags
- Share snapshot cross-account (simulated)
- Mount evidence volume read-only on forensics instance
- Query CloudTrail logs with Athena for forensic investigation
- Enable Route53 Resolver query logging
- Practice S3 Object Lock for evidence immutability
- Cleanup all resources

---

## Prerequisites Check

```bash
#!/bin/bash
# Lab 119 - Prerequisites Check
# Day 49 - Forensics on AWS

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region || echo "ap-south-1")

cat > /tmp/lab119-env.sh << EOF
export ACCOUNT_ID="$ACCOUNT_ID"
export REGION="$REGION"
export LAB="lab119"
EOF

echo "================================================"
echo "  Lab 119: Forensics on AWS Prerequisites"
echo "================================================"
aws sts get-caller-identity --output table
echo "Region: $REGION"

echo ""
echo "[1] Checking CloudTrail delivery to S3..."
TRAIL_BUCKET=$(aws cloudtrail describe-trails \
  --region $REGION \
  --query 'trailList[?IsMultiRegionTrail==`true`].S3BucketName' \
  --output text 2>/dev/null | head -1)
echo "CloudTrail S3 bucket: ${TRAIL_BUCKET:-Not configured}"
echo "export TRAIL_BUCKET=\"$TRAIL_BUCKET\"" >> /tmp/lab119-env.sh

echo ""
echo "[2] Checking default VPC..."
DEFAULT_VPC=$(aws ec2 describe-vpcs \
  --filters Name=isDefault,Values=true \
  --region $REGION \
  --query 'Vpcs[0].VpcId' \
  --output text)
echo "Default VPC: $DEFAULT_VPC"
echo "export DEFAULT_VPC=\"$DEFAULT_VPC\"" >> /tmp/lab119-env.sh

echo ""
echo "✅ Environment saved to /tmp/lab119-env.sh"
echo "================================================"
```

---

## Part 1 — Evidence Storage Setup (S3 Object Lock)

```bash
#!/bin/bash
# Lab 119 - Part 1: Evidence Storage
source /tmp/lab119-env.sh

echo "================================================"
echo "  Part 1: Evidence S3 Bucket with Object Lock"
echo "================================================"

# Step 1: Create evidence S3 bucket with Object Lock (MUST be at creation)
echo ""
echo "[1] Creating forensic evidence bucket with Object Lock..."
EVIDENCE_BUCKET="lab119-evidence-${ACCOUNT_ID}-${REGION}"

aws s3api create-bucket \
  --bucket $EVIDENCE_BUCKET \
  --region $REGION \
  --create-bucket-configuration LocationConstraint=$REGION \
  --object-lock-enabled-for-bucket 2>/dev/null || \
aws s3api create-bucket \
  --bucket $EVIDENCE_BUCKET \
  --region $REGION \
  --object-lock-enabled-for-bucket 2>/dev/null

echo "✅ Evidence bucket created: $EVIDENCE_BUCKET"
echo "export EVIDENCE_BUCKET=\"$EVIDENCE_BUCKET\"" >> /tmp/lab119-env.sh

# Enable versioning (required for Object Lock)
aws s3api put-bucket-versioning \
  --bucket $EVIDENCE_BUCKET \
  --versioning-configuration Status=Enabled \
  --region $REGION
echo "✅ Versioning enabled"

# Configure Object Lock default retention (Governance mode, 90 days)
aws s3api put-object-lock-configuration \
  --bucket $EVIDENCE_BUCKET \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "GOVERNANCE",
        "Days": 90
      }
    }
  }' \
  --region $REGION 2>/dev/null && \
  echo "✅ Object Lock: GOVERNANCE mode, 90-day default retention" || \
  echo "⚠️  Object Lock configuration may require specific permissions"

# Step 2: Block all public access
aws s3api put-public-access-block \
  --bucket $EVIDENCE_BUCKET \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
  --region $REGION
echo "✅ Public access blocked"

# Step 3: Enable access logging on evidence bucket
LOGS_BUCKET="lab119-evidence-logs-${ACCOUNT_ID}"
aws s3api create-bucket \
  --bucket $LOGS_BUCKET \
  --region $REGION \
  --create-bucket-configuration LocationConstraint=$REGION 2>/dev/null || \
  aws s3api create-bucket --bucket $LOGS_BUCKET --region $REGION 2>/dev/null

aws s3api put-bucket-logging \
  --bucket $EVIDENCE_BUCKET \
  --bucket-logging-status "{
    \"LoggingEnabled\": {
      \"TargetBucket\": \"$LOGS_BUCKET\",
      \"TargetPrefix\": \"evidence-access-logs/\"
    }
  }" \
  --region $REGION 2>/dev/null && echo "✅ Access logging enabled"

echo "export LOGS_BUCKET=\"$LOGS_BUCKET\"" >> /tmp/lab119-env.sh

echo ""
echo "================================================"
echo "Part 1 Complete!"
echo "================================================"
```

---

## Part 2 — Launch Simulated Victim + Forensic Snapshot

```bash
#!/bin/bash
# Lab 119 - Part 2: Victim EC2 + Forensic Snapshot
source /tmp/lab119-env.sh

echo "================================================"
echo "  Part 2: Simulated Victim + Forensic Snapshot"
echo "================================================"

# Step 1: Create forensics security group
echo ""
echo "[1] Creating forensics isolation security group..."
FORENSICS_SG=$(aws ec2 create-security-group \
  --group-name "lab119-forensics-sg" \
  --description "FORENSICS: All traffic blocked" \
  --vpc-id $DEFAULT_VPC \
  --region $REGION \
  --query 'GroupId' \
  --output text)

# Remove default egress rule
aws ec2 revoke-security-group-egress \
  --group-id $FORENSICS_SG \
  --protocol -1 \
  --port -1 \
  --cidr 0.0.0.0/0 \
  --region $REGION 2>/dev/null

aws ec2 create-tags \
  --resources $FORENSICS_SG \
  --tags Key=Name,Value=FORENSICS-ISOLATED \
  --region $REGION
echo "✅ Forensics SG: $FORENSICS_SG (no inbound, no outbound)"
echo "export FORENSICS_SG=\"$FORENSICS_SG\"" >> /tmp/lab119-env.sh

# Step 2: Launch simulated victim EC2
echo ""
echo "[2] Launching simulated victim EC2 instance..."
DEFAULT_SUBNET=$(aws ec2 describe-subnets \
  --filters Name=vpc-id,Values=$DEFAULT_VPC \
  --region $REGION \
  --query 'Subnets[0].SubnetId' \
  --output text)

AMI_ID=$(aws ec2 describe-images \
  --owners amazon \
  --filters "Name=name,Values=amzn2-ami-hvm-*-x86_64-gp2" \
            "Name=state,Values=available" \
  --query 'sort_by(Images,&CreationDate)[-1].ImageId' \
  --output text --region $REGION)

VICTIM_ID=$(aws ec2 run-instances \
  --image-id $AMI_ID \
  --instance-type t3.micro \
  --subnet-id $DEFAULT_SUBNET \
  --no-associate-public-ip-address \
  --tag-specifications \
    "ResourceType=instance,Tags=[{Key=Name,Value=lab119-victim},{Key=Lab,Value=lab119}]" \
  --region $REGION \
  --query 'Instances[0].InstanceId' \
  --output text)

echo "✅ Victim instance: $VICTIM_ID"
echo "export VICTIM_ID=\"$VICTIM_ID\"" >> /tmp/lab119-env.sh

echo ""
echo "[3] Waiting for instance to reach running state..."
aws ec2 wait instance-running \
  --instance-ids $VICTIM_ID \
  --region $REGION
echo "✅ Instance running"

# Step 3: CONTAINMENT — isolate with forensics SG
echo ""
echo "[4] Containment: Isolating victim with forensics SG..."
aws ec2 modify-instance-attribute \
  --instance-id $VICTIM_ID \
  --groups $FORENSICS_SG \
  --region $REGION
echo "✅ Victim ISOLATED — all network traffic blocked"

# Step 4: Create forensic EBS snapshot with chain-of-custody tags
echo ""
echo "[5] Creating forensic EBS snapshot (evidence preservation)..."
VOLUME_ID=$(aws ec2 describe-instances \
  --instance-ids $VICTIM_ID \
  --region $REGION \
  --query 'Reservations[0].Instances[0].BlockDeviceMappings[0].Ebs.VolumeId' \
  --output text)

CASE_ID="IR-$(date +%Y%m%d)-001"
SNAPSHOT_ID=$(aws ec2 create-snapshot \
  --volume-id $VOLUME_ID \
  --description "FORENSICS-${VICTIM_ID}-${CASE_ID}" \
  --tag-specifications "ResourceType=snapshot,Tags=[
    {Key=Purpose,Value=Forensics},
    {Key=CaseId,Value=$CASE_ID},
    {Key=InstanceId,Value=$VICTIM_ID},
    {Key=Analyst,Value=PradeepKumar},
    {Key=CollectionTime,Value=$(date -u +%Y-%m-%dT%H:%M:%SZ)},
    {Key=FindingType,Value=Backdoor-EC2-C2Activity},
    {Key=Lab,Value=lab119}
  ]" \
  --region $REGION \
  --query 'SnapshotId' \
  --output text)

echo "✅ Forensic snapshot: $SNAPSHOT_ID"
echo "   Case ID: $CASE_ID"
echo "   Tagged with: Purpose, CaseId, Analyst, CollectionTime"
echo "export SNAPSHOT_ID=\"$SNAPSHOT_ID\"" >> /tmp/lab119-env.sh
echo "export CASE_ID=\"$CASE_ID\"" >> /tmp/lab119-env.sh
echo "export VOLUME_ID=\"$VOLUME_ID\"" >> /tmp/lab119-env.sh

echo ""
echo "================================================"
echo "Part 2 Complete!"
echo "================================================"
```

---

## Part 3 — Forensic Analysis Instance + Read-Only Mount

```bash
#!/bin/bash
# Lab 119 - Part 3: Forensic Analysis
source /tmp/lab119-env.sh

echo "================================================"
echo "  Part 3: Forensic Analysis Setup"
echo "================================================"

# Step 1: Wait for snapshot completion
echo ""
echo "[1] Waiting for forensic snapshot to complete..."
aws ec2 wait snapshot-completed \
  --snapshot-ids $SNAPSHOT_ID \
  --region $REGION
echo "✅ Snapshot complete: $SNAPSHOT_ID"

# Step 2: Compute integrity hash (chain of custody)
echo ""
echo "[2] Chain of custody — snapshot metadata hash..."
SNAP_INFO=$(aws ec2 describe-snapshots \
  --snapshot-ids $SNAPSHOT_ID \
  --region $REGION \
  --query 'Snapshots[0].{Id:SnapshotId,Volume:VolumeId,Size:VolumeSize,State:State,StartTime:StartTime}' \
  --output json)
echo "$SNAP_INFO" | python3 -m json.tool

SNAP_HASH=$(echo "$SNAP_INFO" | sha256sum | cut -d' ' -f1)
echo ""
echo "SHA-256 of snapshot metadata: $SNAP_HASH"
echo "(Store this in case log for integrity verification)"

# Step 3: Upload hash to evidence bucket (integrity record)
echo ""
echo "[3] Uploading integrity record to evidence S3 bucket..."
cat > /tmp/lab119-chain-of-custody.json << EOF
{
  "case_id": "$CASE_ID",
  "evidence_type": "EBS_SNAPSHOT",
  "snapshot_id": "$SNAPSHOT_ID",
  "source_instance": "$VICTIM_ID",
  "source_volume": "$VOLUME_ID",
  "collection_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "analyst": "PradeepKumar",
  "integrity_hash": "$SNAP_HASH",
  "collection_method": "aws ec2 create-snapshot",
  "isolation_before_collection": true,
  "notes": "Victim isolated with forensics SG before snapshot"
}
EOF

aws s3 cp /tmp/lab119-chain-of-custody.json \
  "s3://$EVIDENCE_BUCKET/cases/$CASE_ID/chain-of-custody.json" \
  --region $REGION && \
  echo "✅ Chain of custody record uploaded to S3"

# Step 4: Create forensics analysis volume from snapshot
echo ""
echo "[4] Creating forensic analysis volume from snapshot..."
FORENSIC_VOL_ID=$(aws ec2 create-volume \
  --snapshot-id $SNAPSHOT_ID \
  --availability-zone "${REGION}a" \
  --volume-type gp3 \
  --tag-specifications "ResourceType=volume,Tags=[
    {Key=Name,Value=lab119-forensic-analysis},
    {Key=CaseId,Value=$CASE_ID},
    {Key=Purpose,Value=ForensicAnalysis}
  ]" \
  --region $REGION \
  --query 'VolumeId' \
  --output text)

echo "✅ Forensic analysis volume: $FORENSIC_VOL_ID"
echo "export FORENSIC_VOL_ID=\"$FORENSIC_VOL_ID\"" >> /tmp/lab119-env.sh

# Step 5: Show read-only mount command (would run on forensics instance)
echo ""
echo "[5] Read-only mount procedure (runs on forensics EC2)..."
cat << 'EOF'
# After attaching forensic volume to forensics EC2 as /dev/sdf:

# Check available devices
lsblk

# Mount READ-ONLY (critical - never write to evidence)
sudo mount -o ro,noexec,noatime /dev/xvdf1 /mnt/evidence

# Verify read-only
mount | grep evidence
# Should show: ro (read-only)

# File system analysis
sudo find /mnt/evidence -name "*.sh" -newer /mnt/evidence/etc/passwd
sudo ls -la /mnt/evidence/tmp/
sudo cat /mnt/evidence/var/log/secure

# Check for persistence mechanisms
sudo crontab -l -u root --root /mnt/evidence
sudo cat /mnt/evidence/etc/cron.d/*
sudo ls /mnt/evidence/etc/init.d/

# Hash all evidence files
sudo find /mnt/evidence -type f -exec sha256sum {} \; > /tmp/evidence-hashes.txt

# Unmount when done (never force-unmount)
sudo umount /mnt/evidence
EOF

echo ""
echo "================================================"
echo "Part 3 Complete!"
echo "================================================"
```

---

## Part 4 — Route53 Resolver Logs + Athena CloudTrail Query

```bash
#!/bin/bash
# Lab 119 - Part 4: DNS Logging + Athena
source /tmp/lab119-env.sh

echo "================================================"
echo "  Part 4: Route53 Resolver Logs + Athena"
echo "================================================"

# Step 1: Enable Route53 Resolver query logging
echo ""
echo "[1] Enabling Route53 Resolver query logging..."
RESOLVER_LOG_CONFIG=$(aws route53resolver create-resolver-query-log-config \
  --name "lab119-dns-logs" \
  --destination-arn "arn:aws:s3:::$EVIDENCE_BUCKET/dns-logs/" \
  --region $REGION \
  --query 'ResolverQueryLogConfig.{Id:Id,Status:Status}' \
  --output table 2>/dev/null)

RESOLVER_CONFIG_ID=$(aws route53resolver list-resolver-query-log-configs \
  --region $REGION \
  --query 'ResolverQueryLogConfigs[?Name==`lab119-dns-logs`].Id' \
  --output text 2>/dev/null)

if [ ! -z "$RESOLVER_CONFIG_ID" ] && [ "$RESOLVER_CONFIG_ID" != "None" ]; then
  # Associate with VPC
  aws route53resolver associate-resolver-query-log-config \
    --resolver-query-log-config-id $RESOLVER_CONFIG_ID \
    --resource-id $DEFAULT_VPC \
    --region $REGION 2>/dev/null && \
    echo "✅ Route53 Resolver logging enabled for VPC: $DEFAULT_VPC"
  echo "export RESOLVER_CONFIG_ID=\"$RESOLVER_CONFIG_ID\"" >> /tmp/lab119-env.sh
else
  echo "⚠️  Route53 Resolver logging setup requires specific permissions"
fi

# Step 2: Athena setup for CloudTrail queries
echo ""
echo "[2] Athena forensic query templates..."
cat << 'ATHENA_EOF'
-- =====================================================
-- FORENSIC ATHENA QUERIES (run in Athena console)
-- Assumes CloudTrail table: cloudtrail_logs
-- =====================================================

-- Query 1: All actions by a compromised access key
SELECT
  eventtime,
  eventname,
  eventsource,
  sourceipaddress,
  useragent,
  awsregion,
  requestparameters,
  errorcode
FROM cloudtrail_logs
WHERE useridentity.accesskeyid = 'AKIAEXAMPLE_COMPROMISED'
  AND eventtime >= '2024-01-15T00:00:00Z'
  AND eventtime <= '2024-01-16T23:59:59Z'
ORDER BY eventtime ASC;

-- Query 2: IAM changes (backdoor detection)
SELECT
  eventtime,
  eventname,
  useridentity.arn AS caller,
  requestparameters
FROM cloudtrail_logs
WHERE eventsource = 'iam.amazonaws.com'
  AND eventname IN (
    'CreateUser','CreateRole','AttachUserPolicy',
    'AttachRolePolicy','CreateAccessKey','PutRolePolicy'
  )
  AND eventtime >= '2024-01-15T00:00:00Z'
ORDER BY eventtime ASC;

-- Query 3: S3 data exfiltration check
SELECT
  eventtime,
  useridentity.arn AS caller,
  requestparameters,
  sourceipaddress,
  COUNT(*) AS object_count
FROM cloudtrail_logs
WHERE eventname = 'GetObject'
  AND eventsource = 's3.amazonaws.com'
  AND eventtime >= '2024-01-15T00:00:00Z'
GROUP BY eventtime, useridentity.arn, requestparameters, sourceipaddress
ORDER BY object_count DESC
LIMIT 100;

-- Query 4: Console logins from unknown IPs
SELECT
  eventtime,
  useridentity.username,
  sourceipaddress,
  additionalEventData,
  errorcode
FROM cloudtrail_logs
WHERE eventname = 'ConsoleLogin'
  AND sourceipaddress NOT IN ('203.0.113.0','198.51.100.0')
  AND eventtime >= '2024-01-01T00:00:00Z'
ORDER BY eventtime DESC;

-- Query 5: GuardDuty finding correlation
SELECT
  eventtime,
  eventname,
  useridentity.arn,
  sourceipaddress,
  requestparameters
FROM cloudtrail_logs
WHERE sourceipaddress = '185.220.101.1'  -- Replace with IOC IP
  AND eventtime >= '2024-01-15T00:00:00Z'
ORDER BY eventtime;
ATHENA_EOF

echo ""
echo "[3] Creating Athena workgroup for forensics..."
aws athena create-work-group \
  --name "lab119-forensics" \
  --description "Lab119 forensic investigation workgroup" \
  --configuration \
    "ResultConfiguration={OutputLocation=s3://$EVIDENCE_BUCKET/athena-results/},
     EnforceWorkGroupConfiguration=true,
     PublishCloudWatchMetricsEnabled=true" \
  --region $REGION 2>/dev/null && \
  echo "✅ Athena workgroup created: lab119-forensics" || \
  echo "⚠️  Athena workgroup creation may require specific permissions"

echo ""
echo "================================================"
echo "Part 4 Complete!"
echo "================================================"
```

---

## Part 5 — Cleanup

```bash
#!/bin/bash
# Lab 119 - Part 5: Cleanup
source /tmp/lab119-env.sh

echo "================================================"
echo "  Part 5: Cleanup All Lab 119 Resources"
echo "================================================"

echo ""
echo "[1] Terminating victim instance..."
aws ec2 terminate-instances \
  --instance-ids $VICTIM_ID \
  --region $REGION 2>/dev/null && echo "✅ Victim terminated"

echo ""
echo "[2] Deleting forensic analysis volume..."
aws ec2 delete-volume \
  --volume-id $FORENSIC_VOL_ID \
  --region $REGION 2>/dev/null && echo "✅ Forensic volume deleted"

echo ""
echo "[3] Waiting for victim termination..."
aws ec2 wait instance-terminated \
  --instance-ids $VICTIM_ID \
  --region $REGION 2>/dev/null

echo ""
echo "[4] Deleting forensics security group..."
aws ec2 delete-security-group \
  --group-id $FORENSICS_SG \
  --region $REGION 2>/dev/null && echo "✅ Forensics SG deleted"

echo ""
echo "[5] Disassociating + deleting Route53 resolver log config..."
if [ ! -z "$RESOLVER_CONFIG_ID" ]; then
  ASSOC_ID=$(aws route53resolver list-resolver-query-log-config-associations \
    --region $REGION \
    --query "ResolverQueryLogConfigAssociations[?ResolverQueryLogConfigId=='$RESOLVER_CONFIG_ID'].Id" \
    --output text 2>/dev/null)
  if [ ! -z "$ASSOC_ID" ]; then
    aws route53resolver disassociate-resolver-query-log-config \
      --resolver-query-log-config-id $RESOLVER_CONFIG_ID \
      --resource-id $DEFAULT_VPC \
      --region $REGION 2>/dev/null && echo "✅ DNS log config disassociated"
  fi
  aws route53resolver delete-resolver-query-log-config \
    --resolver-query-log-config-id $RESOLVER_CONFIG_ID \
    --region $REGION 2>/dev/null && echo "✅ DNS log config deleted"
fi

echo ""
echo "[6] Deleting Athena workgroup..."
aws athena delete-work-group \
  --work-group "lab119-forensics" \
  --recursive-delete-option \
  --region $REGION 2>/dev/null && echo "✅ Athena workgroup deleted"

echo ""
echo "[7] Deleting evidence bucket (remove Object Lock first)..."
echo "    Note: Object Lock objects cannot be deleted before retention expires"
echo "    In a real case, retain evidence per policy"
aws s3 rm s3://$EVIDENCE_BUCKET --recursive \
  --region $REGION 2>/dev/null
aws s3 rb s3://$EVIDENCE_BUCKET --force \
  --region $REGION 2>/dev/null && echo "✅ Evidence bucket deleted"

aws s3 rb s3://$LOGS_BUCKET --force \
  --region $REGION 2>/dev/null && echo "✅ Logs bucket deleted"

echo ""
echo "[8] Cleanup temp files..."
rm -f /tmp/lab119-env.sh /tmp/lab119-chain-of-custody.json
echo "✅ Temp files cleaned"

echo ""
echo "================================================"
echo "Lab 119 Cleanup Complete!"
echo "================================================"
```

---

## ✅ Lab 119 Verification Checklist

```
Lab 119 — Forensics on AWS Checklist
│
├── Part 1: Evidence Storage
│     ├── [ ] S3 bucket with Object Lock ENABLED at creation
│     ├── [ ] GOVERNANCE mode, 90-day retention
│     ├── [ ] Versioning enabled
│     ├── [ ] Public access blocked
│     └── [ ] Access logging to separate bucket
│
├── Part 2: Victim + Snapshot
│     ├── [ ] Forensics SG: zero inbound + zero outbound
│     ├── [ ] Victim isolated BEFORE snapshot
│     ├── [ ] Snapshot created with forensic tags
│     ├── [ ] Tags: CaseId, Analyst, CollectionTime, FindingType
│     └── [ ] Chain of custody record uploaded to S3
│
├── Part 3: Forensic Analysis
│     ├── [ ] Snapshot completed
│     ├── [ ] Integrity hash computed + stored
│     ├── [ ] Forensic volume created from snapshot
│     ├── [ ] Read-only mount command reviewed (-o ro,noexec)
│     └── [ ] Persistence mechanism check commands reviewed
│
├── Part 4: Logging + Athena
│     ├── [ ] Route53 Resolver logging enabled
│     ├── [ ] 5 Athena forensic query templates reviewed
│     ├── [ ] Athena workgroup created (results to evidence bucket)
│     └── [ ] Compromised key query template practiced
│
└── Part 5: Cleanup
      └── [ ] All resources deleted
```

---

## 🔑 Lab 119 Key Takeaways

| Concept | What You Practiced |
|---|---|
| Object Lock at creation | Cannot enable after bucket creation |
| GOVERNANCE vs COMPLIANCE | Governance = admin override; Compliance = nobody |
| Isolate before snapshot | Containment first, then preserve evidence |
| Read-only mount flag | `-o ro,noexec,noatime` |
| Chain of custody | Tags + S3 record + integrity hash |
| Route53 Resolver logs | DNS queries — detect DNS tunneling |
| Athena forensic queries | SQL over CloudTrail S3 data at scale |

---

# 📅 Day 50 — Section 3: Lab 120
## AWS Systems Manager — Session Manager + Patch Manager + Parameter Store

---

## 🎯 Lab Objective
In this lab you will:
- Launch EC2 with SSM managed instance core profile
- Configure Session Manager with S3 session logging
- Access EC2 instance via Session Manager (no SSH)
- Create SSM Parameter Store SecureString with CMK
- Run SSM Run Command across instances
- Configure Patch Manager baseline + scan
- Enable SSM Inventory
- Cleanup all resources

---

## Prerequisites Check

```bash
#!/bin/bash
# Lab 120 - Prerequisites Check
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region || echo "ap-south-1")

cat > /tmp/lab120-env.sh << EOF
export ACCOUNT_ID="$ACCOUNT_ID"
export REGION="$REGION"
export LAB="lab120"
EOF

echo "================================================"
echo "  Lab 120: AWS Systems Manager Prerequisites"
echo "================================================"
aws sts get-caller-identity --output table
echo "Region: $REGION"

echo ""
echo "[1] Checking SSM managed instances..."
aws ssm describe-instance-information \
  --region $REGION \
  --query 'InstanceInformationList[*].{InstanceId:InstanceId,PingStatus:PingStatus,PlatformType:PlatformType}' \
  --output table 2>/dev/null || echo "No managed instances found"

echo ""
echo "[2] Checking existing Session Manager preferences..."
aws ssm get-document \
  --name "SSM-SessionManagerRunShell" \
  --region $REGION \
  --query 'Document.DocumentVersion' \
  --output text 2>/dev/null && echo "✅ Session Manager configured" || \
  echo "ℹ️  Session Manager not yet configured"

echo ""
echo "✅ Environment saved to /tmp/lab120-env.sh"
echo "================================================"
```

---

## Part 1 — EC2 Instance with SSM Profile

```bash
#!/bin/bash
# Lab 120 - Part 1: EC2 + SSM Instance Profile
source /tmp/lab120-env.sh

echo "================================================"
echo "  Part 1: EC2 + SSM Managed Instance Profile"
echo "================================================"

# Step 1: Create EC2 instance profile with SSM managed policy
echo ""
echo "[1] Creating SSM instance profile..."
cat > /tmp/lab120-ec2-trust.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ec2.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF

EC2_ROLE_ARN=$(aws iam create-role \
  --role-name "lab120-ssm-ec2-role" \
  --assume-role-policy-document file:///tmp/lab120-ec2-trust.json \
  --query 'Role.Arn' --output text)

# Attach SSM managed instance core policy
aws iam attach-role-policy \
  --role-name "lab120-ssm-ec2-role" \
  --policy-arn "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"

# Create instance profile
aws iam create-instance-profile \
  --instance-profile-name "lab120-ssm-instance-profile" 2>/dev/null
aws iam add-role-to-instance-profile \
  --instance-profile-name "lab120-ssm-instance-profile" \
  --role-name "lab120-ssm-ec2-role"

echo "✅ SSM instance profile: lab120-ssm-instance-profile"
echo "export EC2_ROLE_ARN=\"$EC2_ROLE_ARN\"" >> /tmp/lab120-env.sh
sleep 10

# Step 2: Create SSM session logging S3 bucket
echo ""
echo "[2] Creating session logs S3 bucket..."
SESSION_LOGS_BUCKET="lab120-session-logs-${ACCOUNT_ID}"
aws s3api create-bucket \
  --bucket $SESSION_LOGS_BUCKET \
  --region $REGION \
  --create-bucket-configuration LocationConstraint=$REGION 2>/dev/null || \
  aws s3api create-bucket --bucket $SESSION_LOGS_BUCKET --region $REGION 2>/dev/null

aws s3api put-public-access-block \
  --bucket $SESSION_LOGS_BUCKET \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

echo "✅ Session logs bucket: $SESSION_LOGS_BUCKET"
echo "export SESSION_LOGS_BUCKET=\"$SESSION_LOGS_BUCKET\"" >> /tmp/lab120-env.sh

# Step 3: Configure Session Manager preferences (logging)
echo ""
echo "[3] Configuring Session Manager session logging..."
aws ssm update-document \
  --name "SSM-SessionManagerRunShell" \
  --document-version "\$LATEST" \
  --content "{
    \"schemaVersion\": \"1.0\",
    \"description\": \"Lab120 Session Manager preferences\",
    \"sessionType\": \"Standard_Stream\",
    \"inputs\": {
      \"s3BucketName\": \"$SESSION_LOGS_BUCKET\",
      \"s3KeyPrefix\": \"session-logs\",
      \"s3EncryptionEnabled\": true,
      \"cloudWatchLogGroupName\": \"/aws/ssm/lab120-sessions\",
      \"cloudWatchEncryptionEnabled\": false,
      \"cloudWatchStreamingEnabled\": true,
      \"runAsEnabled\": false,
      \"shellProfile\": {
        \"linux\": \"cd ~ && exec bash\"
      }
    }
  }" \
  --region $REGION 2>/dev/null && \
  echo "✅ Session Manager logging configured (S3 + CloudWatch)" || \
  echo "ℹ️  Creating new preferences document..."

# Step 4: Launch SSM-managed EC2
echo ""
echo "[4] Launching SSM-managed EC2 instance..."
DEFAULT_VPC=$(aws ec2 describe-vpcs \
  --filters Name=isDefault,Values=true \
  --region $REGION \
  --query 'Vpcs[0].VpcId' --output text)

DEFAULT_SUBNET=$(aws ec2 describe-subnets \
  --filters Name=vpc-id,Values=$DEFAULT_VPC \
  --region $REGION \
  --query 'Subnets[0].SubnetId' --output text)

AMI_ID=$(aws ec2 describe-images \
  --owners amazon \
  --filters "Name=name,Values=amzn2-ami-hvm-*-x86_64-gp2" \
            "Name=state,Values=available" \
  --query 'sort_by(Images,&CreationDate)[-1].ImageId' \
  --output text --region $REGION)

INSTANCE_ID=$(aws ec2 run-instances \
  --image-id $AMI_ID \
  --instance-type t3.micro \
  --subnet-id $DEFAULT_SUBNET \
  --iam-instance-profile Name=lab120-ssm-instance-profile \
  --no-associate-public-ip-address \
  --tag-specifications \
    "ResourceType=instance,Tags=[{Key=Name,Value=lab120-ssm-managed},{Key=Lab,Value=lab120},{Key=PatchGroup,Value=lab120-linux}]" \
  --region $REGION \
  --query 'Instances[0].InstanceId' --output text)

echo "✅ Instance launched: $INSTANCE_ID"
echo "   No SSH key assigned — SSM Session Manager only"
echo "export INSTANCE_ID=\"$INSTANCE_ID\"" >> /tmp/lab120-env.sh

echo ""
echo "[5] Waiting for instance + SSM registration (~2-3 min)..."
aws ec2 wait instance-running \
  --instance-ids $INSTANCE_ID \
  --region $REGION
echo "✅ EC2 running — waiting 60s for SSM agent registration..."
sleep 60

echo ""
echo "================================================"
echo "Part 1 Complete!"
echo "================================================"
```

---

## Part 2 — Parameter Store + Run Command

```bash
#!/bin/bash
# Lab 120 - Part 2: Parameter Store + Run Command
source /tmp/lab120-env.sh

echo "================================================"
echo "  Part 2: Parameter Store + Run Command"
echo "================================================"

# Step 1: Create KMS CMK for SecureString
echo ""
echo "[1] Creating KMS CMK for Parameter Store..."
PS_KEY_ID=$(aws kms create-key \
  --description "Lab120 SSM Parameter Store CMK" \
  --query 'KeyMetadata.KeyId' --output text --region $REGION)
aws kms create-alias \
  --alias-name "alias/lab120-ssm-cmk" \
  --target-key-id $PS_KEY_ID \
  --region $REGION
echo "✅ CMK: $PS_KEY_ID"
echo "export PS_KEY_ID=\"$PS_KEY_ID\"" >> /tmp/lab120-env.sh

# Step 2: Create parameters (String, SecureString, hierarchy)
echo ""
echo "[2] Creating SSM Parameter Store parameters..."
aws ssm put-parameter \
  --name "/lab120/prod/app/db-host" \
  --value "prod-db.lab120.internal" \
  --type String --region $REGION
echo "✅ String: /lab120/prod/app/db-host"

aws ssm put-parameter \
  --name "/lab120/prod/app/db-port" \
  --value "5432" \
  --type String --region $REGION
echo "✅ String: /lab120/prod/app/db-port"

aws ssm put-parameter \
  --name "/lab120/prod/app/db-password" \
  --value "S3cur3DBP@ssLab120!" \
  --type SecureString \
  --key-id $PS_KEY_ID \
  --region $REGION
echo "✅ SecureString: /lab120/prod/app/db-password (KMS encrypted)"

# Step 3: Retrieve parameters
echo ""
echo "[3] Retrieving parameters..."
echo "String retrieval:"
aws ssm get-parameter \
  --name "/lab120/prod/app/db-host" \
  --region $REGION \
  --query 'Parameter.{Name:Name,Type:Type,Value:Value}' \
  --output table

echo ""
echo "SecureString retrieval (requires kms:Decrypt):"
aws ssm get-parameter \
  --name "/lab120/prod/app/db-password" \
  --with-decryption \
  --region $REGION \
  --query 'Parameter.{Name:Name,Type:Type}' \
  --output table
echo "(Value: [REDACTED] — decrypted but not displayed)"

echo ""
echo "Path-based retrieval (all /lab120/prod/app/*):"
aws ssm get-parameters-by-path \
  --path "/lab120/prod/app" \
  --with-decryption \
  --region $REGION \
  --query 'Parameters[*].{Name:Name,Type:Type}' \
  --output table

# Step 4: SSM Run Command
echo ""
echo "[4] Running SSM Run Command on managed instance..."
echo "    Checking if instance is registered with SSM..."
SSM_STATUS=$(aws ssm describe-instance-information \
  --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
  --region $REGION \
  --query 'InstanceInformationList[0].PingStatus' \
  --output text 2>/dev/null)

if [ "$SSM_STATUS" == "Online" ]; then
  COMMAND_ID=$(aws ssm send-command \
    --instance-ids $INSTANCE_ID \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=[
      "echo [INFO] SSM Run Command executing",
      "whoami",
      "hostname",
      "uptime",
      "df -h /",
      "echo [INFO] Checking for suspicious processes:",
      "ps aux | grep -v grep | grep -E '\''(nc|ncat|python|perl|ruby)'\'' || echo No suspicious processes",
      "echo [DONE] Script complete"
    ]' \
    --region $REGION \
    --query 'Command.CommandId' \
    --output text)

  echo "✅ Run Command dispatched: $COMMAND_ID"
  sleep 10

  aws ssm get-command-invocation \
    --command-id $COMMAND_ID \
    --instance-id $INSTANCE_ID \
    --region $REGION \
    --query '{Status:Status,Output:StandardOutputContent}' \
    --output json | python3 -m json.tool
else
  echo "⚠️  Instance not yet registered with SSM (status: $SSM_STATUS)"
  echo "    Showing Run Command syntax for exam reference:"
  cat << 'EOF'
aws ssm send-command \
  --instance-ids i-INSTANCEID \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["command1","command2"]' \
  --max-errors 5 \
  --max-concurrency "50%" \
  --region REGION
EOF
fi

echo ""
echo "================================================"
echo "Part 2 Complete!"
echo "================================================"
```

---

## Part 3 — Patch Manager + Inventory + Cleanup

```bash
#!/bin/bash
# Lab 120 - Part 3: Patch Manager + Cleanup
source /tmp/lab120-env.sh

echo "================================================"
echo "  Part 3: Patch Manager + Inventory + Cleanup"
echo "================================================"

# Step 1: Create custom patch baseline
echo ""
echo "[1] Creating custom patch baseline for Amazon Linux 2..."
BASELINE_ID=$(aws ssm create-patch-baseline \
  --name "lab120-AmazonLinux2-Security-Baseline" \
  --operating-system AMAZON_LINUX_2 \
  --description "Lab120 baseline: Critical patches auto-approved" \
  --approval-rules '{
    "PatchRules": [
      {
        "PatchFilterGroup": {
          "PatchFilters": [
            {"Key": "CLASSIFICATION", "Values": ["Security","Bugfix"]},
            {"Key": "SEVERITY", "Values": ["Critical","Important"]}
          ]
        },
        "ApproveAfterDays": 0,
        "EnableNonSecurity": false
      }
    ]
  }' \
  --region $REGION \
  --query 'BaselineId' \
  --output text)

echo "✅ Patch baseline created: $BASELINE_ID"
echo "   Critical + Important security patches: approved after 0 days"
echo "export BASELINE_ID=\"$BASELINE_ID\"" >> /tmp/lab120-env.sh

# Step 2: Register baseline for Patch Group
echo ""
echo "[2] Registering baseline for Patch Group 'lab120-linux'..."
aws ssm register-patch-baseline-for-patch-group \
  --baseline-id $BASELINE_ID \
  --patch-group "lab120-linux" \
  --region $REGION && \
  echo "✅ Baseline registered for Patch Group: lab120-linux"
echo "   EC2 tag: Patch Group = lab120-linux → uses this baseline"

# Step 3: Run Patch Scan (non-destructive)
echo ""
echo "[3] Running Patch SCAN (assess only, no changes)..."
SSM_STATUS=$(aws ssm describe-instance-information \
  --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
  --region $REGION \
  --query 'InstanceInformationList[0].PingStatus' \
  --output text 2>/dev/null)

if [ "$SSM_STATUS" == "Online" ]; then
  SCAN_ID=$(aws ssm send-command \
    --instance-ids $INSTANCE_ID \
    --document-name "AWS-RunPatchBaseline" \
    --parameters '{"Operation":["Scan"]}' \
    --region $REGION \
    --query 'Command.CommandId' \
    --output text)
  echo "✅ Patch Scan command dispatched: $SCAN_ID"
  echo "   (Scan takes 2-3 min — check results in SSM Compliance)"
else
  echo "ℹ️  SSM agent not yet online — showing scan command for reference:"
  echo "aws ssm send-command --instance-ids INSTANCE_ID --document-name AWS-RunPatchBaseline --parameters '{\"Operation\":[\"Scan\"]}'"
fi

# Step 4: Enable SSM Inventory
echo ""
echo "[4] Creating SSM Inventory association..."
INVENTORY_ASSOC_ID=$(aws ssm create-association \
  --name "AWS-GatherSoftwareInventory" \
  --targets "Key=tag:Lab,Values=lab120" \
  --schedule-expression "rate(1 day)" \
  --parameters \
    'applications=["Enabled"],awsComponents=["Enabled"],networkConfig=["Enabled"],services=["Enabled"]' \
  --region $REGION \
  --query 'AssociationDescription.AssociationId' \
  --output text 2>/dev/null)

echo "✅ Inventory association: $INVENTORY_ASSOC_ID"
echo "export INVENTORY_ASSOC_ID=\"$INVENTORY_ASSOC_ID\"" >> /tmp/lab120-env.sh

# CLEANUP
echo ""
echo "================================================"
echo "  CLEANUP"
echo "================================================"

echo ""
echo "[5] Terminating EC2 instance..."
aws ec2 terminate-instances \
  --instance-ids $INSTANCE_ID \
  --region $REGION 2>/dev/null && echo "✅ Instance terminated"

echo ""
echo "[6] Deleting patch baseline..."
aws ssm deregister-patch-baseline-for-patch-group \
  --baseline-id $BASELINE_ID \
  --patch-group "lab120-linux" \
  --region $REGION 2>/dev/null
aws ssm delete-patch-baseline \
  --baseline-id $BASELINE_ID \
  --region $REGION 2>/dev/null && echo "✅ Patch baseline deleted"

echo ""
echo "[7] Deleting inventory association..."
aws ssm delete-association \
  --association-id $INVENTORY_ASSOC_ID \
  --region $REGION 2>/dev/null && echo "✅ Inventory association deleted"

echo ""
echo "[8] Deleting SSM parameters..."
for PARAM in "/lab120/prod/app/db-host" "/lab120/prod/app/db-port" "/lab120/prod/app/db-password"; do
  aws ssm delete-parameter --name "$PARAM" --region $REGION 2>/dev/null && \
    echo "✅ Deleted: $PARAM"
done

echo ""
echo "[9] Deleting KMS key (schedule)..."
aws kms schedule-key-deletion \
  --key-id $PS_KEY_ID \
  --pending-window-in-days 7 \
  --region $REGION 2>/dev/null && echo "✅ KMS key scheduled for deletion"

echo ""
echo "[10] Deleting session logs bucket..."
aws s3 rb s3://$SESSION_LOGS_BUCKET --force --region $REGION 2>/dev/null && \
  echo "✅ Session logs bucket deleted"

echo ""
echo "[11] Deleting IAM role + instance profile..."
aws iam remove-role-from-instance-profile \
  --instance-profile-name "lab120-ssm-instance-profile" \
  --role-name "lab120-ssm-ec2-role" 2>/dev/null
aws iam delete-instance-profile \
  --instance-profile-name "lab120-ssm-instance-profile" 2>/dev/null
aws iam detach-role-policy \
  --role-name "lab120-ssm-ec2-role" \
  --policy-arn "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore" 2>/dev/null
aws iam delete-role --role-name "lab120-ssm-ec2-role" 2>/dev/null && \
  echo "✅ IAM role deleted"

rm -f /tmp/lab120-env.sh /tmp/lab120-ec2-trust.json
echo "✅ Temp files cleaned"

echo ""
echo "================================================"
echo "Lab 120 Cleanup Complete!"
echo "================================================"
```

---

## ✅ Lab 120 Verification Checklist

```
Lab 120 — AWS Systems Manager Checklist
│
├── Part 1: EC2 + SSM Profile
│     ├── [ ] EC2 role with AmazonSSMManagedInstanceCore
│     ├── [ ] Instance profile created and attached
│     ├── [ ] Session Manager logging: S3 + CloudWatch Logs
│     ├── [ ] EC2 launched with NO SSH key (SSM only)
│     └── [ ] Patch Group tag applied: lab120-linux
│
├── Part 2: Parameter Store + Run Command
│     ├── [ ] KMS CMK for SecureString encryption
│     ├── [ ] String, SecureString params created hierarchically
│     ├── [ ] SecureString requires --with-decryption flag
│     ├── [ ] Path-based parameter retrieval demonstrated
│     └── [ ] Run Command dispatched with AWS-RunShellScript
│
├── Part 3: Patch Manager + Inventory
│     ├── [ ] Custom baseline: Critical + Important, 0-day approval
│     ├── [ ] Baseline registered for Patch Group: lab120-linux
│     ├── [ ] Patch Scan (non-destructive) dispatched
│     ├── [ ] Inventory association: daily schedule
│     └── [ ] All resources cleaned up
```

---

## 🔑 Lab 120 Key Takeaways

| Concept | What You Practiced |
|---|---|
| SSM agent + profile | Both required for managed instance |
| Session Manager logging | SSM Preferences → S3 + CloudWatch |
| No port 22 needed | SSM replaces SSH entirely |
| SecureString + CMK | ssm:GetParameter + kms:Decrypt both needed |
| Patch Group tag | Tag bridges instance to patch baseline |
| Scan vs Install | Scan = assess; Install = apply patches |
| Inventory association | Scheduled gathering of software/config data |

---

# 📅 Day 51 — Section 3: Lab 121
## Automated Remediation — Config + EventBridge + Lambda

---

## 🎯 Lab Objective
In this lab you will:
- Create a non-compliant S3 bucket (public access enabled)
- Deploy Config rule to detect it
- Build Lambda auto-remediation function
- Wire GuardDuty finding → EventBridge → Lambda
- Test automated remediation pipeline end-to-end
- Add SNS notification to all remediations
- Cleanup all resources

---

## Prerequisites Check

```bash
#!/bin/bash
# Lab 121 - Prerequisites Check
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region || echo "ap-south-1")

cat > /tmp/lab121-env.sh << EOF
export ACCOUNT_ID="$ACCOUNT_ID"
export REGION="$REGION"
export LAB="lab121"
EOF

echo "================================================"
echo "  Lab 121: Automated Remediation Prerequisites"
echo "================================================"
aws sts get-caller-identity --output table
echo "Region: $REGION"

echo ""
echo "[1] Checking GuardDuty..."
GD_DETECTOR=$(aws guardduty list-detectors \
  --region $REGION --query 'DetectorIds[0]' --output text 2>/dev/null)
echo "GuardDuty detector: ${GD_DETECTOR:-Not enabled}"
echo "export GD_DETECTOR=\"$GD_DETECTOR\"" >> /tmp/lab121-env.sh

echo ""
echo "✅ Environment saved to /tmp/lab121-env.sh"
echo "================================================"
```

---

## Part 1 — Non-Compliant Resource + Config Rule

```bash
#!/bin/bash
# Lab 121 - Part 1: Non-compliant S3 + Config Rule
source /tmp/lab121-env.sh

echo "================================================"
echo "  Part 1: Non-Compliant Resource + Config Rule"
echo "================================================"

# Step 1: Create deliberately non-compliant S3 bucket
echo ""
echo "[1] Creating NON-COMPLIANT S3 bucket (public access enabled)..."
NONCOMPLIANT_BUCKET="lab121-noncompliant-${ACCOUNT_ID}"
aws s3api create-bucket \
  --bucket $NONCOMPLIANT_BUCKET \
  --region $REGION \
  --create-bucket-configuration LocationConstraint=$REGION 2>/dev/null || \
  aws s3api create-bucket --bucket $NONCOMPLIANT_BUCKET --region $REGION 2>/dev/null

# Explicitly disable block public access (the non-compliant state)
aws s3api put-public-access-block \
  --bucket $NONCOMPLIANT_BUCKET \
  --public-access-block-configuration \
    "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false" \
  --region $REGION

echo "✅ Non-compliant bucket created: $NONCOMPLIANT_BUCKET"
echo "   Public Access Block: DISABLED (intentionally non-compliant)"
echo "export NONCOMPLIANT_BUCKET=\"$NONCOMPLIANT_BUCKET\"" >> /tmp/lab121-env.sh

# Step 2: Create SNS topic for remediation notifications
echo ""
echo "[2] Creating SNS remediation notification topic..."
REMEDIATION_SNS=$(aws sns create-topic \
  --name "lab121-remediation-alerts" \
  --region $REGION \
  --query 'TopicArn' --output text)
echo "✅ SNS topic: $REMEDIATION_SNS"
echo "export REMEDIATION_SNS=\"$REMEDIATION_SNS\"" >> /tmp/lab121-env.sh

echo ""
echo "================================================"
echo "Part 1 Complete!"
echo "================================================"
```

---

## Part 2 — Auto-Remediation Lambda

```bash
#!/bin/bash
# Lab 121 - Part 2: Remediation Lambda
source /tmp/lab121-env.sh

echo "================================================"
echo "  Part 2: Auto-Remediation Lambda Functions"
echo "================================================"

# Step 1: Create Lambda execution role
echo ""
echo "[1] Creating remediation Lambda role (least privilege)..."
cat > /tmp/lab121-trust.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF

REMEDIATION_ROLE=$(aws iam create-role \
  --role-name "lab121-remediation-role" \
  --assume-role-policy-document file:///tmp/lab121-trust.json \
  --query 'Role.Arn' --output text)

aws iam attach-role-policy \
  --role-name "lab121-remediation-role" \
  --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

cat > /tmp/lab121-remediation-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutBucketPublicAccessBlock",
        "s3:GetBucketPublicAccessBlock",
        "s3:ListAllMyBuckets"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:ModifyInstanceAttribute",
        "ec2:DescribeInstances",
        "ec2:CreateSnapshot",
        "ec2:DescribeVolumes"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["sns:Publish"],
      "Resource": "$REMEDIATION_SNS"
    },
    {
      "Effect": "Allow",
      "Action": ["config:PutEvaluations"],
      "Resource": "*"
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name "lab121-remediation-role" \
  --policy-name "RemediationPolicy" \
  --policy-document file:///tmp/lab121-remediation-policy.json

echo "✅ Remediation role: $REMEDIATION_ROLE"
echo "export REMEDIATION_ROLE=\"$REMEDIATION_ROLE\"" >> /tmp/lab121-env.sh
sleep 10

# Step 2: Create S3 auto-remediation Lambda
echo ""
echo "[2] Creating S3 public access remediation Lambda..."
mkdir -p /tmp/lab121-lambda

cat > /tmp/lab121-lambda/s3_remediate.py << 'PYEOF'
import boto3
import json
import os
import logging
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SNS_TOPIC = os.environ.get('SNS_TOPIC_ARN')
REGION = os.environ.get('AWS_REGION', 'ap-south-1')

def lambda_handler(event, context):
    """
    Auto-remediation: Block public access on non-compliant S3 buckets
    Triggered by: Config rule NON_COMPLIANT event via EventBridge
                  OR direct invocation from Config remediation action
    """
    logger.info(f"Event: {json.dumps(event)}")

    s3 = boto3.client('s3', region_name=REGION)
    sns = boto3.client('sns', region_name=REGION)

    # Extract bucket name from Config or EventBridge event
    bucket_name = None
    try:
        # Config remediation direct invocation
        if 'BucketName' in event:
            bucket_name = event['BucketName']
        # EventBridge from Config
        elif 'detail' in event:
            bucket_name = event['detail'].get('resourceId')
        # Direct test invocation
        elif 'test_bucket' in event:
            bucket_name = event['test_bucket']
    except Exception as e:
        logger.error(f"Error extracting bucket name: {e}")
        return {'status': 'error', 'message': str(e)}

    if not bucket_name:
        logger.warning("No bucket name found in event")
        return {'status': 'no_bucket'}

    remediation_result = {
        'bucket': bucket_name,
        'timestamp': datetime.utcnow().isoformat(),
        'actions': []
    }

    try:
        # Check current state
        current = s3.get_bucket_public_access_block(Bucket=bucket_name)
        logger.info(f"Current public access block: {current['PublicAccessBlockConfiguration']}")
    except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
        logger.info("No public access block config exists — will create one")
    except Exception as e:
        logger.error(f"Error checking bucket state: {e}")

    # Apply remediation: block all public access
    try:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        logger.info(f"✅ Public access BLOCKED on bucket: {bucket_name}")
        remediation_result['actions'].append('blocked_public_access')
        remediation_result['status'] = 'REMEDIATED'

    except Exception as e:
        logger.error(f"Remediation failed for {bucket_name}: {e}")
        remediation_result['status'] = 'FAILED'
        remediation_result['error'] = str(e)

    # Always notify team
    try:
        sns.publish(
            TopicArn=SNS_TOPIC,
            Subject=f"Auto-Remediation: S3 Public Access Blocked - {bucket_name}",
            Message=json.dumps({
                'remediation': 'S3_PUBLIC_ACCESS_BLOCKED',
                'bucket': bucket_name,
                'status': remediation_result['status'],
                'timestamp': remediation_result['timestamp'],
                'trigger': 'Config Rule: s3-bucket-public-read-prohibited',
                'note': 'Automatic remediation applied — review if legitimate use case'
            }, indent=2)
        )
        remediation_result['actions'].append('team_notified')
    except Exception as e:
        logger.error(f"SNS notification failed: {e}")

    return remediation_result
PYEOF

cd /tmp/lab121-lambda
zip -r s3_remediate.zip s3_remediate.py

S3_REMEDIATION_LAMBDA=$(aws lambda create-function \
  --function-name "lab121-s3-public-access-remediation" \
  --runtime python3.12 \
  --role "$REMEDIATION_ROLE" \
  --handler "s3_remediate.lambda_handler" \
  --zip-file "fileb:///tmp/lab121-lambda/s3_remediate.zip" \
  --timeout 60 \
  --environment "Variables={SNS_TOPIC_ARN=$REMEDIATION_SNS}" \
  --description "Lab121 auto-remediation: block S3 public access" \
  --region $REGION \
  --query 'FunctionArn' --output text)

aws lambda wait function-active \
  --function-name "lab121-s3-public-access-remediation" \
  --region $REGION

echo "✅ S3 remediation Lambda: $S3_REMEDIATION_LAMBDA"
echo "export S3_REMEDIATION_LAMBDA=\"$S3_REMEDIATION_LAMBDA\"" >> /tmp/lab121-env.sh

echo ""
echo "================================================"
echo "Part 2 Complete!"
echo "================================================"
```

---

## Part 3 — EventBridge Rule + End-to-End Test

```bash
#!/bin/bash
# Lab 121 - Part 3: EventBridge + E2E Test
source /tmp/lab121-env.sh

echo "================================================"
echo "  Part 3: EventBridge Rules + End-to-End Test"
echo "================================================"

# Step 1: Add EventBridge permission to Lambda
echo ""
echo "[1] Adding EventBridge invoke permission to Lambda..."
aws lambda add-permission \
  --function-name "lab121-s3-public-access-remediation" \
  --statement-id "EventBridgeInvoke" \
  --action "lambda:InvokeFunction" \
  --principal "events.amazonaws.com" \
  --source-account "$ACCOUNT_ID" \
  --region $REGION 2>/dev/null
echo "✅ Permission granted"

# Step 2: Create EventBridge rule for Config compliance changes
echo ""
echo "[2] Creating EventBridge rule for Config NON_COMPLIANT events..."
aws events put-rule \
  --name "lab121-config-s3-noncompliant" \
  --description "Lab121: Route S3 public access violations to remediation Lambda" \
  --event-pattern '{
    "source": ["aws.config"],
    "detail-type": ["Config Rules Compliance Change"],
    "detail": {
      "configRuleName": ["lab121-s3-public-read-check"],
      "newEvaluationResult": {
        "complianceType": ["NON_COMPLIANT"]
      }
    }
  }' \
  --state ENABLED \
  --region $REGION
echo "✅ EventBridge rule: lab121-config-s3-noncompliant"

aws events put-targets \
  --rule "lab121-config-s3-noncompliant" \
  --targets "Id=s3-remediation,Arn=$S3_REMEDIATION_LAMBDA" \
  --region $REGION
echo "✅ Lambda target added"

# Step 3: Test remediation directly
echo ""
echo "[3] Testing S3 remediation Lambda directly..."
echo "    Bucket to remediate: $NONCOMPLIANT_BUCKET"
echo ""
echo "    Before remediation:"
aws s3api get-bucket-public-access-block \
  --bucket $NONCOMPLIANT_BUCKET \
  --region $REGION \
  --query 'PublicAccessBlockConfiguration' \
  --output table 2>/dev/null || echo "    (No block config = public access possible)"

# Invoke remediation Lambda
cat > /tmp/lab121-test-event.json << EOF
{
  "test_bucket": "$NONCOMPLIANT_BUCKET"
}
EOF

aws lambda invoke \
  --function-name "lab121-s3-public-access-remediation" \
  --payload file:///tmp/lab121-test-event.json \
  --region $REGION \
  /tmp/lab121-remediation-output.json 2>/dev/null
echo ""
echo "Remediation result:"
cat /tmp/lab121-remediation-output.json | python3 -m json.tool

echo ""
echo "    After remediation:"
aws s3api get-bucket-public-access-block \
  --bucket $NONCOMPLIANT_BUCKET \
  --region $REGION \
  --query 'PublicAccessBlockConfiguration' \
  --output table

echo ""
echo "[4] Architecture summary..."
cat << 'EOF'
Full Automated Remediation Pipeline:

Config Rule (lab121-s3-public-read-check)
  │ NON_COMPLIANT detected
  ▼
EventBridge Rule (lab121-config-s3-noncompliant)
  │ matches Config compliance change event
  ▼
Lambda (lab121-s3-public-access-remediation)
  ├── 1. Block all public access on bucket
  ├── 2. Log action to CloudWatch Logs
  └── 3. Notify security team via SNS

Total response time: ~10-30 seconds from detection to fix
EOF

echo ""
echo "================================================"
echo "Part 3 Complete!"
echo "================================================"
```

---

## Part 4 — Cleanup

```bash
#!/bin/bash
# Lab 121 - Part 4: Cleanup
source /tmp/lab121-env.sh

echo "================================================"
echo "  Part 4: Cleanup All Lab 121 Resources"
echo "================================================"

echo ""
echo "[1] Deleting EventBridge rule + targets..."
aws events remove-targets \
  --rule "lab121-config-s3-noncompliant" \
  --ids "s3-remediation" \
  --region $REGION 2>/dev/null
aws events delete-rule \
  --name "lab121-config-s3-noncompliant" \
  --region $REGION 2>/dev/null && echo "✅ EventBridge rule deleted"

echo ""
echo "[2] Deleting Lambda functions..."
aws lambda delete-function \
  --function-name "lab121-s3-public-access-remediation" \
  --region $REGION 2>/dev/null && echo "✅ Lambda deleted"

echo ""
echo "[3] Deleting SNS topic..."
aws sns delete-topic \
  --topic-arn $REMEDIATION_SNS \
  --region $REGION 2>/dev/null && echo "✅ SNS topic deleted"

echo ""
echo "[4] Deleting non-compliant S3 bucket..."
aws s3 rb s3://$NONCOMPLIANT_BUCKET --force \
  --region $REGION 2>/dev/null && echo "✅ S3 bucket deleted"

echo ""
echo "[5] Deleting IAM role..."
aws iam delete-role-policy \
  --role-name "lab121-remediation-role" \
  --policy-name "RemediationPolicy" 2>/dev/null
aws iam detach-role-policy \
  --role-name "lab121-remediation-role" \
  --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole" 2>/dev/null
aws iam delete-role \
  --role-name "lab121-remediation-role" 2>/dev/null && echo "✅ IAM role deleted"

echo ""
echo "[6] Cleanup temp files..."
rm -f /tmp/lab121-env.sh /tmp/lab121-trust.json \
      /tmp/lab121-remediation-policy.json \
      /tmp/lab121-test-event.json \
      /tmp/lab121-remediation-output.json
rm -rf /tmp/lab121-lambda/
echo "✅ Temp files cleaned"

echo ""
echo "================================================"
echo "Lab 121 Cleanup Complete!"
echo "================================================"
```

---

## ✅ Lab 121 Verification Checklist

```
Lab 121 — Automated Remediation Checklist
│
├── Part 1: Non-Compliant Resource
│     ├── [ ] S3 bucket created with public access ENABLED
│     └── [ ] SNS topic for remediation alerts created
│
├── Part 2: Remediation Lambda
│     ├── [ ] Role: least privilege (specific S3 + SNS + EC2 only)
│     ├── [ ] Lambda: check → remediate → notify pattern
│     ├── [ ] Always notifies SNS even on success
│     └── [ ] Idempotent: safe to run multiple times
│
├── Part 3: EventBridge + E2E Test
│     ├── [ ] EB rule: Config NON_COMPLIANT → Lambda
│     ├── [ ] Direct Lambda test successful
│     ├── [ ] Before: public access not blocked
│     ├── [ ] After: all public access blocked
│     └── [ ] Full pipeline architecture understood
│
└── Part 4: Cleanup
      └── [ ] All resources deleted
```

---

## 🔑 Lab 121 Key Takeaways

| Concept | What You Practiced |
|---|---|
| EventBridge source | `aws.config` + `aws.guardduty` patterns |
| Config → EB → Lambda | Detection → routing → remediation chain |
| Idempotent remediation | Blocking already-blocked access = safe |
| Always notify | SNS in every remediation Lambda |
| Least-privilege Lambda role | Only exact actions needed |
| Manual test first | Test Lambda directly before auto-enabling |

---

# 📅 Day 52 — Section 3: Lab 122
## Real-World Scenarios — End-to-End Security Architecture

---

## 🎯 Lab Objective
Day 52 is a synthesis lab. Rather than building one specific service, you will:
- Build a mini end-to-end secure architecture connecting multiple services
- Implement the compromised credential response pipeline
- Create a data exfiltration prevention pattern
- Verify the complete security chain works together
- Cleanup all resources

---

## Part 1 — Compromised Credential Full Response Pipeline

```bash
#!/bin/bash
# Lab 122 - Part 1: Full IR Pipeline
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region || echo "ap-south-1")

cat > /tmp/lab122-env.sh << EOF
export ACCOUNT_ID="$ACCOUNT_ID"
export REGION="$REGION"
EOF

echo "================================================"
echo "  Lab 122: Real-World Scenarios"
echo "================================================"
aws sts get-caller-identity --output table

# Step 1: Create the full IR notification SNS
SNS_ARN=$(aws sns create-topic \
  --name "lab122-security-alerts" \
  --region $REGION \
  --query 'TopicArn' --output text)
echo "✅ Security alerts SNS: $SNS_ARN"
echo "export SNS_ARN=\"$SNS_ARN\"" >> /tmp/lab122-env.sh

# Step 2: Demonstrate the TokenIssueTime session revocation technique
echo ""
echo "[Demo] STS Session Revocation (TokenIssueTime technique)..."
cat << 'EOF'
# This is the emergency response for compromised IAM role credentials.
# The policy below denies ALL actions for tokens issued before NOW.

REVOCATION_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

DENY_POLICY=$(cat << POLICY
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "EmergencyRevoke",
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "DateLessThan": {
        "aws:TokenIssueTime": "$REVOCATION_TIME"
      }
    }
  }]
}
POLICY
)

# Apply to compromised role:
aws iam put-role-policy \
  --role-name COMPROMISED_ROLE_NAME \
  --policy-name EmergencyRevoke \
  --policy-document "$DENY_POLICY"

# This immediately revokes ALL outstanding STS sessions
# issued before the revocation timestamp.
# The role still works — only old tokens are invalidated.
EOF

# Step 3: S3 VPC endpoint policy (data exfiltration prevention)
echo ""
echo "[Demo] S3 VPC Endpoint Policy (exfiltration prevention)..."
cat << 'EOF'
# This VPC endpoint policy prevents EC2 instances from accessing
# S3 buckets in OTHER accounts through the VPC endpoint.
# Stops common "cloud data exfiltration" technique.

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:ResourceAccount": ["YOUR-ACCOUNT-ID"]
        }
      }
    },
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
  ]
}
# Apply via: aws ec2 modify-vpc-endpoint --vpc-endpoint-id vpce-XXX --policy-document above
EOF

echo ""
echo "================================================"
echo "Part 1 Complete!"
echo "================================================"
```

---

## Part 2 — IMDSv2 Enforcement + Verification

```bash
#!/bin/bash
# Lab 122 - Part 2: IMDSv2 + Verification
source /tmp/lab122-env.sh

echo "================================================"
echo "  Part 2: IMDSv2 Enforcement"
echo "================================================"

# Step 1: Launch instance with IMDSv1 (non-compliant)
echo ""
echo "[1] Launching instance with IMDSv1 (non-compliant for demo)..."
DEFAULT_VPC=$(aws ec2 describe-vpcs \
  --filters Name=isDefault,Values=true \
  --region $REGION \
  --query 'Vpcs[0].VpcId' --output text)
DEFAULT_SUBNET=$(aws ec2 describe-subnets \
  --filters Name=vpc-id,Values=$DEFAULT_VPC \
  --region $REGION --query 'Subnets[0].SubnetId' --output text)
AMI_ID=$(aws ec2 describe-images \
  --owners amazon \
  --filters "Name=name,Values=amzn2-ami-hvm-*-x86_64-gp2" \
            "Name=state,Values=available" \
  --query 'sort_by(Images,&CreationDate)[-1].ImageId' \
  --output text --region $REGION)

INSTANCE_ID=$(aws ec2 run-instances \
  --image-id $AMI_ID \
  --instance-type t3.micro \
  --subnet-id $DEFAULT_SUBNET \
  --no-associate-public-ip-address \
  --metadata-options "HttpTokens=optional,HttpPutResponseHopLimit=1" \
  --tag-specifications \
    "ResourceType=instance,Tags=[{Key=Name,Value=lab122-imdsv1-victim},{Key=Lab,Value=lab122}]" \
  --region $REGION \
  --query 'Instances[0].InstanceId' --output text)

echo "✅ Instance (IMDSv1 optional): $INSTANCE_ID"
echo "export INSTANCE_ID=\"$INSTANCE_ID\"" >> /tmp/lab122-env.sh

# Step 2: Enforce IMDSv2 on the instance
echo ""
echo "[2] Enforcing IMDSv2 on instance..."
aws ec2 wait instance-running \
  --instance-ids $INSTANCE_ID --region $REGION

aws ec2 modify-instance-metadata-options \
  --instance-id $INSTANCE_ID \
  --http-tokens required \
  --http-put-response-hop-limit 1 \
  --region $REGION \
  --query 'InstanceMetadataOptions' \
  --output table

echo "✅ IMDSv2 enforced: HttpTokens = required"
echo "   PUT session request now REQUIRED before any metadata call"
echo "   Blocks SSRF-based credential theft (simple GET requests)"

# Step 3: Show SCP for org-wide IMDSv2 enforcement
echo ""
echo "[3] SCP for org-wide IMDSv2 enforcement..."
cat << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "RequireIMDSv2",
    "Effect": "Deny",
    "Action": "ec2:RunInstances",
    "Resource": "arn:aws:ec2:*:*:instance/*",
    "Condition": {
      "StringNotEquals": {
        "ec2:MetadataHttpTokens": "required"
      }
    }
  }]
}
# Attach this SCP at root → prevents any new instance with IMDSv1
# For existing instances: use SSM Run Command to patch fleet
EOF

echo ""
echo "================================================"
echo "Part 2 Complete!"
echo "================================================"
```

---

## Part 3 — Security Architecture Synthesis + Cleanup

```bash
#!/bin/bash
# Lab 122 - Part 3: Architecture Summary + Cleanup
source /tmp/lab122-env.sh

echo "================================================"
echo "  Part 3: Architecture Synthesis"
echo "================================================"

cat << 'EOF'
COMPLETE AWS SECURITY ARCHITECTURE PATTERN
==========================================

LAYER 1 — IDENTITY & ACCESS
├── IAM: Least privilege, no wildcards
├── MFA: Required for console + CLI
├── IMDSv2: Required on all EC2
├── SCP: Region restrictions, protect security services
├── IAM Identity Center: SSO for all accounts
└── Break-glass: Offline emergency credentials

LAYER 2 — NETWORK SECURITY
├── VPC: Private subnets, no direct internet for workloads
├── Security Groups: Per-resource, deny all default
├── NACLs: Subnet-level backup controls
├── VPC Endpoints: Keep AWS API traffic private
├── VPC Endpoint Policies: Prevent cross-account S3 exfiltration
└── Network Firewall: East-west inspection (if needed)

LAYER 3 — DATA PROTECTION
├── KMS CMK: Per-workload encryption keys
├── Secrets Manager: All credentials, auto-rotation
├── S3 Block Public Access: Org-level enabled
├── S3 Object Lock: Immutable backups + evidence
├── Macie: Sensitive data classification
└── TLS: Enforced everywhere, mTLS between microservices

LAYER 4 — DETECTION
├── GuardDuty: Threat detection (org-wide, all accounts)
├── CloudTrail: API audit (org trail, all regions)
├── Config: Compliance monitoring (org conformance packs)
├── Security Hub: Aggregated findings dashboard
├── VPC Flow Logs: Network metadata
└── Route53 Resolver Logs: DNS queries

LAYER 5 — RESPONSE
├── EventBridge: Route findings to automation
├── Lambda: Simple single-step remediations
├── Step Functions: Multi-step IR with human gates
├── SSM Automation: Pre-built remediation runbooks
├── Forensics Account: Isolated investigation environment
└── SNS: Always notify team of automated actions

LAYER 6 — GOVERNANCE
├── Control Tower: Landing zone + guardrails
├── Organizations: Multi-account structure + SCPs
├── Config Aggregator: Org-wide compliance view
├── Service Catalog: Approved infrastructure catalog
├── AWS Artifact: Compliance documentation
└── Backup Vault Lock: Ransomware-proof backups
EOF

# Cleanup
echo ""
echo "================================================"
echo "  CLEANUP"
echo "================================================"

echo ""
echo "[1] Terminating instance..."
aws ec2 terminate-instances \
  --instance-ids $INSTANCE_ID \
  --region $REGION 2>/dev/null && echo "✅ Instance terminated"

echo ""
echo "[2] Deleting SNS topic..."
aws sns delete-topic \
  --topic-arn $SNS_ARN \
  --region $REGION 2>/dev/null && echo "✅ SNS deleted"

rm -f /tmp/lab122-env.sh
echo "✅ Temp files cleaned"

echo ""
echo "================================================"
echo "Lab 122 Complete! All Days 49–52 Labs Done!"
echo "================================================"
```

---

## ✅ Lab 122 Verification Checklist

```
Lab 122 — Real-World Scenarios Checklist
│
├── Part 1: Credential IR Pipeline
│     ├── [ ] TokenIssueTime revocation technique understood
│     ├── [ ] STS revocation vs access key deactivation distinction clear
│     └── [ ] S3 VPC endpoint policy for exfiltration prevention reviewed
│
├── Part 2: IMDSv2
│     ├── [ ] IMDSv2 enforced on instance (HttpTokens=required)
│     ├── [ ] SCP template for org-wide enforcement reviewed
│     └── [ ] SSRF → IMDSv1 → credential theft attack path understood
│
└── Part 3: Architecture Synthesis
      ├── [ ] 6-layer security architecture reviewed
      ├── [ ] Correct service per layer understood
      └── [ ] All resources cleaned up
```

---

# 📅 Day 53 — Full Practice Exam 1
## 25 Scenario-Based Questions

---

> **Instructions:** Treat this as a real exam. Cover the answers, attempt each question, then review. Target: 80%+ (20/25 correct).

---

**Q1.** A company enables AWS Config but no findings appear for 3 days. Which of the following is the MOST LIKELY cause?

A) Config requires GuardDuty to be enabled first  
B) The Config configuration recorder was created but never started  
C) Config rules take 72 hours to initialize  
D) Config only works in us-east-1  

**Answer: B** — Config recorder must be explicitly started with `start-configuration-recorder`. Creating the recorder does not automatically start recording.

---

**Q2.** A Lambda function in a VPC private subnet cannot call `secretsmanager:GetSecretValue`. No NAT Gateway exists. What is the fix?

A) Move Lambda to a public subnet  
B) Create a VPC Interface Endpoint for Secrets Manager  
C) Store the secret as an environment variable  
D) Add a NAT instance  

**Answer: B** — VPC Interface Endpoint for `com.amazonaws.region.secretsmanager` routes SM API calls through the AWS private network without internet access.

---

**Q3.** An ECS task on Fargate needs read access to DynamoDB. The architect configures a Task Role with DynamoDB permissions. What additional step is required?

A) Add DynamoDB permissions to the ECS Task Execution Role  
B) Enable Fargate platform version 1.4  
C) Nothing — Task Role alone is sufficient for Fargate  
D) Configure a VPC endpoint for DynamoDB  

**Answer: C** — The Task Role (not Execution Role) provides the application code's AWS permissions. For Fargate, the Task Role is all that's needed for DynamoDB access. The Execution Role handles ECS agent operations (image pull, log delivery, secret fetch).

---

**Q4.** A security engineer needs to invalidate ALL active sessions of a compromised IAM role without deleting the role. What is the correct technique?

A) Rotate the role's access keys  
B) Attach an inline deny policy with `aws:TokenIssueTime` condition set to the current time  
C) Delete and recreate the role  
D) Disable the role's permissions boundary  

**Answer: B** — `aws:TokenIssueTime` with `DateLessThan: now` denies all actions for tokens issued before the current timestamp, effectively revoking all outstanding sessions immediately.

---

**Q5.** A company's auditor asks for evidence of AWS's PCI-DSS compliance for the underlying infrastructure. Where does the security team obtain this?

A) AWS Trusted Advisor dashboard  
B) AWS Security Hub compliance score  
C) AWS Artifact — PCI DSS Attestation of Compliance (AOC) and Responsibility Matrix  
D) AWS Config PCI-DSS conformance pack results  

**Answer: C** — Artifact provides AWS's own PCI-DSS AOC. Config conformance pack shows YOUR compliance; Artifact shows AWS's infrastructure compliance.

---

**Q6.** An SCP at the root of an organization denies `s3:DeleteBucket`. An admin in the management account tries to delete a bucket. What happens?

A) The deletion is denied — root SCP applies to all accounts  
B) The deletion succeeds — SCPs never apply to the management account  
C) The deletion requires MFA to proceed  
D) The deletion is queued for 24 hours  

**Answer: B** — SCPs NEVER apply to the management account. This is the most tested SCP concept.

---

**Q7.** Which combination provides BOTH detection of who changed an IAM policy AND what the policy looked like before the change?

A) GuardDuty + Security Hub  
B) CloudTrail (who changed) + AWS Config configuration history (before/after state)  
C) Macie + CloudWatch  
D) Config alone  

**Answer: B** — CloudTrail records the API call with caller identity. Config records the resource configuration at each point in time. Together: complete audit trail.

---

**Q8.** A Kubernetes pod in EKS needs to write to S3. The EKS node's instance profile has no S3 permissions. What is the CORRECT solution?

A) Add S3 permissions to the node instance profile  
B) Hardcode AWS credentials as a Kubernetes Secret  
C) Configure IRSA — annotate the pod's service account with an IAM role ARN via OIDC  
D) Mount an AWS credential file as a ConfigMap  

**Answer: C** — IRSA provides pod-level IAM access via OIDC federation without modifying the node instance profile or hardcoding credentials.

---

**Q9.** ECR Enhanced Scanning is enabled. A new critical CVE is published that affects an image pushed 2 weeks ago. What happens?

A) The image must be manually rescanned  
B) Inspector automatically re-evaluates the image and generates a new finding  
C) The image is automatically deleted  
D) Nothing — scanning only occurs at push time  

**Answer: B** — Enhanced Scanning via Inspector provides continuous scanning. New CVE publications trigger automatic re-evaluation of existing images.

---

**Q10.** A company wants to prevent developers from creating EC2 instances with IMDSv1 across all 80 accounts. What is the most efficient control?

A) Config rule in each account  
B) SCP at root: Deny `ec2:RunInstances` where `ec2:MetadataHttpTokens` != `required`  
C) CloudFormation stack policy  
D) IAM policy in each account  

**Answer: B** — SCP at root applies to all 80 accounts simultaneously. This is org-wide preventive control vs Config's detective control.

---

**Q11.** An ECS task definition has a secret injected as `"valueFrom": "arn:aws:secretsmanager:..."`. Secrets Manager rotates the secret 4 hours after the task starts. What is the effect on the running task?

A) The running task automatically fetches the new value  
B) The running task continues using the old (rotated) secret until it restarts  
C) The task crashes on the next API call  
D) ECS re-injects the new value within 5 minutes  

**Answer: B** — ECS injects secrets at task launch time only. The running container has the old value in its environment. Design rotation windows to coincide with task restarts.

---

**Q12.** A GuardDuty finding `CryptoCurrency:EC2/BitcoinTool.B` is generated. No on-call engineer is available. What automated response addresses this?

A) GuardDuty automatically terminates the instance  
B) Pre-built EventBridge rule → Lambda isolates instance (forensics SG) + creates EBS snapshot + sends SNS notification  
C) Config rule remediates the finding  
D) Security Hub creates a ticket automatically  

**Answer: B** — GuardDuty generates EventBridge events. Pre-built Lambda triggered by EB pattern matching high-severity findings provides automated containment. GuardDuty never auto-remediates.

---

**Q13.** A compliance team needs Kubernetes Secrets encrypted at rest in EKS. What is the solution?

A) Base64-encode all secret values  
B) Enable envelope encryption for etcd using a KMS CMK  
C) Use IRSA for all pods  
D) Enable ECR image scanning  

**Answer: B** — Envelope encryption with KMS CMK encrypts the etcd datastore where Kubernetes Secrets are stored. Base64 is encoding, not encryption.

---

**Q14.** A company accepts the AWS HIPAA BAA in the management account of a 50-account organization. A new account joins the org next week. Is the new account covered by the BAA?

A) No — new accounts need to accept the BAA separately  
B) Yes — org-level BAA acceptance automatically covers all current and future member accounts  
C) Only if the account is in the Security OU  
D) Only after the monthly billing cycle  

**Answer: B** — Org-level agreement acceptance in AWS Artifact automatically covers all member accounts, including those added after acceptance.

---

**Q15.** What is the FIRST action when an attacker gains EC2 instance credentials via SSRF and uses them from an external IP?

A) Terminate the EC2 instance  
B) Isolate the EC2 instance (forensics SG) AND revoke outstanding STS sessions via TokenIssueTime deny policy  
C) Delete the IAM role  
D) Disable GuardDuty to stop alerts  

**Answer: B** — Two simultaneous actions: contain the source (isolate EC2) and revoke the credentials (TokenIssueTime). Order matters — don't terminate before preserving evidence.

---

**Q16.** AWS Config auto-remediation stops a production RDS instance that was incorrectly flagged. How should this have been prevented?

A) Disable Config for production  
B) Use Config rule scope to exclude the production RDS; test with manual remediation mode first; use tags to exclude critical resources  
C) Use GuardDuty instead  
D) Only run Config during maintenance windows  

**Answer: B** — Config rule scope (by tag, resource type, or resource ID) limits which resources the rule evaluates. Manual mode first allows human review before enabling auto-remediation.

---

**Q17.** A company needs the most complete picture of a security incident for forensic purposes. Which combination covers API activity, network activity, and DNS activity?

A) CloudTrail + GuardDuty  
B) CloudTrail + VPC Flow Logs + Route53 Resolver Query Logs  
C) Security Hub + Macie  
D) Config + CloudWatch  

**Answer: B** — CloudTrail = API calls. VPC Flow Logs = network connections (IP/port/bytes). Route53 Resolver Logs = DNS queries. Together: complete forensic picture.

---

**Q18.** An organization uses Control Tower. A developer manually edits an SCP managed by Control Tower. What is the consequence?

A) The SCP is permanently deleted  
B) The landing zone enters a "drifted" state — Control Tower may overwrite the changes during the next update  
C) The change is approved by Control Tower automatically  
D) The developer's account is suspended  

**Answer: B** — Manually editing CT-managed resources causes drift. Use Customizations for Control Tower (CfCT) for custom controls.

---

**Q19.** A Lambda function's execution role has `s3:*` on `*`. What is the correct remediation under the principle of least privilege?

A) Add a permission boundary  
B) Replace with specific actions (`s3:GetObject`, `s3:PutObject`) on the specific bucket ARN the function actually needs  
C) Add an explicit Deny for dangerous S3 actions  
D) Move to a VPC to restrict access  

**Answer: B** — Least privilege = exact actions + exact resource ARN. Deny statements are backup controls, not replacements for proper scoping.

---

**Q20.** Which S3 Object Lock mode prevents deletion even by the root account, with no override possible?

A) Governance Mode  
B) Legal Hold  
C) Compliance Mode  
D) Vault Lock  

**Answer: C** — Compliance Mode is truly immutable — no user (including root) can delete or modify objects until the retention period expires. Governance Mode can be overridden by privileged users.

---

**Q21.** A company needs CERT-In compliance in India. Their CloudTrail logs are currently retained for 30 days. What change is required?

A) Enable GuardDuty  
B) Extend CloudTrail S3 lifecycle policy to 180 days minimum  
C) Enable CloudTrail multi-region  
D) Configure CloudTrail to log data events  

**Answer: B** — CERT-In (India, 2022 directive) requires minimum 180-day log retention. S3 lifecycle policy on the CloudTrail delivery bucket must be updated.

---

**Q22.** A penetration tester discovers an SSRF vulnerability that can read `http://169.254.169.254/latest/meta-data/iam/security-credentials/`. Which control would have prevented the credential theft?

A) S3 Block Public Access  
B) VPC security group blocking port 80  
C) Enforcing IMDSv2 (HttpTokens=required) on the EC2 instance  
D) Enabling GuardDuty  

**Answer: C** — IMDSv2 requires a PUT request to obtain a session token before metadata can be accessed. SSRF typically uses GET/POST, breaking the credential theft path. IMDSv2 is the direct fix.

---

**Q23.** An organization wants to deploy automated remediation for Security Hub findings across all 100 accounts. What is the recommended deployment approach?

A) Deploy Lambda to each account manually  
B) Use CloudFormation StackSets to deploy EventBridge rules, Lambda functions, and IAM roles to all member accounts  
C) Deploy everything in the management account  
D) Use Config conformance pack only  

**Answer: B** — CloudFormation StackSets deploy the remediation infrastructure (EventBridge rules, Lambda, IAM roles) to all member accounts simultaneously. Combined with org-level Security Hub, this provides org-wide automated remediation.

---

**Q24.** A Step Functions IR workflow needs a human to approve before terminating a compromised EC2 instance. Which Step Functions feature enables this pause?

A) Wait state with fixed duration  
B) Task state with a task token callback — workflow pauses and sends token to reviewer; resumes only when `SendTaskSuccess` or `SendTaskFailure` is called  
C) Choice state with a condition  
D) Parallel state  

**Answer: B** — Task token callback is the Step Functions human approval gate. The workflow pauses indefinitely, sends the token via SNS/API Gateway to the reviewer, and only continues when the reviewer calls the Step Functions API with the token.

---

**Q25.** A company discovers a Lambda function has `"Principal": "*"` with no conditions in its resource-based policy. What is the risk and immediate fix?

A) No risk — Lambda validates IAM anyway  
B) Risk: any unauthenticated caller on the internet can invoke the function. Fix: replace with specific principal ARN (account, service, or role) and add Condition block (aws:SourceAccount or ArnLike)  
C) The policy is invalid and Lambda will reject invocations  
D) Only IAM users can use wildcard principals  

**Answer: B** — `"Principal": "*"` with no conditions means public invocation. Remove and replace with scoped principals + conditions immediately.

---

## 📊 Practice Exam 1 Score Card

```
Mark your answers and calculate your score:
Q1:  B   Q2:  B   Q3:  C   Q4:  B   Q5:  C
Q6:  B   Q7:  B   Q8:  C   Q9:  B   Q10: B
Q11: B   Q12: B   Q13: B   Q14: B   Q15: B
Q16: B   Q17: B   Q18: B   Q19: B   Q20: C
Q21: B   Q22: C   Q23: B   Q24: B   Q25: B

Score: __ / 25

Target: 20+ (80%) before scheduling the exam
Below 20: Review weak areas before Exam 2
```

---

# 📅 Day 54 — Full Practice Exam 2
## 25 Scenario-Based Questions

---

**Q1.** A company wants to restrict all AWS API calls to only ap-south-1 and us-east-1 across all accounts. IAM actions must still work globally. Which SCP correctly achieves this?

A) `"Action": "*", "Condition": {"StringEquals": {"aws:RequestedRegion": ["ap-south-1","us-east-1"]}}`  
B) `"NotAction": ["iam:*","sts:*","route53:*"], "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["ap-south-1","us-east-1"]}}` with Deny  
C) `"Action": "ec2:*"` restricted to those regions  
D) Enable region restriction in IAM password policy  

**Answer: B** — `StringNotEquals` on `aws:RequestedRegion` with `NotAction` exempting global services (IAM, STS, Route53, CloudFront) is the correct pattern. Option A would ALLOW only those regions but wouldn't deny others.

---

**Q2.** An EC2 instance on ECS (EC2 launch type) has a broad IAM instance profile. A container escapes and queries 169.254.169.254 to obtain instance credentials. Which control SPECIFICALLY prevents this?

A) Task role with deny policy  
B) iptables rule on the EC2 host blocking containers from accessing 169.254.169.254  
C) Security group blocking port 80  
D) ECR image scanning  

**Answer: B** — An iptables rule on the EC2 host blocking the metadata endpoint from container network namespaces prevents containers from stealing instance-level credentials. This doesn't affect normal EC2 IMDS access from the host.

---

**Q3.** A Secrets Manager secret rotation Lambda fails during the `testSecret` stage. What happens to the secret?

A) The secret is permanently corrupted  
B) The rotation fails, AWSPENDING label is removed, and AWSCURRENT remains the old valid value — no downtime occurs  
C) The application is immediately locked out  
D) The secret is automatically restored from AWSPREVIOUS  

**Answer: B** — If any rotation Lambda stage fails, SM rolls back — AWSCURRENT remains the working value. No application impact. Fix the Lambda and retry rotation.

---

**Q4.** A Security Hub finding with severity 8.5 is generated. The company's EventBridge rule only routes findings with severity >= 9.0. What happens?

A) The finding is auto-remediated by Security Hub  
B) The finding exists in Security Hub but is NOT routed to the remediation Lambda  
C) The finding is escalated to severity 9.0 automatically  
D) EventBridge routes all Security Hub findings regardless of rules  

**Answer: B** — EventBridge pattern matching is exact. Severity 8.5 doesn't match `>= 9.0`. The finding is visible in Security Hub but no automated action occurs. Consider separate rules for Medium/High severity findings.

---

**Q5.** A developer pushes an image tagged `:latest` to an ECR repo with tag immutability DISABLED. The CI/CD pipeline deploys this image. Next day, another push overwrites `:latest`. What is the security risk?

A) No risk — Docker always uses the same image for a given tag  
B) New ECS task launches or service updates will silently pull the new (potentially malicious) image without any change to the task definition  
C) ECR rejects overwrites by default  
D) The old image is preserved in ECR  

**Answer: B** — Without tag immutability, `:latest` can be silently overwritten. Supply chain attack: push malicious image to `:latest`, wait for ECS service to scale up, malicious code runs. Enable IMMUTABLE tag mutability and use digest-pinned references.

---

**Q6.** An organization has GuardDuty enabled with org integration. A member account admin attempts to delete their GuardDuty detector. What prevents this?

A) GuardDuty cannot be deleted in member accounts  
B) SCP at root denying `guardduty:DeleteDetector` + GuardDuty org integration preventing member account opt-out  
C) IAM policy in each account  
D) Control Tower mandatory guardrail  

**Answer: B** — Two controls: SCP denies the API call at the policy level. GuardDuty org integration with `AutoEnable` means even if the detector were somehow disabled, it would be re-enabled by the management account.

---

**Q7.** A Step Functions workflow for incident response needs to: (1) snapshot EC2, (2) isolate EC2, (3) wait for human approval, (4) terminate EC2. At step 4, an admin accidentally clicks "Terminate" on the wrong instance. How should the architecture prevent this?

A) Use Lambda instead of Step Functions  
B) Include the specific instance ID in the approval request and require the reviewer to confirm by inputting the instance ID in the approval response  
C) Skip the human approval step  
D) Use Config rules instead  

**Answer: B** — The task token callback approval message should include the instance ID, finding details, and case reference. The reviewer confirmation input should include the instance ID — preventing accidental approval for the wrong resource.

---

**Q8.** AWS Config finds an EC2 instance with port 22 open to 0.0.0.0/0. The company wants this auto-remediated. Which SSM Automation document addresses this?

A) `AWS-StopEC2Instance`  
B) `AWS-DisablePublicAccessForSecurityGroup`  
C) `AWS-TerminateEC2Instance`  
D) `AWS-CreateSnapshot`  

**Answer: B** — `AWS-DisablePublicAccessForSecurityGroup` removes rules allowing unrestricted access (0.0.0.0/0 or ::/0) from security groups. It's the pre-built SSM document for the `restricted-ssh` Config rule remediation.

---

**Q9.** A company migrates from SSH + bastion to AWS SSM Session Manager. Which THREE changes should be made to harden the security posture?

A) Remove SSH keys from all EC2 instances, revoke port 22 inbound in security groups, enable Session Manager logging to S3  
B) Add port 2222 as alternative SSH port, enable MFA on SSH, deploy bastion in private subnet  
C) Rotate SSH keys weekly, limit SSH to corporate IPs, add MFA  
D) Keep bastion as backup, log SSH sessions to S3  

**Answer: A** — Remove SSH keys (no fallback attack surface), close port 22 (no inbound), enable session logging (audit trail). This completes the migration properly.

---

**Q10.** A company's forensics team needs to query 12 months of CloudTrail logs to investigate a breach. CloudTrail Event History shows only 90 days. Where are the older logs?

A) They are automatically archived to Glacier by CloudTrail  
B) In the S3 delivery bucket configured in the CloudTrail trail (accessible via Athena)  
C) In DynamoDB (CloudTrail default secondary storage)  
D) Unavailable — CloudTrail only retains 90 days  

**Answer: B** — CloudTrail delivers logs to S3 indefinitely (governed by your lifecycle policy). Athena can query these logs with SQL. The 90-day limit is only for the Event History UI in the console.

---

**Q11.** An organization uses Control Tower. They want to add custom SCPs that go beyond the built-in guardrails without causing CT drift. What is the correct approach?

A) Edit the Control Tower-managed SCPs directly  
B) Use Customizations for Control Tower (CfCT) to deploy custom SCPs via a managed pipeline  
C) Create SCPs manually in Organizations console  
D) Ask AWS Support to add custom guardrails  

**Answer: B** — CfCT is the AWS-native mechanism for extending Control Tower with custom controls. It deploys via a pipeline that integrates with Account Factory, avoiding drift.

---

**Q12.** A Lambda function handles sensitive financial data. The security team wants to ensure no tampered code ever executes. Which control addresses this?

A) VPC placement  
B) Reserved concurrency limits  
C) Code Signing with AWS Signer in Enforce mode attached to the function  
D) Environment variable encryption with CMK  

**Answer: C** — Code Signing validates the deployment package cryptographic signature against trusted AWS Signer profiles. Enforce mode blocks deployment if the signature is invalid or from an untrusted profile.

---

**Q13.** Which EKS security feature directly controls what AWS services an individual pod can access (without giving the entire node access)?

A) Network Policy (Calico)  
B) IRSA — IAM Roles for Service Accounts  
C) Security Groups for Pods  
D) Pod Security Standards (Restricted profile)  

**Answer: B** — IRSA provides per-pod IAM role assumption via OIDC. Each pod gets exactly the AWS permissions its service account is mapped to — independent of the node's instance profile.

---

**Q14.** A company's RDS database password needs to be rotated every 30 days with ZERO application downtime. Which Secrets Manager rotation type achieves this?

A) Single-user rotation with 30-day schedule  
B) Lambda rotation with custom `createSecret → setSecret → testSecret → finishSecret` pipeline  
C) Multi-user rotation with 30-day schedule  
D) Manual rotation with scheduled SSM automation  

**Answer: C** — Multi-user rotation creates and validates a new user's credentials before switching AWSCURRENT. The application uses the current credentials throughout — no downtime. Single-user rotation has a brief gap.

---

**Q15.** AWS Macie generates a finding that sensitive PII data exists in an S3 bucket not intended for PII storage. What is the immediate response?

A) Delete the bucket  
B) Identify the source of the PII upload (CloudTrail), apply bucket policy to restrict access, notify data privacy team, assess notification obligations  
C) Enable GuardDuty on the bucket  
D) Move the bucket to a different region  

**Answer: B** — Multi-step response: investigate (CloudTrail for who uploaded), contain (bucket policy), notify (privacy team), assess (GDPR/DPDPA 72-hour notification obligations). Macie classifies data; response is a people + process + tech response.

---

**Q16.** A service account in EKS is bound to a ClusterRole with `system:masters`. A pod using this service account is compromised. What is the blast radius?

A) Only the pod's namespace is affected  
B) The attacker has full Kubernetes cluster admin — can read all secrets in all namespaces, modify RBAC, deploy to all namespaces, escalate to other workloads  
C) Only read access to the cluster  
D) Limited to the pod's resource requests  

**Answer: B** — `system:masters` = unrestricted cluster admin. A compromised pod bound to this role gives the attacker complete control of the Kubernetes cluster. Never bind service accounts to `system:masters`.

---

**Q17.** A company enables AWS Config but realizes the Config S3 delivery bucket lacks a bucket policy allowing `config.amazonaws.com` to write. What happens?

A) Config stores findings in DynamoDB instead  
B) Config evaluation continues but configuration snapshots and history fail to deliver to S3 — no data loss in Config service, but no S3 archive  
C) Config auto-creates the bucket policy  
D) Config stops evaluating rules  

**Answer: B** — Config requires the bucket policy to include `config.amazonaws.com` as a principal with `s3:PutObject` on the bucket. Without it, delivery fails silently. Config evaluation continues using its internal store.

---

**Q18.** An attacker pushes a malicious Lambda layer to a public ECR-equivalent layer ARN and tricks developers into using it. Which control prevents this?

A) Reserved concurrency  
B) VPC placement  
C) Code signing + restricting layer resource policy to specific trusted account IDs only  
D) CloudWatch monitoring  

**Answer: C** — Code signing validates layer integrity. Restricting layer resource policy to specific trusted account IDs prevents external accounts from sharing malicious layers. Never use public layers from unknown sources.

---

**Q19.** A company discovers that CloudTrail is enabled but NOT logging S3 data events (GetObject, PutObject). An S3 data exfiltration incident is suspected. What forensic data is available?

A) No S3-related forensic data is available  
B) S3 management events (CreateBucket, DeleteBucket, PutBucketPolicy) are logged by default in CloudTrail, but object-level access (GetObject) is NOT — only S3 Server Access Logs (if enabled) would show GetObject calls  
C) GuardDuty compensates for missing S3 data events  
D) Config provides object-level S3 access logs  

**Answer: B** — CloudTrail S3 data events (GetObject, PutObject) are NOT enabled by default — they must be explicitly configured. S3 Server Access Logs or enabling data events going forward are needed for object-level forensics. This incident creates a gap in evidence.

---

**Q20.** A company wants to share a Service Catalog portfolio containing 10 approved infrastructure products with all 120 accounts in their AWS Organization. What is the most efficient approach?

A) Import the portfolio manually in each account  
B) Share the portfolio at the Organization root level via Service Catalog — automatically distributes to all current and future accounts  
C) Use CloudFormation StackSets to deploy each product template  
D) Email the CloudFormation templates to each account admin  

**Answer: B** — Portfolio sharing at the Organization root (or OU) level automatically makes the portfolio available in all member accounts. New accounts added to the org automatically receive access.

---

**Q21.** A GuardDuty finding `Discovery:S3/AnomalousBehavior` is generated. What does this indicate?

A) An S3 bucket was made public  
B) An IAM principal is performing S3 reconnaissance — listing buckets, listing objects, or accessing S3 in a way that deviates from their established baseline behavior  
C) An S3 bucket was deleted  
D) A Lambda function accessed S3 without permission  

**Answer: B** — `Discovery:S3/AnomalousBehavior` indicates unusual S3 enumeration or access patterns compared to the entity's CloudTrail baseline. Common precursor to data exfiltration.

---

**Q22.** Which Control Tower component is responsible for providing the security team read-only access to all member accounts and receiving SNS compliance notifications?

A) Log Archive account  
B) Audit account  
C) Management account  
D) Security tooling account  

**Answer: B** — The **Audit account** is the security team's operational hub in Control Tower — read-only access to all member accounts + SNS topics receiving compliance alerts. Log Archive stores the actual log files.

---

**Q23.** An ECS task is running with a database password injected via Secrets Manager ARN reference. Secrets Manager rotates the password. The running task starts failing database connections. What is the MOST LIKELY cause and fix?

A) The task role doesn't have SM permissions — add secretsmanager:GetSecretValue  
B) The running task still has the old (rotated) password in its environment. Fix: either restart the task after rotation, or implement SM client refresh logic in the application code  
C) SM rotation always causes a 5-minute outage  
D) Use multi-user rotation instead of single-user  

**Answer: B** — ECS injects at launch time. After rotation, the running task's env var is stale. Solutions: (1) design rotation windows with task restarts, (2) application fetches fresh secret on connection error, or (3) use multi-user rotation to avoid password invalidation while tasks are running.

---

**Q24.** A company needs to query which EC2 instances were running in their environment on January 15th 2024 — a date 8 months ago. Which service provides this historical inventory data?

A) EC2 console (only shows current state)  
B) AWS Config configuration history — shows the state of every resource at any point in time  
C) CloudTrail — shows EC2 launch/terminate events  
D) Systems Manager Inventory (only current state)  

**Answer: B** — AWS Config maintains configuration history for all recorded resources. You can query the configuration timeline to see what instances existed at any past point, their configuration, tags, and relationships.

---

**Q25.** A company wants the STRONGEST protection for AWS Backup recovery points against a ransomware operator who gains full admin access to the AWS account. What architecture achieves this?

A) AWS Backup with versioning enabled in the production account  
B) AWS Backup with Vault Lock (Compliance mode) in a SEPARATE isolated account + SCP on the backup account denying backup deletion + cross-account backup copy  
C) AWS Backup with MFA delete on the backup S3 bucket  
D) Daily snapshots with 30-day retention in the production account  

**Answer: B** — Defense-in-depth for backups: (1) separate account prevents production account compromise from reaching backups, (2) Vault Lock Compliance mode prevents deletion even by root, (3) SCP on backup account adds another layer, (4) cross-account copy provides geographic + account separation.

---

## 📊 Practice Exam 2 Score Card

```
Mark your answers and calculate your score:
Q1:  B   Q2:  B   Q3:  B   Q4:  B   Q5:  B
Q6:  B   Q7:  B   Q8:  B   Q9:  A   Q10: B
Q11: B   Q12: C   Q13: B   Q14: C   Q15: B
Q16: B   Q17: B   Q18: C   Q19: B   Q20: B
Q21: B   Q22: B   Q23: B   Q24: B   Q25: B

Score: __ / 25

Weak area analysis:
- Score < 3/3 on Organization/SCP questions → Review Day 44
- Score < 3/3 on Container questions → Review Day 41/42
- Score < 3/3 on IR/Forensics questions → Review Day 48/49
- Score < 3/3 on Config/Remediation → Review Day 43/51
```

---

# 🎉 Days 49–54 Complete!

```
Lab + Exam Summary:
├── Lab 119: Forensics (S3 Object Lock + EBS snapshot + Athena)
├── Lab 120: SSM (Session Manager + Patch Manager + Parameter Store)
├── Lab 121: Automated Remediation (Config + EventBridge + Lambda)
├── Lab 122: Real-World Scenarios (IMDSv2 + credential IR + architecture)
├── Day 53: Practice Exam 1 (25 questions + answers)
└── Day 54: Practice Exam 2 (25 questions + answers)

Next Steps (Days 55-56):
├── Day 55: Full Practice Exam 3 + identify weak areas
├── Day 56: Weak area deep dive + flashcard review
├── Week 9: Final prep + exam readiness assessment
└── Week 10: Schedule exam when scoring 80%+ consistently

You've covered all the material, Pradeep.
Time to lock in the exam date and go get it! 🚀
```
