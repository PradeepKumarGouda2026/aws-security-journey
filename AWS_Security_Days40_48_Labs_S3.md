# 📚 AWS Security Specialist — Days 40–48
## Section 3: Labs
### Pradeep Kumar | Study Plan

---

> **Coverage:**
> - Lab 40: Lambda Security
> - Lab 41: ECS/EKS Security
> - Lab 42: Secrets in Containers
> - Lab 43: AWS Config
> - Lab 44: AWS Organizations (SCPs)
> - Lab 45: Control Tower
> - Lab 46: Service Catalog
> - Lab 47: AWS Artifact
> - Lab 48: Incident Response Playbooks

---

# 📅 Day 40 — Section 3: Lab 110
## Lambda Security — Full Implementation

---

## 🎯 Lab Objective
In this lab you will:
- Create a least-privilege Lambda execution role
- Store secrets in Secrets Manager (never env vars)
- Deploy a Lambda function with CMK-encrypted env vars
- Configure resource-based policy (restrict invocation)
- Set reserved concurrency (kill switch demo)
- Deploy Lambda inside a VPC with private subnet
- Configure VPC endpoint for Secrets Manager
- Enable code signing with AWS Signer
- Verify CloudTrail captures all Lambda API events
- Cleanup all resources

---

## Prerequisites Check

```bash
#!/bin/bash
# Lab 110 - Prerequisites Check
# Day 40 - Lambda Security

echo "================================================"
echo "  Lab 110: Lambda Security Prerequisites"
echo "================================================"

aws sts get-caller-identity --output table

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region || echo "ap-south-1")

echo ""
echo "Account : $ACCOUNT_ID"
echo "Region  : $REGION"

# Check existing Lambda functions
echo ""
echo "[1] Checking existing Lambda functions..."
aws lambda list-functions \
  --region $REGION \
  --query 'Functions[*].{Name:FunctionName,Runtime:Runtime,Role:Role}' \
  --output table 2>/dev/null | head -20

# Check VPCs
echo ""
echo "[2] Checking VPCs..."
aws ec2 describe-vpcs \
  --region $REGION \
  --query 'Vpcs[*].{VpcId:VpcId,CIDR:CidrBlock,Default:IsDefault}' \
  --output table

# Save env
cat > /tmp/lab110-env.sh << EOF
export ACCOUNT_ID="$ACCOUNT_ID"
export REGION="$REGION"
export LAB="lab110"
EOF

echo ""
echo "✅ Environment saved to /tmp/lab110-env.sh"
echo "================================================"
```

---

## Part 1 — Secrets Manager Secret + KMS CMK

```bash
#!/bin/bash
# Lab 110 - Part 1: Secret + KMS Setup
source /tmp/lab110-env.sh

echo "================================================"
echo "  Part 1: Secrets Manager + KMS CMK"
echo "================================================"

# Step 1: Create KMS CMK for Lambda env var encryption
echo ""
echo "[1] Creating KMS CMK for Lambda..."
KEY_ID=$(aws kms create-key \
  --description "Lab110 Lambda env var CMK" \
  --key-usage ENCRYPT_DECRYPT \
  --region $REGION \
  --query 'KeyMetadata.KeyId' \
  --output text)

aws kms create-alias \
  --alias-name "alias/lab110-lambda-cmk" \
  --target-key-id $KEY_ID \
  --region $REGION

KEY_ARN=$(aws kms describe-key \
  --key-id $KEY_ID \
  --query 'KeyMetadata.Arn' \
  --output text)

echo "✅ KMS CMK created: $KEY_ID"
echo "export KEY_ID=\"$KEY_ID\"" >> /tmp/lab110-env.sh
echo "export KEY_ARN=\"$KEY_ARN\"" >> /tmp/lab110-env.sh

# Step 2: Create secret in Secrets Manager
echo ""
echo "[2] Creating secret in Secrets Manager..."
SECRET_ARN=$(aws secretsmanager create-secret \
  --name "lab110/app/dbpassword" \
  --description "Lab110 simulated DB password" \
  --secret-string '{"username":"dbadmin","password":"S3cur3P@ss!Lab110"}' \
  --kms-key-id $KEY_ID \
  --region $REGION \
  --query 'ARN' \
  --output text)

echo "✅ Secret created: $SECRET_ARN"
echo "export SECRET_ARN=\"$SECRET_ARN\"" >> /tmp/lab110-env.sh

# Step 3: Verify secret is encrypted with CMK
echo ""
echo "[3] Verifying secret encryption..."
aws secretsmanager describe-secret \
  --secret-id "lab110/app/dbpassword" \
  --region $REGION \
  --query '{Name:Name,KmsKey:KmsKeyId,RotationEnabled:RotationEnabled}' \
  --output table

echo ""
echo "================================================"
echo "Part 1 Complete!"
echo "================================================"
```

---

## Part 2 — IAM Execution Role (Least Privilege)

```bash
#!/bin/bash
# Lab 110 - Part 2: IAM Execution Role
source /tmp/lab110-env.sh

echo "================================================"
echo "  Part 2: Lambda Execution Role"
echo "================================================"

# Step 1: Create trust policy
echo ""
echo "[1] Creating Lambda execution role..."
cat > /tmp/lab110-trust.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "lambda.amazonaws.com" },
    "Action": "sts:AssumeRole"
  }]
}
EOF

ROLE_ARN=$(aws iam create-role \
  --role-name "lab110-lambda-execution-role" \
  --assume-role-policy-document file:///tmp/lab110-trust.json \
  --description "Lab110 least-privilege Lambda role" \
  --query 'Role.Arn' \
  --output text)

echo "✅ Role created: $ROLE_ARN"
echo "export ROLE_ARN=\"$ROLE_ARN\"" >> /tmp/lab110-env.sh

# Step 2: Attach baseline execution policy (CloudWatch Logs)
echo ""
echo "[2] Attaching CloudWatch Logs policy..."
aws iam attach-role-policy \
  --role-name "lab110-lambda-execution-role" \
  --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
echo "✅ AWSLambdaBasicExecutionRole attached"

# Step 3: Attach VPC execution policy
echo ""
echo "[3] Attaching VPC execution policy..."
aws iam attach-role-policy \
  --role-name "lab110-lambda-execution-role" \
  --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
echo "✅ AWSLambdaVPCAccessExecutionRole attached"

# Step 4: Create scoped inline policy for Secrets Manager
echo ""
echo "[4] Creating scoped Secrets Manager inline policy..."
cat > /tmp/lab110-sm-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue"],
      "Resource": "$SECRET_ARN"
    },
    {
      "Effect": "Allow",
      "Action": ["kms:Decrypt"],
      "Resource": "$KEY_ARN"
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name "lab110-lambda-execution-role" \
  --policy-name "SecretsManagerScoped" \
  --policy-document file:///tmp/lab110-sm-policy.json

echo "✅ Scoped SM + KMS inline policy attached"

# Step 5: Verify role policies
echo ""
echo "[5] Verifying attached policies..."
aws iam list-attached-role-policies \
  --role-name "lab110-lambda-execution-role" \
  --query 'AttachedPolicies[*].PolicyName' \
  --output table

echo ""
echo "[Expected output: AWSLambdaBasicExecutionRole, AWSLambdaVPCAccessExecutionRole]"
echo "Plus inline policy: SecretsManagerScoped"

echo ""
echo "================================================"
echo "Part 2 Complete!"
echo "================================================"
```

---

## Part 3 — VPC + Private Subnet + Security Group

```bash
#!/bin/bash
# Lab 110 - Part 3: VPC Setup for Lambda
source /tmp/lab110-env.sh

echo "================================================"
echo "  Part 3: VPC + Subnet + Security Group"
echo "================================================"

# Step 1: Create VPC
echo ""
echo "[1] Creating VPC..."
VPC_ID=$(aws ec2 create-vpc \
  --cidr-block "10.110.0.0/16" \
  --region $REGION \
  --query 'Vpc.VpcId' \
  --output text)

aws ec2 create-tags \
  --resources $VPC_ID \
  --tags Key=Name,Value=lab110-vpc Key=Lab,Value=lab110 \
  --region $REGION

echo "✅ VPC created: $VPC_ID"
echo "export VPC_ID=\"$VPC_ID\"" >> /tmp/lab110-env.sh

# Step 2: Create private subnet (no internet route)
echo ""
echo "[2] Creating private subnet..."
SUBNET_ID=$(aws ec2 create-subnet \
  --vpc-id $VPC_ID \
  --cidr-block "10.110.1.0/24" \
  --availability-zone "${REGION}a" \
  --region $REGION \
  --query 'Subnet.SubnetId' \
  --output text)

aws ec2 create-tags \
  --resources $SUBNET_ID \
  --tags Key=Name,Value=lab110-private-subnet \
  --region $REGION

echo "✅ Private subnet created: $SUBNET_ID"
echo "export SUBNET_ID=\"$SUBNET_ID\"" >> /tmp/lab110-env.sh

# Step 3: Create security group for Lambda
echo ""
echo "[3] Creating Lambda security group..."
LAMBDA_SG_ID=$(aws ec2 create-security-group \
  --group-name "lab110-lambda-sg" \
  --description "Lab110 Lambda security group" \
  --vpc-id $VPC_ID \
  --region $REGION \
  --query 'GroupId' \
  --output text)

# Lambda needs outbound HTTPS only (for Secrets Manager VPC endpoint)
aws ec2 authorize-security-group-egress \
  --group-id $LAMBDA_SG_ID \
  --protocol tcp \
  --port 443 \
  --cidr 0.0.0.0/0 \
  --region $REGION 2>/dev/null

# Remove default all-outbound rule (tighten it)
aws ec2 revoke-security-group-egress \
  --group-id $LAMBDA_SG_ID \
  --protocol -1 \
  --port -1 \
  --cidr 0.0.0.0/0 \
  --region $REGION 2>/dev/null

# Re-add only HTTPS outbound
aws ec2 authorize-security-group-egress \
  --group-id $LAMBDA_SG_ID \
  --protocol tcp \
  --port 443 \
  --cidr 10.110.0.0/16 \
  --region $REGION

echo "✅ Security group created: $LAMBDA_SG_ID (HTTPS outbound to VPC CIDR only)"
echo "export LAMBDA_SG_ID=\"$LAMBDA_SG_ID\"" >> /tmp/lab110-env.sh

# Step 4: Create VPC Interface Endpoint for Secrets Manager
echo ""
echo "[4] Creating VPC endpoint for Secrets Manager..."
SM_ENDPOINT_ID=$(aws ec2 create-vpc-endpoint \
  --vpc-id $VPC_ID \
  --service-name "com.amazonaws.${REGION}.secretsmanager" \
  --vpc-endpoint-type Interface \
  --subnet-ids $SUBNET_ID \
  --security-group-ids $LAMBDA_SG_ID \
  --private-dns-enabled \
  --region $REGION \
  --query 'VpcEndpoint.VpcEndpointId' \
  --output text)

echo "✅ Secrets Manager VPC endpoint: $SM_ENDPOINT_ID"
echo "export SM_ENDPOINT_ID=\"$SM_ENDPOINT_ID\"" >> /tmp/lab110-env.sh

echo ""
echo "⏳ Waiting 30s for VPC endpoint to become available..."
sleep 30

echo ""
echo "================================================"
echo "Part 3 Complete!"
echo "================================================"
```

---

## Part 4 — Deploy Lambda Function

```bash
#!/bin/bash
# Lab 110 - Part 4: Deploy Lambda Function
source /tmp/lab110-env.sh

echo "================================================"
echo "  Part 4: Lambda Function Deployment"
echo "================================================"

# Step 1: Create function code
echo ""
echo "[1] Creating Lambda function code..."
mkdir -p /tmp/lab110-lambda

cat > /tmp/lab110-lambda/lambda_function.py << 'PYEOF'
import boto3
import json
import os
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Lab 110 - Secure Lambda demonstrating:
    1. Secrets Manager integration (no env var secrets)
    2. Least-privilege execution role
    3. VPC + private subnet + SM VPC endpoint
    """
    secret_name = os.environ.get('SECRET_NAME', 'lab110/app/dbpassword')
    region = os.environ.get('AWS_REGION', 'ap-south-1')

    client = boto3.client('secretsmanager', region_name=region)

    try:
        response = client.get_secret_value(SecretId=secret_name)
        secret = json.loads(response['SecretString'])
        username = secret.get('username', 'unknown')

        # NEVER log the actual password
        logger.info(f"Successfully retrieved credentials for: {username}")
        logger.info(f"Function name: {context.function_name}")
        logger.info(f"Remaining time: {context.get_remaining_time_in_millis()}ms")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Secret retrieved successfully via Secrets Manager',
                'username': username,
                'source': 'SecretsManager (not env var)',
                'function': context.function_name
            })
        }

    except Exception as e:
        logger.error(f"Failed to retrieve secret: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
PYEOF

cd /tmp/lab110-lambda
zip -r function.zip lambda_function.py
echo "✅ Lambda package created"

# Step 2: Wait for role propagation
echo ""
echo "[2] Waiting 15s for IAM role propagation..."
sleep 15

# Step 3: Deploy Lambda into VPC
echo ""
echo "[3] Deploying Lambda function into VPC..."
FUNCTION_ARN=$(aws lambda create-function \
  --function-name "lab110-secure-lambda" \
  --runtime "python3.12" \
  --role "$ROLE_ARN" \
  --handler "lambda_function.lambda_handler" \
  --zip-file "fileb:///tmp/lab110-lambda/function.zip" \
  --timeout 30 \
  --memory-size 128 \
  --vpc-config "SubnetIds=$SUBNET_ID,SecurityGroupIds=$LAMBDA_SG_ID" \
  --kms-key-arn "$KEY_ARN" \
  --environment "Variables={SECRET_NAME=lab110/app/dbpassword}" \
  --description "Lab110 secure Lambda - VPC + SM + CMK" \
  --region $REGION \
  --query 'FunctionArn' \
  --output text)

echo "✅ Lambda deployed: $FUNCTION_ARN"
echo "export FUNCTION_ARN=\"$FUNCTION_ARN\"" >> /tmp/lab110-env.sh

# Step 4: Wait for Active state
echo ""
echo "[4] Waiting for Lambda to become Active..."
aws lambda wait function-active \
  --function-name "lab110-secure-lambda" \
  --region $REGION
echo "✅ Function is Active"

# Step 5: Verify VPC config
echo ""
echo "[5] Verifying VPC configuration..."
aws lambda get-function-configuration \
  --function-name "lab110-secure-lambda" \
  --region $REGION \
  --query '{State:State,VpcId:VpcConfig.VpcId,Subnets:VpcConfig.SubnetIds,KMSKey:KMSKeyArn}' \
  --output table

echo ""
echo "================================================"
echo "Part 4 Complete!"
echo "================================================"
```

---

## Part 5 — Reserved Concurrency + Resource Policy

```bash
#!/bin/bash
# Lab 110 - Part 5: Concurrency + Resource Policy
source /tmp/lab110-env.sh

echo "================================================"
echo "  Part 5: Concurrency + Resource Policy"
echo "================================================"

# Step 1: Set reserved concurrency
echo ""
echo "[1] Setting reserved concurrency to 10..."
aws lambda put-function-concurrency \
  --function-name "lab110-secure-lambda" \
  --reserved-concurrent-executions 10 \
  --region $REGION \
  --query 'ReservedConcurrentExecutions'

echo "✅ Reserved concurrency set to 10"

# Step 2: Add resource-based policy (restrict invocation)
echo ""
echo "[2] Adding resource-based policy (account-scoped)..."
aws lambda add-permission \
  --function-name "lab110-secure-lambda" \
  --statement-id "AllowCurrentAccountOnly" \
  --action "lambda:InvokeFunction" \
  --principal "arn:aws:iam::${ACCOUNT_ID}:root" \
  --region $REGION

echo "✅ Resource policy: only account $ACCOUNT_ID can invoke"

# Step 3: View resource policy
echo ""
echo "[3] Current resource policy..."
aws lambda get-policy \
  --function-name "lab110-secure-lambda" \
  --region $REGION \
  --query 'Policy' \
  --output text | python3 -m json.tool

# Step 4: Demonstrate kill switch
echo ""
echo "[4] Demonstrating kill switch (concurrency = 0)..."
aws lambda put-function-concurrency \
  --function-name "lab110-secure-lambda" \
  --reserved-concurrent-executions 0 \
  --region $REGION
echo "✅ Kill switch activated (concurrency = 0)"
echo "   → All invocations will now return 429 TooManyRequestsException"

# Step 5: Restore concurrency
echo ""
echo "[5] Restoring concurrency to 10..."
aws lambda put-function-concurrency \
  --function-name "lab110-secure-lambda" \
  --reserved-concurrent-executions 10 \
  --region $REGION
echo "✅ Concurrency restored to 10"

echo ""
echo "================================================"
echo "Part 5 Complete!"
echo "================================================"
```

---

## Part 6 — Invoke + Verify + CloudTrail Audit

```bash
#!/bin/bash
# Lab 110 - Part 6: Invoke + Verify + Audit
source /tmp/lab110-env.sh

echo "================================================"
echo "  Part 6: Invoke + Verify + CloudTrail Audit"
echo "================================================"

# Step 1: Invoke function
echo ""
echo "[1] Invoking Lambda function..."
aws lambda invoke \
  --function-name "lab110-secure-lambda" \
  --region $REGION \
  --log-type Tail \
  /tmp/lab110-output.json \
  --query 'LogResult' \
  --output text | base64 -d

echo ""
echo "Function output:"
cat /tmp/lab110-output.json | python3 -m json.tool

# Step 2: Check function configuration
echo ""
echo "[2] Function security configuration summary..."
aws lambda get-function-configuration \
  --function-name "lab110-secure-lambda" \
  --region $REGION \
  --query '{
    State: State,
    Runtime: Runtime,
    KMSKey: KMSKeyArn,
    VpcId: VpcConfig.VpcId,
    Timeout: Timeout,
    MemorySize: MemorySize
  }' \
  --output table

# Step 3: Check CloudWatch Logs for function output
echo ""
echo "[3] Checking CloudWatch Logs for function output..."
LOG_GROUP="/aws/lambda/lab110-secure-lambda"
LATEST_STREAM=$(aws logs describe-log-streams \
  --log-group-name $LOG_GROUP \
  --order-by LastEventTime \
  --descending \
  --region $REGION \
  --query 'logStreams[0].logStreamName' \
  --output text 2>/dev/null)

if [ "$LATEST_STREAM" != "None" ] && [ ! -z "$LATEST_STREAM" ]; then
  aws logs get-log-events \
    --log-group-name $LOG_GROUP \
    --log-stream-name "$LATEST_STREAM" \
    --region $REGION \
    --query 'events[*].message' \
    --output text 2>/dev/null | head -20
else
  echo "⏳ Log stream not yet available (normal - takes 1-2 min)"
fi

# Step 4: CloudTrail - verify GetSecretValue was called
echo ""
echo "[4] Checking CloudTrail for Lambda + Secrets Manager events..."
echo "    (Note: CloudTrail has ~15 min delay)"
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --region $REGION \
  --max-results 5 \
  --query 'Events[*].{Time:EventTime,Event:EventName,User:Username,Source:EventSource}' \
  --output table 2>/dev/null || echo "⏳ Events not yet available"

# Step 5: Verify env vars are encrypted (not plaintext secret)
echo ""
echo "[5] Verifying env vars contain no plaintext secrets..."
echo "    Environment variables in function config:"
aws lambda get-function-configuration \
  --function-name "lab110-secure-lambda" \
  --region $REGION \
  --query 'Environment.Variables' \
  --output table
echo "    ✅ Only SECRET_NAME (pointer) visible - actual value in Secrets Manager"

echo ""
echo "================================================"
echo "Part 6 Complete!"
echo "================================================"
```

---

## Part 7 — Cleanup

```bash
#!/bin/bash
# Lab 110 - Part 7: Cleanup
source /tmp/lab110-env.sh

echo "================================================"
echo "  Part 7: Cleanup All Lab 110 Resources"
echo "================================================"

echo ""
echo "[1] Deleting Lambda function..."
aws lambda delete-function \
  --function-name "lab110-secure-lambda" \
  --region $REGION 2>/dev/null && echo "✅ Lambda deleted"

echo ""
echo "[2] Deleting IAM role policies and role..."
aws iam detach-role-policy \
  --role-name "lab110-lambda-execution-role" \
  --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole" 2>/dev/null
aws iam detach-role-policy \
  --role-name "lab110-lambda-execution-role" \
  --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole" 2>/dev/null
aws iam delete-role-policy \
  --role-name "lab110-lambda-execution-role" \
  --policy-name "SecretsManagerScoped" 2>/dev/null
aws iam delete-role \
  --role-name "lab110-lambda-execution-role" 2>/dev/null && echo "✅ IAM role deleted"

echo ""
echo "[3] Deleting VPC endpoint..."
aws ec2 delete-vpc-endpoints \
  --vpc-endpoint-ids $SM_ENDPOINT_ID \
  --region $REGION 2>/dev/null && echo "✅ VPC endpoint deleted"

echo ""
echo "[4] Waiting 30s for endpoint deletion..."
sleep 30

echo ""
echo "[5] Deleting security group..."
aws ec2 delete-security-group \
  --group-id $LAMBDA_SG_ID \
  --region $REGION 2>/dev/null && echo "✅ Security group deleted"

echo ""
echo "[6] Deleting subnet..."
aws ec2 delete-subnet \
  --subnet-id $SUBNET_ID \
  --region $REGION 2>/dev/null && echo "✅ Subnet deleted"

echo ""
echo "[7] Deleting VPC..."
aws ec2 delete-vpc \
  --vpc-id $VPC_ID \
  --region $REGION 2>/dev/null && echo "✅ VPC deleted"

echo ""
echo "[8] Deleting Secrets Manager secret (force, no recovery)..."
aws secretsmanager delete-secret \
  --secret-id "lab110/app/dbpassword" \
  --force-delete-without-recovery \
  --region $REGION 2>/dev/null && echo "✅ Secret deleted"

echo ""
echo "[9] Scheduling KMS key deletion (7 day minimum)..."
aws kms schedule-key-deletion \
  --key-id $KEY_ID \
  --pending-window-in-days 7 \
  --region $REGION 2>/dev/null && echo "✅ KMS key scheduled for deletion in 7 days"

echo ""
echo "[10] Cleaning up temp files..."
rm -f /tmp/lab110-env.sh /tmp/lab110-trust.json \
      /tmp/lab110-sm-policy.json /tmp/lab110-output.json
rm -rf /tmp/lab110-lambda/
echo "✅ Temp files cleaned"

echo ""
echo "================================================"
echo "Lab 110 Cleanup Complete!"
echo "================================================"
```

---

## ✅ Lab 110 Verification Checklist

```
Lab 110 — Lambda Security Checklist
│
├── Prerequisites
│     ├── [ ] Identity verified, region set
│     └── [ ] VPCs and existing Lambda functions checked
│
├── Part 1: Secrets + KMS
│     ├── [ ] KMS CMK created with alias
│     ├── [ ] Secret created in Secrets Manager
│     └── [ ] Secret encrypted with CMK (not AWS-managed key)
│
├── Part 2: IAM Execution Role
│     ├── [ ] Role created with Lambda trust policy
│     ├── [ ] AWSLambdaBasicExecutionRole attached
│     ├── [ ] AWSLambdaVPCAccessExecutionRole attached
│     └── [ ] Scoped inline policy: SM ARN + KMS ARN only
│
├── Part 3: VPC + Networking
│     ├── [ ] VPC created (10.110.0.0/16)
│     ├── [ ] Private subnet (no internet route)
│     ├── [ ] Security group: HTTPS outbound to VPC CIDR only
│     └── [ ] VPC Interface Endpoint for Secrets Manager
│
├── Part 4: Lambda Deployment
│     ├── [ ] Function deployed inside VPC
│     ├── [ ] KMS CMK assigned for env var encryption
│     ├── [ ] SECRET_NAME env var (pointer, not value)
│     └── [ ] Function state: Active
│
├── Part 5: Concurrency + Resource Policy
│     ├── [ ] Reserved concurrency = 10
│     ├── [ ] Resource policy: account-scoped invocation only
│     ├── [ ] Kill switch demonstrated (concurrency = 0)
│     └── [ ] Concurrency restored to 10
│
├── Part 6: Invocation + Audit
│     ├── [ ] Function invoked successfully
│     ├── [ ] Output shows SM retrieval (not env var)
│     ├── [ ] CloudWatch Logs show username (not password)
│     └── [ ] CloudTrail captures GetSecretValue
│
└── Part 7: Cleanup
      └── [ ] All resources deleted
```

---

## 🔑 Lab 110 Key Takeaways

| Concept | What You Practiced |
|---|---|
| Least-privilege role | Scoped to specific secret ARN + KMS ARN |
| No secrets in env vars | SECRET_NAME pointer only — value in SM |
| VPC Lambda networking | Private subnet, no internet, SM VPC endpoint |
| CMK for env vars | KMS key assigned to function |
| Kill switch | Reserved concurrency = 0 |
| Resource policy | Account-scoped invocation restriction |
| Chain: SM+KMS | Both ssm:Get + kms:Decrypt needed |
| CloudTrail coverage | All Lambda + SM API calls audited |

---

# 📅 Day 41 — Section 3: Lab 111
## ECS/EKS Security

---

## 🎯 Lab Objective
In this lab you will:
- Create an ECS Task Definition with a Task Role (not instance profile)
- Deploy ECS task in awsvpc mode (task-level security groups)
- Inject secrets via Secrets Manager ARN (native ECS integration)
- Enable ECS Container Insights for monitoring
- Create and verify ECR image with tag immutability
- Enable ECR Enhanced Scanning (Inspector)
- Verify CloudTrail captures ECS + ECR events
- Cleanup all resources

---

## Prerequisites Check

```bash
#!/bin/bash
# Lab 111 - Prerequisites Check
# Day 41 - ECS/EKS Security

echo "================================================"
echo "  Lab 111: ECS/EKS Security Prerequisites"
echo "================================================"

aws sts get-caller-identity --output table

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region || echo "ap-south-1")

echo ""
echo "Account : $ACCOUNT_ID"
echo "Region  : $REGION"

# Check ECS clusters
echo ""
echo "[1] Checking ECS clusters..."
aws ecs list-clusters \
  --region $REGION \
  --query 'clusterArns[]' \
  --output table 2>/dev/null || echo "No clusters found"

# Check ECR repositories
echo ""
echo "[2] Checking ECR repositories..."
aws ecr describe-repositories \
  --region $REGION \
  --query 'repositories[*].{Name:repositoryName,Scan:imageScanningConfiguration.scanOnPush}' \
  --output table 2>/dev/null || echo "No repositories found"

# Save env
cat > /tmp/lab111-env.sh << EOF
export ACCOUNT_ID="$ACCOUNT_ID"
export REGION="$REGION"
export LAB="lab111"
EOF

echo ""
echo "✅ Environment saved to /tmp/lab111-env.sh"
echo "================================================"
```

---

## Part 1 — ECR Repository with Security Controls

```bash
#!/bin/bash
# Lab 111 - Part 1: ECR Security Setup
source /tmp/lab111-env.sh

echo "================================================"
echo "  Part 1: ECR Repository + Security Controls"
echo "================================================"

# Step 1: Create ECR repository with tag immutability + scanning
echo ""
echo "[1] Creating ECR repository with security controls..."
REPO_URI=$(aws ecr create-repository \
  --repository-name "lab111-secure-app" \
  --image-tag-mutability IMMUTABLE \
  --image-scanning-configuration scanOnPush=true \
  --encryption-configuration encryptionType=KMS \
  --region $REGION \
  --query 'repository.repositoryUri' \
  --output text)

echo "✅ ECR repository created: $REPO_URI"
echo "   Tag mutability: IMMUTABLE"
echo "   Scan on push: ENABLED"
echo "   Encryption: KMS"
echo "export REPO_URI=\"$REPO_URI\"" >> /tmp/lab111-env.sh

# Step 2: Enable Enhanced Scanning (Inspector)
echo ""
echo "[2] Enabling ECR Enhanced Scanning via Inspector..."
aws inspector2 enable \
  --resource-types ECR \
  --region $REGION 2>/dev/null && \
  echo "✅ Inspector ECR Enhanced Scanning enabled" || \
  echo "⚠️  Inspector may already be enabled or requires activation"

# Step 3: Apply ECR repository policy (restrict cross-account pull)
echo ""
echo "[3] Applying repository policy (account-only pull)..."
cat > /tmp/lab111-ecr-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAccountPull",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${ACCOUNT_ID}:root"
      },
      "Action": [
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "ecr:BatchCheckLayerAvailability"
      ]
    }
  ]
}
EOF

aws ecr set-repository-policy \
  --repository-name "lab111-secure-app" \
  --policy-text file:///tmp/lab111-ecr-policy.json \
  --region $REGION
echo "✅ Repository policy applied (account-scoped pull only)"

# Step 4: Build + push a simple test image
echo ""
echo "[4] Building and pushing test image..."
aws ecr get-login-password \
  --region $REGION | \
  docker login \
  --username AWS \
  --password-stdin \
  "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com" 2>/dev/null || \
  echo "⚠️  Docker login skipped (Docker may not be available in this env)"

cat > /tmp/Dockerfile << 'EOF'
FROM public.ecr.aws/amazonlinux/amazonlinux:2023
RUN yum install -y python3 && yum clean all
COPY app.py /app/app.py
CMD ["python3", "/app/app.py"]
EOF

cat > /tmp/app.py << 'EOF'
import time
print("Lab 111 - Secure container app running")
time.sleep(60)
EOF

docker build -t lab111-secure-app /tmp/ 2>/dev/null && \
  docker tag lab111-secure-app:latest \
    "${REPO_URI}:v1.0" && \
  docker push "${REPO_URI}:v1.0" && \
  echo "✅ Image pushed: ${REPO_URI}:v1.0" || \
  echo "⚠️  Docker build/push skipped (Docker not available)"

echo ""
echo "================================================"
echo "Part 1 Complete!"
echo "================================================"
```

---

## Part 2 — ECS Task Role + Execution Role + Secret

```bash
#!/bin/bash
# Lab 111 - Part 2: ECS IAM Roles + Secret
source /tmp/lab111-env.sh

echo "================================================"
echo "  Part 2: ECS Task Role + Execution Role + Secret"
echo "================================================"

# Step 1: Create secret for ECS injection
echo ""
echo "[1] Creating secret for ECS injection..."
ECS_SECRET_ARN=$(aws secretsmanager create-secret \
  --name "lab111/app/api-key" \
  --description "Lab111 ECS injected API key" \
  --secret-string '{"api_key":"lab111-super-secret-key-xyz"}' \
  --region $REGION \
  --query 'ARN' \
  --output text)

echo "✅ Secret created: $ECS_SECRET_ARN"
echo "export ECS_SECRET_ARN=\"$ECS_SECRET_ARN\"" >> /tmp/lab111-env.sh

# Step 2: Create ECS Task Execution Role
echo ""
echo "[2] Creating ECS Task Execution Role..."
cat > /tmp/lab111-ecs-trust.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "ecs-tasks.amazonaws.com" },
    "Action": "sts:AssumeRole"
  }]
}
EOF

EXEC_ROLE_ARN=$(aws iam create-role \
  --role-name "lab111-ecs-execution-role" \
  --assume-role-policy-document file:///tmp/lab111-ecs-trust.json \
  --description "Lab111 ECS task execution role" \
  --query 'Role.Arn' \
  --output text)

# Attach base execution policy
aws iam attach-role-policy \
  --role-name "lab111-ecs-execution-role" \
  --policy-arn "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"

# Add scoped SM policy
cat > /tmp/lab111-exec-sm-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["secretsmanager:GetSecretValue"],
    "Resource": "$ECS_SECRET_ARN"
  }]
}
EOF

aws iam put-role-policy \
  --role-name "lab111-ecs-execution-role" \
  --policy-name "SMSecretAccess" \
  --policy-document file:///tmp/lab111-exec-sm-policy.json

echo "✅ Execution role created: $EXEC_ROLE_ARN"
echo "export EXEC_ROLE_ARN=\"$EXEC_ROLE_ARN\"" >> /tmp/lab111-env.sh

# Step 3: Create ECS Task Role (application-level permissions)
echo ""
echo "[3] Creating ECS Task Role (app-level AWS access)..."
TASK_ROLE_ARN=$(aws iam create-role \
  --role-name "lab111-ecs-task-role" \
  --assume-role-policy-document file:///tmp/lab111-ecs-trust.json \
  --description "Lab111 ECS task role - app permissions" \
  --query 'Role.Arn' \
  --output text)

# Minimal task policy - only what the app needs
cat > /tmp/lab111-task-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],
    "Resource": "arn:aws:logs:*:*:*"
  }]
}
EOF

aws iam put-role-policy \
  --role-name "lab111-ecs-task-role" \
  --policy-name "MinimalTaskPolicy" \
  --policy-document file:///tmp/lab111-task-policy.json

echo "✅ Task role created: $TASK_ROLE_ARN"
echo "   (Execution Role = ECS agent | Task Role = app code)"
echo "export TASK_ROLE_ARN=\"$TASK_ROLE_ARN\"" >> /tmp/lab111-env.sh

echo ""
echo "================================================"
echo "Part 2 Complete!"
echo "================================================"
```

---

## Part 3 — ECS Task Definition + Cluster

```bash
#!/bin/bash
# Lab 111 - Part 3: ECS Task Definition + Cluster
source /tmp/lab111-env.sh

echo "================================================"
echo "  Part 3: ECS Cluster + Task Definition"
echo "================================================"

# Step 1: Create ECS Cluster with Container Insights
echo ""
echo "[1] Creating ECS cluster with Container Insights..."
CLUSTER_ARN=$(aws ecs create-cluster \
  --cluster-name "lab111-secure-cluster" \
  --settings name=containerInsights,value=enabled \
  --region $REGION \
  --query 'cluster.clusterArn' \
  --output text)

echo "✅ Cluster created: $CLUSTER_ARN"
echo "export CLUSTER_ARN=\"$CLUSTER_ARN\"" >> /tmp/lab111-env.sh

# Step 2: Create CloudWatch Log Group for ECS
echo ""
echo "[2] Creating CloudWatch log group..."
aws logs create-log-group \
  --log-group-name "/ecs/lab111-secure-app" \
  --region $REGION 2>/dev/null
echo "✅ Log group created: /ecs/lab111-secure-app"

# Step 3: Create Task Definition with secrets injection
echo ""
echo "[3] Creating Task Definition with SM secret injection..."

# Use a public image for lab since ECR push may not work in all environments
IMAGE="${REPO_URI}:v1.0"
FALLBACK_IMAGE="public.ecr.aws/amazonlinux/amazonlinux:2023"

cat > /tmp/lab111-taskdef.json << EOF
{
  "family": "lab111-secure-taskdef",
  "taskRoleArn": "$TASK_ROLE_ARN",
  "executionRoleArn": "$EXEC_ROLE_ARN",
  "networkMode": "awsvpc",
  "cpu": "256",
  "memory": "512",
  "requiresCompatibilities": ["FARGATE"],
  "containerDefinitions": [
    {
      "name": "lab111-app",
      "image": "$FALLBACK_IMAGE",
      "essential": true,
      "command": ["sh", "-c", "echo API_KEY=\$API_KEY_VALUE | cut -c1-15 && sleep 60"],
      "secrets": [
        {
          "name": "API_KEY_VALUE",
          "valueFrom": "$ECS_SECRET_ARN"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/lab111-secure-app",
          "awslogs-region": "$REGION",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "readonlyRootFilesystem": true
    }
  ]
}
EOF

TASKDEF_ARN=$(aws ecs register-task-definition \
  --cli-input-json file:///tmp/lab111-taskdef.json \
  --region $REGION \
  --query 'taskDefinition.taskDefinitionArn' \
  --output text)

echo "✅ Task Definition registered: $TASKDEF_ARN"
echo "   Network mode: awsvpc (task-level security groups)"
echo "   Secret: injected via valueFrom ARN (not plaintext)"
echo "   Root filesystem: read-only"
echo "export TASKDEF_ARN=\"$TASKDEF_ARN\"" >> /tmp/lab111-env.sh

# Step 4: Verify task definition
echo ""
echo "[4] Verifying task definition security settings..."
aws ecs describe-task-definition \
  --task-definition "lab111-secure-taskdef" \
  --region $REGION \
  --query 'taskDefinition.{
    TaskRole:taskRoleArn,
    ExecRole:executionRoleArn,
    NetworkMode:networkMode,
    Secrets:containerDefinitions[0].secrets,
    ReadOnly:containerDefinitions[0].readonlyRootFilesystem
  }' \
  --output json | python3 -m json.tool

echo ""
echo "================================================"
echo "Part 3 Complete!"
echo "================================================"
```

---

## Part 4 — CloudTrail Audit + Cleanup

```bash
#!/bin/bash
# Lab 111 - Part 4: Audit + Cleanup
source /tmp/lab111-env.sh

echo "================================================"
echo "  Part 4: CloudTrail Audit + Cleanup"
echo "================================================"

# Step 1: Check CloudTrail for ECS events
echo ""
echo "[1] Checking CloudTrail for ECS registration events..."
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RegisterTaskDefinition \
  --region $REGION \
  --max-results 3 \
  --query 'Events[*].{Time:EventTime,Event:EventName,User:Username}' \
  --output table 2>/dev/null || echo "⏳ Events not yet available (~15 min delay)"

# Step 2: Verify ECR scan results (if image was pushed)
echo ""
echo "[2] Checking ECR scan results..."
aws ecr describe-image-scan-findings \
  --repository-name "lab111-secure-app" \
  --image-id imageTag=v1.0 \
  --region $REGION \
  --query 'imageScanFindings.findingSeverityCounts' \
  --output table 2>/dev/null || echo "⚠️  No scan results (image may not have been pushed)"

# CLEANUP
echo ""
echo "================================================"
echo "  CLEANUP"
echo "================================================"

echo ""
echo "[3] Deregistering task definition..."
aws ecs deregister-task-definition \
  --task-definition "$TASKDEF_ARN" \
  --region $REGION 2>/dev/null && echo "✅ Task definition deregistered"

echo ""
echo "[4] Deleting ECS cluster..."
aws ecs delete-cluster \
  --cluster "lab111-secure-cluster" \
  --region $REGION 2>/dev/null && echo "✅ Cluster deleted"

echo ""
echo "[5] Deleting ECR repository..."
aws ecr delete-repository \
  --repository-name "lab111-secure-app" \
  --force \
  --region $REGION 2>/dev/null && echo "✅ ECR repository deleted"

echo ""
echo "[6] Deleting secret..."
aws secretsmanager delete-secret \
  --secret-id "lab111/app/api-key" \
  --force-delete-without-recovery \
  --region $REGION 2>/dev/null && echo "✅ Secret deleted"

echo ""
echo "[7] Deleting IAM roles..."
for ROLE in "lab111-ecs-execution-role" "lab111-ecs-task-role"; do
  aws iam detach-role-policy \
    --role-name $ROLE \
    --policy-arn "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy" 2>/dev/null
  aws iam delete-role-policy \
    --role-name $ROLE \
    --policy-name "SMSecretAccess" 2>/dev/null
  aws iam delete-role-policy \
    --role-name $ROLE \
    --policy-name "MinimalTaskPolicy" 2>/dev/null
  aws iam delete-role --role-name $ROLE 2>/dev/null && \
    echo "✅ Role deleted: $ROLE"
done

echo ""
echo "[8] Deleting CloudWatch log group..."
aws logs delete-log-group \
  --log-group-name "/ecs/lab111-secure-app" \
  --region $REGION 2>/dev/null && echo "✅ Log group deleted"

echo ""
echo "[9] Cleanup temp files..."
rm -f /tmp/lab111-env.sh /tmp/lab111-*.json \
      /tmp/Dockerfile /tmp/app.py
echo "✅ Temp files cleaned"

echo ""
echo "================================================"
echo "Lab 111 Cleanup Complete!"
echo "================================================"
```

---

## ✅ Lab 111 Verification Checklist

```
Lab 111 — ECS/EKS Security Checklist
│
├── Part 1: ECR Security
│     ├── [ ] Repository with IMMUTABLE tag mutability
│     ├── [ ] Scan on push enabled
│     ├── [ ] KMS encryption enabled
│     ├── [ ] Inspector Enhanced Scanning enabled
│     └── [ ] Repository policy: account-scoped pull
│
├── Part 2: IAM Roles
│     ├── [ ] Execution role: ECS agent operations
│     ├── [ ] Execution role: SM secret fetch (scoped ARN)
│     ├── [ ] Task role: application code permissions
│     └── [ ] Key distinction understood: Exec vs Task role
│
├── Part 3: Task Definition
│     ├── [ ] Network mode: awsvpc
│     ├── [ ] Secret injected via valueFrom ARN (not plaintext)
│     ├── [ ] readonlyRootFilesystem: true
│     ├── [ ] Container Insights enabled on cluster
│     └── [ ] CloudWatch log configuration set
│
└── Part 4: Audit + Cleanup
      ├── [ ] CloudTrail captures ECS events
      ├── [ ] ECR scan findings reviewed
      └── [ ] All resources deleted
```

---

## 🔑 Lab 111 Key Takeaways

| Concept | What You Practiced |
|---|---|
| Task Role vs Exec Role | Task=app code; Execution=ECS agent |
| awsvpc mode | Task-level security groups |
| SM secret injection | valueFrom ARN in task definition |
| ECR tag immutability | IMMUTABLE prevents :latest overwrite |
| Enhanced scanning | Inspector continuous CVE detection |
| Read-only root FS | Container filesystem hardening |
| Container Insights | ECS cluster-level monitoring |

---

# 📅 Day 42 — Section 3: Lab 112
## Secrets in Containers

---

## 🎯 Lab Objective
In this lab you will:
- Compare insecure vs secure secrets injection patterns
- Store and retrieve secrets from Secrets Manager
- Configure ECS native secrets injection (ARN reference)
- Test SSM Parameter Store SecureString injection
- Enable CloudTrail for all GetSecretValue calls
- Demonstrate multi-user rotation concept
- Cleanup all resources

---

## Prerequisites Check

```bash
#!/bin/bash
# Lab 112 - Prerequisites Check
source /tmp/lab112-env.sh 2>/dev/null || true

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region || echo "ap-south-1")

cat > /tmp/lab112-env.sh << EOF
export ACCOUNT_ID="$ACCOUNT_ID"
export REGION="$REGION"
export LAB="lab112"
EOF

echo "================================================"
echo "  Lab 112: Secrets in Containers Prerequisites"
echo "================================================"
aws sts get-caller-identity --output table
echo "Region: $REGION"
echo "✅ Environment saved to /tmp/lab112-env.sh"
echo "================================================"
```

---

## Part 1 — Insecure vs Secure Pattern Comparison

```bash
#!/bin/bash
# Lab 112 - Part 1: Secrets Pattern Comparison (Conceptual)
source /tmp/lab112-env.sh

echo "================================================"
echo "  Part 1: Secrets Patterns — Insecure vs Secure"
echo "================================================"

# Demonstrate the insecure pattern (for educational purposes only)
echo ""
echo "[INSECURE PATTERN - DO NOT USE IN PRODUCTION]"
echo "---------------------------------------------"
cat << 'EOF'
# Anti-pattern 1: Hardcoded in task definition
"environment": [
  {"name": "DB_PASSWORD", "value": "plaintext-password-here"}
]
# Visible in: API response, console, task definition history, logs

# Anti-pattern 2: Baked into Docker image
# Dockerfile: ENV DB_PASSWORD=mypassword
# Visible in: docker history, ECR, any image pull

# Anti-pattern 3: Kubernetes Secret (base64 only)
# kubectl create secret generic db-pass --from-literal=password=mypass
# Visible as base64 to anyone with kubectl get secret + kube:Decode
EOF

echo ""
echo "[SECURE PATTERN - USE THIS]"
echo "---------------------------"
cat << 'EOF'
# Correct pattern: SM ARN reference in ECS task definition
"secrets": [
  {
    "name": "DB_PASSWORD",
    "valueFrom": "arn:aws:secretsmanager:region:account:secret:prod/db/pass"
  }
]
# Value NEVER appears in task definition — fetched at launch by ECS agent
# Requires Task Execution Role with secretsmanager:GetSecretValue
EOF

echo ""
echo "================================================"
echo "Part 1 Complete (Conceptual Review)"
echo "================================================"
```

---

## Part 2 — Create Secrets + SSM Parameters

```bash
#!/bin/bash
# Lab 112 - Part 2: Create Secrets + Parameters
source /tmp/lab112-env.sh

echo "================================================"
echo "  Part 2: Secrets Manager + SSM Parameter Store"
echo "================================================"

# Step 1: Create KMS CMK
echo ""
echo "[1] Creating KMS CMK for secrets..."
KEY_ID=$(aws kms create-key \
  --description "Lab112 secrets CMK" \
  --query 'KeyMetadata.KeyId' \
  --region $REGION \
  --output text)
aws kms create-alias \
  --alias-name "alias/lab112-secrets-cmk" \
  --target-key-id $KEY_ID \
  --region $REGION
KEY_ARN=$(aws kms describe-key --key-id $KEY_ID --query 'KeyMetadata.Arn' --output text --region $REGION)
echo "✅ KMS CMK: $KEY_ID"
echo "export KEY_ID=\"$KEY_ID\"" >> /tmp/lab112-env.sh
echo "export KEY_ARN=\"$KEY_ARN\"" >> /tmp/lab112-env.sh

# Step 2: Create multiple Secrets Manager secrets
echo ""
echo "[2] Creating Secrets Manager secrets..."

DB_SECRET_ARN=$(aws secretsmanager create-secret \
  --name "lab112/prod/db-password" \
  --secret-string '{"username":"prodadmin","password":"Pr0dS3cur3!Pass"}' \
  --kms-key-id $KEY_ID \
  --region $REGION \
  --query 'ARN' --output text)
echo "✅ DB secret: $DB_SECRET_ARN"
echo "export DB_SECRET_ARN=\"$DB_SECRET_ARN\"" >> /tmp/lab112-env.sh

API_SECRET_ARN=$(aws secretsmanager create-secret \
  --name "lab112/prod/api-key" \
  --secret-string '{"api_key":"lab112-api-key-abc123xyz"}' \
  --kms-key-id $KEY_ID \
  --region $REGION \
  --query 'ARN' --output text)
echo "✅ API secret: $API_SECRET_ARN"
echo "export API_SECRET_ARN=\"$API_SECRET_ARN\"" >> /tmp/lab112-env.sh

# Step 3: Create SSM SecureString for config values
echo ""
echo "[3] Creating SSM SecureString parameters (hierarchical)..."
aws ssm put-parameter \
  --name "/lab112/prod/db/host" \
  --value "prod-db.cluster.ap-south-1.rds.amazonaws.com" \
  --type String \
  --region $REGION
echo "✅ SSM String: /lab112/prod/db/host"

aws ssm put-parameter \
  --name "/lab112/prod/db/port" \
  --value "5432" \
  --type String \
  --region $REGION
echo "✅ SSM String: /lab112/prod/db/port"

aws ssm put-parameter \
  --name "/lab112/prod/cache/redis-password" \
  --value "RedisS3cur3P@ss!" \
  --type SecureString \
  --key-id $KEY_ID \
  --region $REGION
echo "✅ SSM SecureString: /lab112/prod/cache/redis-password"

echo ""
echo "================================================"
echo "Part 2 Complete!"
echo "================================================"
```

---

## Part 3 — Retrieve + Audit Secrets Access

```bash
#!/bin/bash
# Lab 112 - Part 3: Retrieve Secrets + Audit Trail
source /tmp/lab112-env.sh

echo "================================================"
echo "  Part 3: Secret Retrieval + Audit"
echo "================================================"

# Step 1: Retrieve SM secret (simulate what app code does)
echo ""
echo "[1] Retrieving Secrets Manager secret (simulating app code)..."
SECRET_VALUE=$(aws secretsmanager get-secret-value \
  --secret-id "lab112/prod/db-password" \
  --region $REGION \
  --query 'SecretString' \
  --output text)

USERNAME=$(echo $SECRET_VALUE | python3 -c "import sys,json; print(json.load(sys.stdin)['username'])")
echo "✅ Retrieved secret successfully"
echo "   Username: $USERNAME"
echo "   Password: [REDACTED - never log passwords]"

# Step 2: Retrieve SSM SecureString
echo ""
echo "[2] Retrieving SSM SecureString (with decryption)..."
REDIS_PASS=$(aws ssm get-parameter \
  --name "/lab112/prod/cache/redis-password" \
  --with-decryption \
  --region $REGION \
  --query 'Parameter.Value' \
  --output text)
echo "✅ SSM SecureString retrieved (requires ssm:GetParameter + kms:Decrypt)"
echo "   Value starts with: ${REDIS_PASS:0:8}..."

# Step 3: Retrieve SSM by path (get all /lab112/prod/db/* at once)
echo ""
echo "[3] Retrieving SSM parameters by path..."
aws ssm get-parameters-by-path \
  --path "/lab112/prod/db" \
  --region $REGION \
  --query 'Parameters[*].{Name:Name,Type:Type,Value:Value}' \
  --output table

# Step 4: Check SM secret versions
echo ""
echo "[4] Checking SM secret versioning..."
aws secretsmanager list-secret-version-ids \
  --secret-id "lab112/prod/db-password" \
  --region $REGION \
  --query 'Versions[*].{VersionId:VersionId,Stages:VersionStages,CreatedDate:CreatedDate}' \
  --output table
echo "   Current active = AWSCURRENT label"

# Step 5: Manual secret rotation simulation
echo ""
echo "[5] Simulating manual secret rotation..."
echo "    (In production, SM + Lambda handles this automatically)"
aws secretsmanager put-secret-value \
  --secret-id "lab112/prod/db-password" \
  --secret-string '{"username":"prodadmin","password":"N3wR0t4t3dP@ss!"}' \
  --region $REGION \
  --query '{VersionId:VersionId,VersionStages:VersionStages}' \
  --output table
echo "✅ Secret rotated manually"
echo "   New value = AWSCURRENT, old value = AWSPREVIOUS"

# Step 6: CloudTrail audit for GetSecretValue
echo ""
echo "[6] Checking CloudTrail for GetSecretValue events..."
echo "    (15 min delay expected)"
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --region $REGION \
  --max-results 5 \
  --query 'Events[*].{Time:EventTime,Event:EventName,User:Username}' \
  --output table 2>/dev/null || echo "⏳ CloudTrail events not yet available"

echo ""
echo "================================================"
echo "Part 3 Complete!"
echo "================================================"
```

---

## Part 4 — Cleanup

```bash
#!/bin/bash
# Lab 112 - Part 4: Cleanup
source /tmp/lab112-env.sh

echo "================================================"
echo "  Part 4: Cleanup All Lab 112 Resources"
echo "================================================"

echo ""
echo "[1] Deleting Secrets Manager secrets..."
for SECRET in "lab112/prod/db-password" "lab112/prod/api-key"; do
  aws secretsmanager delete-secret \
    --secret-id "$SECRET" \
    --force-delete-without-recovery \
    --region $REGION 2>/dev/null && echo "✅ Deleted: $SECRET"
done

echo ""
echo "[2] Deleting SSM parameters..."
for PARAM in "/lab112/prod/db/host" "/lab112/prod/db/port" "/lab112/prod/cache/redis-password"; do
  aws ssm delete-parameter \
    --name "$PARAM" \
    --region $REGION 2>/dev/null && echo "✅ Deleted: $PARAM"
done

echo ""
echo "[3] Scheduling KMS key deletion..."
aws kms schedule-key-deletion \
  --key-id $KEY_ID \
  --pending-window-in-days 7 \
  --region $REGION 2>/dev/null && echo "✅ KMS key scheduled for deletion"

echo ""
echo "[4] Cleanup temp files..."
rm -f /tmp/lab112-env.sh
echo "✅ Temp files cleaned"

echo ""
echo "================================================"
echo "Lab 112 Cleanup Complete!"
echo "================================================"
```

---

## ✅ Lab 112 Verification Checklist

```
Lab 112 — Secrets in Containers Checklist
│
├── Part 1: Pattern Review
│     ├── [ ] Understood insecure patterns (env var, Docker bake)
│     └── [ ] Understood SM ARN reference pattern
│
├── Part 2: Secret Creation
│     ├── [ ] KMS CMK created for encryption
│     ├── [ ] SM secrets created with CMK encryption
│     ├── [ ] SSM String params created (non-sensitive config)
│     └── [ ] SSM SecureString created (sensitive values)
│
├── Part 3: Retrieval + Audit
│     ├── [ ] SM secret retrieved, password not logged
│     ├── [ ] SSM SecureString retrieved with decryption flag
│     ├── [ ] SSM path retrieval demonstrated
│     ├── [ ] SM versioning (AWSCURRENT/PREVIOUS) understood
│     ├── [ ] Manual rotation simulated
│     └── [ ] CloudTrail GetSecretValue captured
│
└── Part 4: Cleanup
      └── [ ] All resources deleted
```

---

## 🔑 Lab 112 Key Takeaways

| Concept | What You Practiced |
|---|---|
| SM vs SSM choice | SM = rotation needed; SSM = free, config values |
| ARN reference in ECS | Secret never in task definition plaintext |
| SM versioning | AWSCURRENT / AWSPREVIOUS labels |
| SecureString retrieval | Requires `--with-decryption` + kms:Decrypt |
| Path-based SSM retrieval | Fetch all params under /path/ at once |
| Manual rotation | New version = AWSCURRENT; old = AWSPREVIOUS |
| CloudTrail audit | Every GetSecretValue logged with caller |

---

# 📅 Day 43 — Section 3: Lab 113
## AWS Config — Rules, Compliance + Remediation

---

## 🎯 Lab Objective
In this lab you will:
- Enable AWS Config recorder in the region
- Create and evaluate managed Config rules
- Build a custom Lambda-based Config rule
- Configure auto-remediation with SSM Automation
- Query Config history via AWS CLI
- Review compliance summary
- Cleanup all resources

---

## Prerequisites Check

```bash
#!/bin/bash
# Lab 113 - Prerequisites Check
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region || echo "ap-south-1")

cat > /tmp/lab113-env.sh << EOF
export ACCOUNT_ID="$ACCOUNT_ID"
export REGION="$REGION"
export LAB="lab113"
EOF

echo "================================================"
echo "  Lab 113: AWS Config Prerequisites"
echo "================================================"
aws sts get-caller-identity --output table
echo "Region: $REGION"

# Check if Config is already enabled
echo ""
echo "[1] Checking Config recorder status..."
aws configservice describe-configuration-recorders \
  --region $REGION \
  --query 'ConfigurationRecorders[*].{Name:name,AllSupported:recordingGroup.allSupported}' \
  --output table 2>/dev/null || echo "Config not yet configured"

echo "✅ Environment saved to /tmp/lab113-env.sh"
echo "================================================"
```

---

## Part 1 — Enable Config Recorder + Delivery Channel

```bash
#!/bin/bash
# Lab 113 - Part 1: Enable Config
source /tmp/lab113-env.sh

echo "================================================"
echo "  Part 1: Enable AWS Config Recorder"
echo "================================================"

# Step 1: Create S3 bucket for Config delivery
echo ""
echo "[1] Creating S3 bucket for Config delivery..."
CONFIG_BUCKET="lab113-config-${ACCOUNT_ID}-${REGION}"
aws s3api create-bucket \
  --bucket $CONFIG_BUCKET \
  --region $REGION \
  --create-bucket-configuration LocationConstraint=$REGION 2>/dev/null || \
  aws s3api create-bucket \
    --bucket $CONFIG_BUCKET \
    --region $REGION 2>/dev/null
echo "✅ Config S3 bucket: $CONFIG_BUCKET"
echo "export CONFIG_BUCKET=\"$CONFIG_BUCKET\"" >> /tmp/lab113-env.sh

# Enable bucket versioning
aws s3api put-bucket-versioning \
  --bucket $CONFIG_BUCKET \
  --versioning-configuration Status=Enabled \
  --region $REGION
echo "✅ Bucket versioning enabled"

# Apply bucket policy for Config delivery
cat > /tmp/lab113-bucket-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSConfigBucketPermissionsCheck",
      "Effect": "Allow",
      "Principal": {"Service": "config.amazonaws.com"},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::$CONFIG_BUCKET"
    },
    {
      "Sid": "AWSConfigBucketDelivery",
      "Effect": "Allow",
      "Principal": {"Service": "config.amazonaws.com"},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::$CONFIG_BUCKET/AWSLogs/$ACCOUNT_ID/Config/*",
      "Condition": {
        "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
      }
    }
  ]
}
EOF

aws s3api put-bucket-policy \
  --bucket $CONFIG_BUCKET \
  --policy file:///tmp/lab113-bucket-policy.json
echo "✅ Bucket policy applied"

# Step 2: Create Config IAM role
echo ""
echo "[2] Creating Config service role..."
cat > /tmp/lab113-config-trust.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "config.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF

CONFIG_ROLE_ARN=$(aws iam create-role \
  --role-name "lab113-config-role" \
  --assume-role-policy-document file:///tmp/lab113-config-trust.json \
  --query 'Role.Arn' --output text)

aws iam attach-role-policy \
  --role-name "lab113-config-role" \
  --policy-arn "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"

echo "✅ Config role: $CONFIG_ROLE_ARN"
echo "export CONFIG_ROLE_ARN=\"$CONFIG_ROLE_ARN\"" >> /tmp/lab113-env.sh
sleep 10

# Step 3: Create Config recorder
echo ""
echo "[3] Creating Config recorder..."
aws configservice put-configuration-recorder \
  --configuration-recorder \
    "name=lab113-recorder,roleARN=$CONFIG_ROLE_ARN,recordingGroup={allSupported=true,includeGlobalResourceTypes=true}" \
  --region $REGION
echo "✅ Config recorder created"

# Step 4: Create delivery channel
echo ""
echo "[4] Creating Config delivery channel..."
aws configservice put-delivery-channel \
  --delivery-channel \
    "name=lab113-channel,s3BucketName=$CONFIG_BUCKET" \
  --region $REGION
echo "✅ Delivery channel created"

# Step 5: Start recording
echo ""
echo "[5] Starting Config recorder..."
aws configservice start-configuration-recorder \
  --configuration-recorder-name "lab113-recorder" \
  --region $REGION
echo "✅ Config recording STARTED"

echo ""
echo "================================================"
echo "Part 1 Complete!"
echo "================================================"
```

---

## Part 2 — Deploy Managed Config Rules

```bash
#!/bin/bash
# Lab 113 - Part 2: Managed Config Rules
source /tmp/lab113-env.sh

echo "================================================"
echo "  Part 2: Deploy Managed Config Rules"
echo "================================================"

# Array of security-relevant managed rules
declare -A RULES=(
  ["lab113-cloudtrail-enabled"]="cloudtrail-enabled"
  ["lab113-root-mfa-enabled"]="root-account-mfa-enabled"
  ["lab113-s3-public-read-prohibited"]="s3-bucket-public-read-prohibited"
  ["lab113-iam-root-no-access-keys"]="iam-root-access-key-check"
  ["lab113-ebs-encrypted"]="encrypted-volumes"
)

for RULE_NAME in "${!RULES[@]}"; do
  SOURCE="${RULES[$RULE_NAME]}"
  echo ""
  echo "Creating rule: $RULE_NAME (${SOURCE})..."
  aws configservice put-config-rule \
    --config-rule "{
      \"ConfigRuleName\": \"$RULE_NAME\",
      \"Source\": {
        \"Owner\": \"AWS\",
        \"SourceIdentifier\": \"$SOURCE\"
      }
    }" \
    --region $REGION 2>/dev/null && \
    echo "  ✅ Created: $RULE_NAME" || \
    echo "  ⚠️  Rule may already exist or require IAM"
done

echo ""
echo "[Waiting 60s for initial evaluation...]"
sleep 60

# Get compliance summary
echo ""
echo "[Compliance Summary]"
aws configservice describe-compliance-by-config-rule \
  --config-rule-names \
    "lab113-cloudtrail-enabled" \
    "lab113-root-mfa-enabled" \
    "lab113-s3-public-read-prohibited" \
    "lab113-iam-root-no-access-keys" \
    "lab113-ebs-encrypted" \
  --region $REGION \
  --query 'ComplianceByConfigRules[*].{Rule:ConfigRuleName,Compliance:Compliance.ComplianceType}' \
  --output table 2>/dev/null

echo ""
echo "================================================"
echo "Part 2 Complete!"
echo "================================================"
```

---

## Part 3 — Custom Lambda Config Rule

```bash
#!/bin/bash
# Lab 113 - Part 3: Custom Config Rule (Lambda)
source /tmp/lab113-env.sh

echo "================================================"
echo "  Part 3: Custom Lambda Config Rule"
echo "================================================"

# Step 1: Create Lambda function for custom rule
echo ""
echo "[1] Creating custom Config rule Lambda..."
mkdir -p /tmp/lab113-lambda

cat > /tmp/lab113-lambda/config_rule.py << 'PYEOF'
import boto3
import json

def lambda_handler(event, context):
    """
    Custom Config rule: Check S3 buckets have logging enabled.
    Returns COMPLIANT if logging enabled, NON_COMPLIANT otherwise.
    """
    invoking_event = json.loads(event['invokingEvent'])
    configuration_item = invoking_event.get('configurationItem', {})

    # Only evaluate S3 bucket resources
    if configuration_item.get('resourceType') != 'AWS::S3::Bucket':
        return put_evaluation(
            event,
            configuration_item.get('resourceId', 'unknown'),
            'NOT_APPLICABLE',
            'Resource is not an S3 bucket'
        )

    bucket_name = configuration_item.get('resourceId')
    config_capture = configuration_item.get('configuration', {})
    logging_enabled = config_capture.get('loggingEnabled', False)

    if logging_enabled:
        compliance = 'COMPLIANT'
        annotation = 'S3 bucket has server access logging enabled'
    else:
        compliance = 'NON_COMPLIANT'
        annotation = 'S3 bucket does NOT have server access logging enabled'

    return put_evaluation(event, bucket_name, compliance, annotation)

def put_evaluation(event, resource_id, compliance, annotation):
    config_client = boto3.client('config')
    config_client.put_evaluations(
        Evaluations=[{
            'ComplianceResourceType': 'AWS::S3::Bucket',
            'ComplianceResourceId': resource_id,
            'ComplianceType': compliance,
            'Annotation': annotation,
            'OrderingTimestamp': __import__('datetime').datetime.utcnow()
        }],
        ResultToken=event['resultToken']
    )
    return {'compliance': compliance, 'resource': resource_id}
PYEOF

cd /tmp/lab113-lambda
zip -r config_rule.zip config_rule.py

# Step 2: Create Lambda execution role for Config
cat > /tmp/lab113-lambda-trust.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF

LAMBDA_ROLE_ARN=$(aws iam create-role \
  --role-name "lab113-config-rule-lambda-role" \
  --assume-role-policy-document file:///tmp/lab113-lambda-trust.json \
  --query 'Role.Arn' --output text)

aws iam attach-role-policy \
  --role-name "lab113-config-rule-lambda-role" \
  --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

cat > /tmp/lab113-lambda-config-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["config:PutEvaluations","s3:GetBucketLogging"],
    "Resource": "*"
  }]
}
EOF

aws iam put-role-policy \
  --role-name "lab113-config-rule-lambda-role" \
  --policy-name "ConfigEvalPolicy" \
  --policy-document file:///tmp/lab113-lambda-config-policy.json

echo "✅ Lambda role created"
echo "export LAMBDA_ROLE_ARN=\"$LAMBDA_ROLE_ARN\"" >> /tmp/lab113-env.sh
sleep 10

# Step 3: Deploy Lambda
RULE_LAMBDA_ARN=$(aws lambda create-function \
  --function-name "lab113-config-rule-s3-logging" \
  --runtime python3.12 \
  --role "$LAMBDA_ROLE_ARN" \
  --handler "config_rule.lambda_handler" \
  --zip-file "fileb:///tmp/lab113-lambda/config_rule.zip" \
  --timeout 30 \
  --region $REGION \
  --query 'FunctionArn' --output text)

echo "✅ Custom rule Lambda deployed: $RULE_LAMBDA_ARN"
echo "export RULE_LAMBDA_ARN=\"$RULE_LAMBDA_ARN\"" >> /tmp/lab113-env.sh

# Wait for Lambda to be active
aws lambda wait function-active \
  --function-name "lab113-config-rule-s3-logging" \
  --region $REGION

# Step 4: Grant Config permission to invoke Lambda
aws lambda add-permission \
  --function-name "lab113-config-rule-s3-logging" \
  --statement-id "ConfigInvoke" \
  --action "lambda:InvokeFunction" \
  --principal "config.amazonaws.com" \
  --source-account "$ACCOUNT_ID" \
  --region $REGION

# Step 5: Create custom Config rule
aws configservice put-config-rule \
  --config-rule "{
    \"ConfigRuleName\": \"lab113-s3-logging-check\",
    \"Description\": \"Custom rule: Check S3 bucket logging\",
    \"Source\": {
      \"Owner\": \"CUSTOM_LAMBDA\",
      \"SourceIdentifier\": \"$RULE_LAMBDA_ARN\",
      \"SourceDetails\": [{
        \"EventSource\": \"aws.config\",
        \"MessageType\": \"ConfigurationItemChangeNotification\"
      }]
    },
    \"Scope\": {
      \"ComplianceResourceTypes\": [\"AWS::S3::Bucket\"]
    }
  }" \
  --region $REGION

echo "✅ Custom Config rule created: lab113-s3-logging-check"

echo ""
echo "================================================"
echo "Part 3 Complete!"
echo "================================================"
```

---

## Part 4 — Cleanup

```bash
#!/bin/bash
# Lab 113 - Part 4: Cleanup
source /tmp/lab113-env.sh

echo "================================================"
echo "  Part 4: Cleanup All Lab 113 Resources"
echo "================================================"

echo ""
echo "[1] Stopping Config recorder..."
aws configservice stop-configuration-recorder \
  --configuration-recorder-name "lab113-recorder" \
  --region $REGION 2>/dev/null && echo "✅ Recorder stopped"

echo ""
echo "[2] Deleting Config rules..."
for RULE in \
  "lab113-cloudtrail-enabled" \
  "lab113-root-mfa-enabled" \
  "lab113-s3-public-read-prohibited" \
  "lab113-iam-root-no-access-keys" \
  "lab113-ebs-encrypted" \
  "lab113-s3-logging-check"; do
  aws configservice delete-config-rule \
    --config-rule-name "$RULE" \
    --region $REGION 2>/dev/null && echo "✅ Deleted rule: $RULE"
done

echo ""
echo "[3] Deleting delivery channel..."
aws configservice delete-delivery-channel \
  --delivery-channel-name "lab113-channel" \
  --region $REGION 2>/dev/null && echo "✅ Delivery channel deleted"

echo ""
echo "[4] Deleting Config recorder..."
aws configservice delete-configuration-recorder \
  --configuration-recorder-name "lab113-recorder" \
  --region $REGION 2>/dev/null && echo "✅ Recorder deleted"

echo ""
echo "[5] Deleting Lambda function..."
aws lambda delete-function \
  --function-name "lab113-config-rule-s3-logging" \
  --region $REGION 2>/dev/null && echo "✅ Lambda deleted"

echo ""
echo "[6] Deleting IAM roles..."
aws iam detach-role-policy \
  --role-name "lab113-config-role" \
  --policy-arn "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole" 2>/dev/null
aws iam delete-role --role-name "lab113-config-role" 2>/dev/null && echo "✅ Config role deleted"

aws iam detach-role-policy \
  --role-name "lab113-config-rule-lambda-role" \
  --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole" 2>/dev/null
aws iam delete-role-policy \
  --role-name "lab113-config-rule-lambda-role" \
  --policy-name "ConfigEvalPolicy" 2>/dev/null
aws iam delete-role --role-name "lab113-config-rule-lambda-role" 2>/dev/null && echo "✅ Lambda role deleted"

echo ""
echo "[7] Deleting Config S3 bucket..."
aws s3 rm s3://$CONFIG_BUCKET --recursive 2>/dev/null
aws s3 rb s3://$CONFIG_BUCKET --force 2>/dev/null && echo "✅ Config bucket deleted"

echo ""
echo "[8] Cleanup temp files..."
rm -f /tmp/lab113-env.sh /tmp/lab113-*.json
rm -rf /tmp/lab113-lambda/
echo "✅ Temp files cleaned"

echo ""
echo "================================================"
echo "Lab 113 Cleanup Complete!"
echo "================================================"
```

---

## ✅ Lab 113 Verification Checklist

```
Lab 113 — AWS Config Checklist
│
├── Part 1: Config Setup
│     ├── [ ] S3 bucket with versioning for Config delivery
│     ├── [ ] Bucket policy for Config service principal
│     ├── [ ] Config IAM role with AWS_ConfigRole policy
│     ├── [ ] Configuration recorder created (allSupported)
│     ├── [ ] Delivery channel created
│     └── [ ] Recording STARTED
│
├── Part 2: Managed Rules
│     ├── [ ] cloudtrail-enabled rule created
│     ├── [ ] root-account-mfa-enabled rule created
│     ├── [ ] s3-bucket-public-read-prohibited rule created
│     ├── [ ] iam-root-access-key-check rule created
│     ├── [ ] encrypted-volumes rule created
│     └── [ ] Compliance summary reviewed
│
├── Part 3: Custom Rule
│     ├── [ ] Custom Lambda evaluator deployed
│     ├── [ ] Lambda granted config.amazonaws.com permission
│     ├── [ ] Custom rule: lab113-s3-logging-check created
│     └── [ ] Evaluates S3 bucket logging status
│
└── Part 4: Cleanup
      └── [ ] All resources deleted (recorder, rules, Lambda, S3, IAM)
```

---

## 🔑 Lab 113 Key Takeaways

| Concept | What You Practiced |
|---|---|
| Config recorder | Must be manually started — not auto-enabled |
| Delivery channel | S3 bucket + bucket policy for Config service |
| Managed rules | ~300+ pre-built AWS rules |
| Custom rules | Lambda evaluator with PutEvaluations API |
| Compliance evaluation | COMPLIANT / NON_COMPLIANT / NOT_APPLICABLE |
| Config = detective | Detects, does NOT prevent non-compliance |
| CloudTrail + Config | Config = WHAT changed; CT = WHO changed |

---

# 📅 Day 44 — Section 3: Lab 114
## AWS Organizations — SCPs + Multi-Account

---

## 🎯 Lab Objective
In this lab you will:
- Explore existing Organization structure
- Create and attach an SCP to deny dangerous actions
- Verify SCP inheritance and evaluation logic
- Create region-restriction SCP
- Test SCP vs IAM interaction
- Review Organizations policies CLI
- Cleanup all resources

---

## Prerequisites Check

```bash
#!/bin/bash
# Lab 114 - Prerequisites Check
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region || echo "ap-south-1")

cat > /tmp/lab114-env.sh << EOF
export ACCOUNT_ID="$ACCOUNT_ID"
export REGION="$REGION"
export LAB="lab114"
EOF

echo "================================================"
echo "  Lab 114: AWS Organizations Prerequisites"
echo "================================================"
aws sts get-caller-identity --output table

# Check Organizations membership
echo ""
echo "[1] Checking Organizations status..."
aws organizations describe-organization \
  --query 'Organization.{Id:Id,MasterAccountId:MasterAccountId,FeatureSet:FeatureSet}' \
  --output table 2>/dev/null || \
  echo "⚠️  Not in an Organization or insufficient permissions"

# Check if this is management account
MASTER_ACCOUNT=$(aws organizations describe-organization \
  --query 'Organization.MasterAccountId' \
  --output text 2>/dev/null)

if [ "$MASTER_ACCOUNT" == "$ACCOUNT_ID" ]; then
  echo "✅ This IS the management account — full SCP access"
  echo "export IS_MANAGEMENT=true" >> /tmp/lab114-env.sh
else
  echo "ℹ️  This is a MEMBER account — SCP creation requires management account"
  echo "export IS_MANAGEMENT=false" >> /tmp/lab114-env.sh
fi

echo ""
echo "✅ Environment saved to /tmp/lab114-env.sh"
echo "================================================"
```

---

## Part 1 — Explore Organization Structure

```bash
#!/bin/bash
# Lab 114 - Part 1: Explore Organization
source /tmp/lab114-env.sh

echo "================================================"
echo "  Part 1: Explore Organization Structure"
echo "================================================"

# Step 1: Organization details
echo ""
echo "[1] Organization details..."
aws organizations describe-organization \
  --output json 2>/dev/null | python3 -m json.tool | head -30

# Step 2: List OUs
echo ""
echo "[2] Listing Organizational Units (OUs)..."
ROOT_ID=$(aws organizations list-roots \
  --query 'Roots[0].Id' \
  --output text 2>/dev/null)
echo "Root ID: $ROOT_ID"
echo "export ROOT_ID=\"$ROOT_ID\"" >> /tmp/lab114-env.sh

aws organizations list-organizational-units-for-parent \
  --parent-id $ROOT_ID \
  --query 'OrganizationalUnits[*].{Id:Id,Name:Name}' \
  --output table 2>/dev/null || echo "No OUs found under root"

# Step 3: List accounts
echo ""
echo "[3] Listing member accounts..."
aws organizations list-accounts \
  --query 'Accounts[*].{Id:Id,Name:Name,Status:Status,JoinedMethod:JoinedMethod}' \
  --output table 2>/dev/null | head -20

# Step 4: List existing SCPs
echo ""
echo "[4] Existing Service Control Policies..."
aws organizations list-policies \
  --filter SERVICE_CONTROL_POLICY \
  --query 'Policies[*].{Id:Id,Name:Name,Description:Description}' \
  --output table 2>/dev/null

# Step 5: View FullAWSAccess SCP (the default)
echo ""
echo "[5] Viewing FullAWSAccess SCP (default)..."
FULL_ACCESS_ID=$(aws organizations list-policies \
  --filter SERVICE_CONTROL_POLICY \
  --query 'Policies[?Name==`FullAWSAccess`].Id' \
  --output text 2>/dev/null)

if [ ! -z "$FULL_ACCESS_ID" ]; then
  aws organizations describe-policy \
    --policy-id $FULL_ACCESS_ID \
    --query 'Policy.Content' \
    --output text 2>/dev/null | python3 -m json.tool
fi

echo ""
echo "================================================"
echo "Part 1 Complete!"
echo "================================================"
```

---

## Part 2 — Create Security Protection SCPs

```bash
#!/bin/bash
# Lab 114 - Part 2: Create SCPs
source /tmp/lab114-env.sh

echo "================================================"
echo "  Part 2: Create Security Protection SCPs"
echo "================================================"

if [ "$IS_MANAGEMENT" != "true" ]; then
  echo "⚠️  SCP creation requires management account."
  echo "    Showing SCP templates for study purposes:"
fi

# SCP 1: Protect security services from deletion
echo ""
echo "[1] SCP: Protect Security Services..."
cat > /tmp/lab114-scp-protect.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenySecurityServicesDeletion",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:DeleteTrail",
        "cloudtrail:StopLogging",
        "cloudtrail:UpdateTrail",
        "config:DeleteConfigRule",
        "config:DeleteConfigurationRecorder",
        "config:DeleteDeliveryChannel",
        "config:StopConfigurationRecorder",
        "guardduty:DeleteDetector",
        "guardduty:DisassociateFromMasterAccount",
        "securityhub:DisableSecurityHub",
        "securityhub:DeleteHub",
        "macie2:DisableMacie"
      ],
      "Resource": "*"
    }
  ]
}
EOF
cat /tmp/lab114-scp-protect.json | python3 -m json.tool

# Create SCP if management account
if [ "$IS_MANAGEMENT" == "true" ]; then
  SCP1_ID=$(aws organizations create-policy \
    --content file:///tmp/lab114-scp-protect.json \
    --description "Lab114 - Deny deletion of security services" \
    --name "lab114-protect-security-services" \
    --type SERVICE_CONTROL_POLICY \
    --query 'Policy.PolicySummary.Id' \
    --output text)
  echo "✅ SCP created: $SCP1_ID"
  echo "export SCP1_ID=\"$SCP1_ID\"" >> /tmp/lab114-env.sh
fi

# SCP 2: Region restriction
echo ""
echo "[2] SCP: Region Restriction (ap-south-1 + us-east-1 only)..."
cat > /tmp/lab114-scp-region.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyNonApprovedRegions",
      "Effect": "Deny",
      "NotAction": [
        "iam:*",
        "sts:*",
        "route53:*",
        "cloudfront:*",
        "waf:*",
        "support:*",
        "trustedadvisor:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "ap-south-1",
            "us-east-1"
          ]
        }
      }
    }
  ]
}
EOF
cat /tmp/lab114-scp-region.json | python3 -m json.tool

if [ "$IS_MANAGEMENT" == "true" ]; then
  SCP2_ID=$(aws organizations create-policy \
    --content file:///tmp/lab114-scp-region.json \
    --description "Lab114 - Restrict to ap-south-1 and us-east-1" \
    --name "lab114-region-restriction" \
    --type SERVICE_CONTROL_POLICY \
    --query 'Policy.PolicySummary.Id' \
    --output text)
  echo "✅ SCP created: $SCP2_ID"
  echo "export SCP2_ID=\"$SCP2_ID\"" >> /tmp/lab114-env.sh
fi

# SCP 3: Prevent root access key creation
echo ""
echo "[3] SCP: Deny Root Access Key Creation..."
cat > /tmp/lab114-scp-root.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyRootAccessKeys",
      "Effect": "Deny",
      "Action": "iam:CreateAccessKey",
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:root"
        }
      }
    },
    {
      "Sid": "PreventLeavingOrg",
      "Effect": "Deny",
      "Action": "organizations:LeaveOrganization",
      "Resource": "*"
    }
  ]
}
EOF
cat /tmp/lab114-scp-root.json | python3 -m json.tool

if [ "$IS_MANAGEMENT" == "true" ]; then
  SCP3_ID=$(aws organizations create-policy \
    --content file:///tmp/lab114-scp-root.json \
    --description "Lab114 - Deny root access keys + org leave" \
    --name "lab114-root-protection" \
    --type SERVICE_CONTROL_POLICY \
    --query 'Policy.PolicySummary.Id' \
    --output text)
  echo "✅ SCP created: $SCP3_ID"
  echo "export SCP3_ID=\"$SCP3_ID\"" >> /tmp/lab114-env.sh
fi

echo ""
echo "================================================"
echo "Part 2 Complete!"
echo "================================================"
```

---

## Part 3 — Attach SCPs + Verify Evaluation

```bash
#!/bin/bash
# Lab 114 - Part 3: Attach SCPs + Verify Logic
source /tmp/lab114-env.sh

echo "================================================"
echo "  Part 3: SCP Attachment + Evaluation Demo"
echo "================================================"

# Step 1: List accounts to find a sandbox to attach to
echo ""
echo "[1] Available accounts for SCP attachment..."
aws organizations list-accounts \
  --query 'Accounts[?Status==`ACTIVE`].{Id:Id,Name:Name}' \
  --output table 2>/dev/null

# Step 2: If management account, attach SCP to a test OU
if [ "$IS_MANAGEMENT" == "true" ] && [ ! -z "$SCP1_ID" ]; then
  echo ""
  echo "[2] Attaching protect-security-services SCP to root..."
  echo "    (In production: attach to specific OUs, not root)"
  aws organizations attach-policy \
    --policy-id $SCP1_ID \
    --target-id $ROOT_ID 2>/dev/null && \
    echo "✅ SCP attached to root" || \
    echo "⚠️  Attachment requires appropriate permissions"
fi

# Step 3: Show SCP evaluation logic (always educational)
echo ""
echo "[3] SCP + IAM Evaluation Logic Demo..."
cat << 'EOF'
┌─────────────────────────────────────────────────────┐
│          SCP + IAM EVALUATION LOGIC                  │
│                                                      │
│  Request: ec2:TerminateInstances                    │
│                                                      │
│  Check 1: Is there an explicit DENY in any SCP?     │
│     YES → DENY (regardless of IAM)                  │
│     NO  → Continue                                  │
│                                                      │
│  Check 2: Is there an ALLOW in the SCP?             │
│     NO  → DENY (implicit deny)                      │
│     YES → Continue                                  │
│                                                      │
│  Check 3: Is there an ALLOW in IAM policies?        │
│     NO  → DENY                                      │
│     YES → ALLOW                                     │
│                                                      │
│  Result: BOTH SCP and IAM must ALLOW                │
└─────────────────────────────────────────────────────┘

Critical Exceptions (SCPs DO NOT apply to):
  - Management account (always exempt)
  - Service-linked roles (AWS-managed)
EOF

# Step 4: List SCPs attached to root
echo ""
echo "[4] SCPs currently attached to root..."
aws organizations list-policies-for-target \
  --target-id $ROOT_ID \
  --filter SERVICE_CONTROL_POLICY \
  --query 'Policies[*].{Id:Id,Name:Name}' \
  --output table 2>/dev/null

echo ""
echo "================================================"
echo "Part 3 Complete!"
echo "================================================"
```

---

## Part 4 — Cleanup

```bash
#!/bin/bash
# Lab 114 - Part 4: Cleanup
source /tmp/lab114-env.sh

echo "================================================"
echo "  Part 4: Cleanup Lab 114 SCPs"
echo "================================================"

if [ "$IS_MANAGEMENT" != "true" ]; then
  echo "ℹ️  No SCPs created (member account) — nothing to clean up"
  rm -f /tmp/lab114-env.sh /tmp/lab114-scp-*.json
  echo "✅ Temp files cleaned"
  exit 0
fi

# Detach SCPs before deletion
for SCP_ID_VAR in SCP1_ID SCP2_ID SCP3_ID; do
  SCP_ID="${!SCP_ID_VAR}"
  if [ ! -z "$SCP_ID" ]; then
    echo ""
    echo "Detaching SCP: $SCP_ID..."
    aws organizations detach-policy \
      --policy-id $SCP_ID \
      --target-id $ROOT_ID 2>/dev/null && echo "✅ Detached"

    echo "Deleting SCP: $SCP_ID..."
    aws organizations delete-policy \
      --policy-id $SCP_ID 2>/dev/null && echo "✅ Deleted: $SCP_ID"
  fi
done

echo ""
echo "Cleaning up temp files..."
rm -f /tmp/lab114-env.sh /tmp/lab114-scp-*.json
echo "✅ Temp files cleaned"

echo ""
echo "================================================"
echo "Lab 114 Cleanup Complete!"
echo "================================================"
```

---

## ✅ Lab 114 Verification Checklist

```
Lab 114 — AWS Organizations SCPs Checklist
│
├── Part 1: Organization Exploration
│     ├── [ ] Organization structure reviewed
│     ├── [ ] Root ID identified
│     ├── [ ] OUs and accounts listed
│     ├── [ ] Existing SCPs reviewed
│     └── [ ] FullAWSAccess default SCP reviewed
│
├── Part 2: SCP Creation
│     ├── [ ] SCP 1: Protect security services (GD/CT/Config)
│     ├── [ ] SCP 2: Region restriction (ap-south-1/us-east-1)
│     └── [ ] SCP 3: Root access key + LeaveOrganization deny
│
├── Part 3: Attachment + Evaluation
│     ├── [ ] SCP attached (management account only)
│     ├── [ ] SCP + IAM evaluation logic understood
│     └── [ ] Management account exemption understood
│
└── Part 4: Cleanup
      └── [ ] All SCPs detached and deleted
```

---

## 🔑 Lab 114 Key Takeaways

| Concept | What You Practiced |
|---|---|
| SCP syntax | Deny + Action + Resource + optional Condition |
| Region restriction | aws:RequestedRegion + global service exemptions |
| Security protection | Deny deletion of CT/Config/GD |
| Root protection | Deny root access key creation + LeaveOrg |
| SCP evaluation | SCP ∩ IAM — both must Allow |
| Management exempt | SCPs never apply to management account |
| SCP attachment | Root → all accounts; OU → member accounts |

---

# 📅 Day 45 — Section 3: Lab 115
## AWS Control Tower — Guardrails + Account Factory

---

## 🎯 Lab Objective
In this lab you will:
- Explore an existing Control Tower landing zone
- Review mandatory, recommended, and elective guardrails
- Understand Account Factory configuration
- Review Log Archive and Audit account structure
- Enable an elective guardrail on an OU
- Verify guardrail implementation (SCP or Config rule)
- Cleanup (disable guardrail if enabled)

---

## Prerequisites Check

```bash
#!/bin/bash
# Lab 115 - Prerequisites Check
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region || echo "ap-south-1")

cat > /tmp/lab115-env.sh << EOF
export ACCOUNT_ID="$ACCOUNT_ID"
export REGION="$REGION"
export LAB="lab115"
EOF

echo "================================================"
echo "  Lab 115: Control Tower Prerequisites"
echo "================================================"
aws sts get-caller-identity --output table

echo ""
echo "[1] Checking Control Tower landing zone..."
aws controltower list-landing-zones \
  --region $REGION \
  --query 'landingZones[*].{Arn:arn,Status:status}' \
  --output table 2>/dev/null || \
  echo "ℹ️  Control Tower not set up in this account/region"

echo ""
echo "✅ Environment saved to /tmp/lab115-env.sh"
echo "================================================"
```

---

## Part 1 — Explore Landing Zone + Guardrails

```bash
#!/bin/bash
# Lab 115 - Part 1: Explore Control Tower
source /tmp/lab115-env.sh

echo "================================================"
echo "  Part 1: Explore Control Tower Structure"
echo "================================================"

# Step 1: List landing zones
echo ""
echo "[1] Landing zone details..."
LZ_ARN=$(aws controltower list-landing-zones \
  --region $REGION \
  --query 'landingZones[0].arn' \
  --output text 2>/dev/null)

if [ "$LZ_ARN" != "None" ] && [ ! -z "$LZ_ARN" ]; then
  aws controltower get-landing-zone \
    --landing-zone-identifier "$LZ_ARN" \
    --region $REGION \
    --query 'landingZone.{Version:version,Status:status,DriftStatus:driftStatus}' \
    --output table
  echo "export LZ_ARN=\"$LZ_ARN\"" >> /tmp/lab115-env.sh
else
  echo "ℹ️  Control Tower landing zone not found"
  echo "    (This lab is exploratory — requires CT to be set up)"
fi

# Step 2: List controls (guardrails) - all categories
echo ""
echo "[2] Listing Control Tower controls by category..."
echo ""
echo "--- MANDATORY controls (sample) ---"
aws controltower list-controls \
  --region $REGION \
  --query 'controls[?behavior==`PREVENTIVE` && implementationDetails.type==`SERVICE_CONTROL_POLICY`].{Name:name,Behavior:behavior,Status:controlStatus}' \
  --output table 2>/dev/null | head -15

echo ""
echo "--- DETECTIVE controls (sample) ---"
aws controltower list-controls \
  --region $REGION \
  --query 'controls[?implementationDetails.type==`AWS_CONFIG_RULE`].{Name:name,Behavior:behavior}' \
  --output table 2>/dev/null | head -10

# Step 3: Show Organization structure as Control Tower sees it
echo ""
echo "[3] Organization OUs (Control Tower view)..."
ROOT_ID=$(aws organizations list-roots \
  --query 'Roots[0].Id' \
  --output text 2>/dev/null)

aws organizations list-organizational-units-for-parent \
  --parent-id $ROOT_ID \
  --query 'OrganizationalUnits[*].{Id:Id,Name:Name}' \
  --output table 2>/dev/null

echo ""
echo "================================================"
echo "Part 1 Complete!"
echo "================================================"
```

---

## Part 2 — Guardrail Analysis + Account Factory Review

```bash
#!/bin/bash
# Lab 115 - Part 2: Guardrails + Account Factory
source /tmp/lab115-env.sh

echo "================================================"
echo "  Part 2: Guardrail Analysis + Account Factory"
echo "================================================"

# Step 1: Explain guardrail types (always educational)
echo ""
echo "[1] Guardrail Type Summary..."
cat << 'EOF'
┌──────────────────────────────────────────────────────────┐
│              CONTROL TOWER GUARDRAIL TYPES               │
├──────────────┬─────────────────┬────────────────────────┤
│ Behavior     │ Implementation  │ Effect                 │
├──────────────┼─────────────────┼────────────────────────┤
│ PREVENTIVE   │ SCP             │ Blocks non-compliant   │
│              │                 │ API calls              │
├──────────────┼─────────────────┼────────────────────────┤
│ DETECTIVE    │ Config Rule     │ Detects non-compliant  │
│              │                 │ configurations         │
├──────────────┼─────────────────┼────────────────────────┤
│ PROACTIVE    │ CFN Hook        │ Blocks non-compliant   │
│              │                 │ CloudFormation deploy  │
└──────────────┴─────────────────┴────────────────────────┘

Enforcement categories:
  MANDATORY          → Always ON, cannot disable
  STRONGLY_RECOMMENDED → ON by default, can disable
  ELECTIVE           → OFF by default, can enable
EOF

# Step 2: List currently enabled controls on Security OU
echo ""
echo "[2] Controls enabled on Security OU..."
SECURITY_OU_ID=$(aws organizations list-organizational-units-for-parent \
  --parent-id $(aws organizations list-roots --query 'Roots[0].Id' --output text 2>/dev/null) \
  --query 'OrganizationalUnits[?Name==`Security`].Id' \
  --output text 2>/dev/null)

if [ ! -z "$SECURITY_OU_ID" ]; then
  aws controltower list-enabled-controls \
    --target-identifier "$SECURITY_OU_ID" \
    --region $REGION \
    --query 'enabledControls[*].{Control:controlIdentifier,Status:statusSummary.status}' \
    --output table 2>/dev/null | head -20
fi

# Step 3: Account Factory service catalog product review
echo ""
echo "[3] Account Factory — Service Catalog products..."
aws servicecatalog search-products \
  --filters FullTextSearch="Account Factory" \
  --region $REGION \
  --query 'ProductViewSummaries[*].{Name:Name,Owner:Owner,Type:Type}' \
  --output table 2>/dev/null || \
  echo "ℹ️  Account Factory product not found or no Service Catalog access"

# Step 4: Explain Log Archive and Audit accounts
echo ""
echo "[4] Key Control Tower Account Purposes..."
cat << 'EOF'
Log Archive Account:
  Purpose: Centralized, immutable log storage
  Contains:
    - S3 bucket: all CloudTrail logs (all accounts)
    - S3 bucket: Config snapshots (all accounts)
    - Versioning + MFA delete + restricted access
  Access: Read-only for audit team; NO delete access

Audit Account:
  Purpose: Security team operational hub
  Contains:
    - SNS topics for compliance alert notifications
    - Read-only access to all member accounts
    - Delegated admin for security services
  Access: Security team only
EOF

echo ""
echo "================================================"
echo "Part 2 Complete!"
echo "================================================"
```

---

## Part 3 — Enable Elective Guardrail + Verify + Cleanup

```bash
#!/bin/bash
# Lab 115 - Part 3: Enable Guardrail + Cleanup
source /tmp/lab115-env.sh

echo "================================================"
echo "  Part 3: Enable Elective Guardrail"
echo "================================================"

# Only attempt if LZ exists
if [ -z "$LZ_ARN" ]; then
  echo "ℹ️  No Control Tower landing zone found — skipping guardrail enable"
  echo "    Review the guardrail enable/disable commands below for exam prep:"

  cat << 'EOF'
# Enable an elective guardrail on an OU
aws controltower enable-control \
  --control-identifier "arn:aws:controltower:REGION::control/CONTROL_NAME" \
  --target-identifier "arn:aws:organizations::ACCOUNT:ou/org-id/OU-ID" \
  --region REGION

# Disable a guardrail from an OU
aws controltower disable-control \
  --control-identifier "arn:aws:controltower:REGION::control/CONTROL_NAME" \
  --target-identifier "arn:aws:organizations::ACCOUNT:ou/org-id/OU-ID" \
  --region REGION

# List all enabled controls for an OU
aws controltower list-enabled-controls \
  --target-identifier "arn:aws:organizations::ACCOUNT:ou/org-id/OU-ID" \
  --region REGION
EOF
  echo ""
  echo "✅ Exam-relevant commands reviewed"
else
  # Get a Sandbox OU to test guardrail on
  SANDBOX_OU_ID=$(aws organizations list-organizational-units-for-parent \
    --parent-id $(aws organizations list-roots --query 'Roots[0].Id' --output text) \
    --query 'OrganizationalUnits[?contains(Name,`Sandbox`)].Id' \
    --output text 2>/dev/null | head -1)

  if [ ! -z "$SANDBOX_OU_ID" ]; then
    # Get an elective control to enable
    ELECTIVE_CONTROL=$(aws controltower list-controls \
      --region $REGION \
      --query 'controls[?behavior==`DETECTIVE` && controlStatus==`ENABLED`].name' \
      --output text 2>/dev/null | awk '{print $1}')

    echo "Target OU: $SANDBOX_OU_ID"
    echo "Elective control to enable: $ELECTIVE_CONTROL"
  fi
fi

echo ""
echo "================================================"
echo "Cleanup:"
echo "================================================"
rm -f /tmp/lab115-env.sh
echo "✅ Temp files cleaned"

echo ""
echo "================================================"
echo "Lab 115 Complete!"
echo "================================================"
```

---

## ✅ Lab 115 Verification Checklist

```
Lab 115 — Control Tower Checklist
│
├── Part 1: Landing Zone Exploration
│     ├── [ ] Landing zone status reviewed
│     ├── [ ] Preventive controls (SCP) identified
│     ├── [ ] Detective controls (Config) identified
│     └── [ ] OU structure reviewed
│
├── Part 2: Guardrail Analysis
│     ├── [ ] 3 guardrail types understood (Prev/Det/Proactive)
│     ├── [ ] 3 enforcement categories understood (M/SR/E)
│     ├── [ ] Log Archive account purpose clear
│     ├── [ ] Audit account purpose clear
│     └── [ ] Account Factory Service Catalog link understood
│
└── Part 3: Guardrail Management
      ├── [ ] Enable/disable guardrail commands reviewed
      ├── [ ] List enabled controls command practiced
      └── [ ] Drift concept understood (manual CT changes = drift)
```

---

## 🔑 Lab 115 Key Takeaways

| Concept | What You Practiced |
|---|---|
| Preventive = SCP | Blocks API calls before resource creation |
| Detective = Config | Detects non-compliant configurations |
| Proactive = CFN Hook | Blocks non-compliant CFN deployments |
| Mandatory | Cannot disable — landing zone baseline |
| Account Factory | Service Catalog product for account vending |
| Log Archive | Immutable centralized log storage |
| Audit Account | Security team read-only hub + SNS alerts |
| CT drift | Manual edits to CT-managed resources |

---

# 📅 Day 46 — Section 3: Lab 116
## Service Catalog — Portfolio + Launch Constraints

---

## 🎯 Lab Objective
In this lab you will:
- Create a Service Catalog portfolio
- Add a CloudFormation product (secure S3 bucket)
- Configure a launch constraint role
- Configure template constraints (restrict parameters)
- Share portfolio with an IAM group
- Provision the product as an end-user
- Verify launch constraint role in action
- Cleanup all resources

---

## Prerequisites Check

```bash
#!/bin/bash
# Lab 116 - Prerequisites Check
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region || echo "ap-south-1")

cat > /tmp/lab116-env.sh << EOF
export ACCOUNT_ID="$ACCOUNT_ID"
export REGION="$REGION"
export LAB="lab116"
EOF

echo "================================================"
echo "  Lab 116: Service Catalog Prerequisites"
echo "================================================"
aws sts get-caller-identity --output table
echo "Region: $REGION"

echo ""
echo "[1] Checking existing portfolios..."
aws servicecatalog list-portfolios \
  --region $REGION \
  --query 'PortfolioDetails[*].{Id:Id,DisplayName:DisplayName,ProviderName:ProviderName}' \
  --output table 2>/dev/null || echo "No portfolios found"

echo "✅ Environment saved to /tmp/lab116-env.sh"
echo "================================================"
```

---

## Part 1 — Create Portfolio + Product

```bash
#!/bin/bash
# Lab 116 - Part 1: Portfolio + Product
source /tmp/lab116-env.sh

echo "================================================"
echo "  Part 1: Create Portfolio + S3 Product"
echo "================================================"

# Step 1: Create portfolio
echo ""
echo "[1] Creating Service Catalog portfolio..."
PORTFOLIO_ID=$(aws servicecatalog create-portfolio \
  --display-name "Lab116 Secure Infrastructure" \
  --description "Lab116 pre-approved secure S3 products" \
  --provider-name "Security Team" \
  --region $REGION \
  --query 'PortfolioDetail.Id' \
  --output text)

echo "✅ Portfolio created: $PORTFOLIO_ID"
echo "export PORTFOLIO_ID=\"$PORTFOLIO_ID\"" >> /tmp/lab116-env.sh

# Step 2: Create CloudFormation template for the product
echo ""
echo "[2] Creating secure S3 bucket CloudFormation template..."
cat > /tmp/lab116-s3-product.yaml << 'EOF'
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Lab116 Service Catalog - Secure S3 Bucket Product'

Parameters:
  BucketPurpose:
    Type: String
    Description: Purpose tag for the bucket
    AllowedValues:
      - "DataLake"
      - "Backups"
      - "Artifacts"
    Default: "Artifacts"
  RetentionDays:
    Type: Number
    Description: S3 lifecycle retention in days
    MinValue: 30
    MaxValue: 365
    Default: 90

Resources:
  SecureBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      VersioningConfiguration:
        Status: Enabled
      LifecycleConfiguration:
        Rules:
          - Id: RetentionRule
            Status: Enabled
            ExpirationInDays: !Ref RetentionDays
      Tags:
        - Key: Purpose
          Value: !Ref BucketPurpose
        - Key: ManagedBy
          Value: ServiceCatalog
        - Key: Lab
          Value: lab116

Outputs:
  BucketName:
    Value: !Ref SecureBucket
    Description: Created S3 bucket name
  BucketArn:
    Value: !GetAtt SecureBucket.Arn
EOF

# Upload template to S3
TEMPLATE_BUCKET="lab116-templates-${ACCOUNT_ID}"
aws s3api create-bucket \
  --bucket $TEMPLATE_BUCKET \
  --region $REGION \
  --create-bucket-configuration LocationConstraint=$REGION 2>/dev/null || \
  aws s3api create-bucket \
    --bucket $TEMPLATE_BUCKET \
    --region $REGION 2>/dev/null

aws s3 cp /tmp/lab116-s3-product.yaml \
  s3://$TEMPLATE_BUCKET/lab116-s3-product.yaml \
  --region $REGION

echo "✅ Template uploaded to: s3://$TEMPLATE_BUCKET/lab116-s3-product.yaml"
echo "export TEMPLATE_BUCKET=\"$TEMPLATE_BUCKET\"" >> /tmp/lab116-env.sh

# Step 3: Create product
echo ""
echo "[3] Creating Service Catalog product..."
TEMPLATE_URL="https://${TEMPLATE_BUCKET}.s3.${REGION}.amazonaws.com/lab116-s3-product.yaml"

PRODUCT_ID=$(aws servicecatalog create-product \
  --name "Secure S3 Bucket" \
  --description "Pre-approved encrypted S3 bucket with versioning and lifecycle" \
  --owner "Security Team" \
  --product-type CLOUD_FORMATION_TEMPLATE \
  --provisioning-artifact-parameters \
    "Name=v1.0,Description=Initial version,Info={LoadTemplateFromURL=$TEMPLATE_URL},Type=CLOUD_FORMATION_TEMPLATE" \
  --region $REGION \
  --query 'ProductViewDetail.ProductViewSummary.ProductId' \
  --output text)

echo "✅ Product created: $PRODUCT_ID"
echo "export PRODUCT_ID=\"$PRODUCT_ID\"" >> /tmp/lab116-env.sh

# Step 4: Associate product with portfolio
echo ""
echo "[4] Associating product with portfolio..."
aws servicecatalog associate-product-with-portfolio \
  --product-id $PRODUCT_ID \
  --portfolio-id $PORTFOLIO_ID \
  --region $REGION
echo "✅ Product associated with portfolio"

echo ""
echo "================================================"
echo "Part 1 Complete!"
echo "================================================"
```

---

## Part 2 — Launch Constraint + Template Constraint

```bash
#!/bin/bash
# Lab 116 - Part 2: Constraints
source /tmp/lab116-env.sh

echo "================================================"
echo "  Part 2: Launch Constraint + Template Constraint"
echo "================================================"

# Step 1: Create launch constraint role
echo ""
echo "[1] Creating launch constraint IAM role..."
cat > /tmp/lab116-sc-trust.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Service": "servicecatalog.amazonaws.com"},
      "Action": "sts:AssumeRole"
    },
    {
      "Effect": "Allow",
      "Principal": {"Service": "cloudformation.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

LC_ROLE_ARN=$(aws iam create-role \
  --role-name "lab116-launch-constraint-role" \
  --assume-role-policy-document file:///tmp/lab116-sc-trust.json \
  --description "Lab116 Service Catalog launch constraint role" \
  --query 'Role.Arn' \
  --output text)

# Attach S3 permissions needed to create the bucket product
cat > /tmp/lab116-lc-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:PutBucketEncryption",
        "s3:PutBucketPublicAccessBlock",
        "s3:PutBucketVersioning",
        "s3:PutLifecycleConfiguration",
        "s3:PutBucketTagging",
        "s3:DeleteBucket",
        "cloudformation:*"
      ],
      "Resource": "*"
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name "lab116-launch-constraint-role" \
  --policy-name "SCLaunchPolicy" \
  --policy-document file:///tmp/lab116-lc-policy.json

echo "✅ Launch constraint role: $LC_ROLE_ARN"
echo "export LC_ROLE_ARN=\"$LC_ROLE_ARN\"" >> /tmp/lab116-env.sh
sleep 10

# Step 2: Create launch constraint on product in portfolio
echo ""
echo "[2] Creating launch constraint..."
aws servicecatalog create-constraint \
  --portfolio-id $PORTFOLIO_ID \
  --product-id $PRODUCT_ID \
  --type "LAUNCH" \
  --parameters "{\"RoleArn\":\"$LC_ROLE_ARN\"}" \
  --region $REGION \
  --query 'ConstraintDetail.{Type:Type,Description:Description}' \
  --output table
echo "✅ Launch constraint created"
echo "   End users only need servicecatalog:ProvisionProduct"
echo "   Launch constraint role handles all S3 creation"

# Step 3: Show template constraint concept
echo ""
echo "[3] Template Constraint — Parameter Restriction Demo..."
cat << 'EOF'
Template constraints restrict what parameter values users can choose.

Example: Restrict RetentionDays to only 90 or 365 days:
{
  "Rules": {
    "RetentionDaysRule": {
      "Assertions": [{
        "Assert": {
          "Fn::Contains": [["90", "365"], {"Ref": "RetentionDays"}]
        },
        "AssertDescription": "Retention must be 90 or 365 days"
      }]
    }
  }
}

Users see only the allowed values in the provisioning form.
Attempting other values is blocked at Service Catalog level.
EOF

echo ""
echo "================================================"
echo "Part 2 Complete!"
echo "================================================"
```

---

## Part 3 — Provision Product + Cleanup

```bash
#!/bin/bash
# Lab 116 - Part 3: Provision + Cleanup
source /tmp/lab116-env.sh

echo "================================================"
echo "  Part 3: Provision Product + Cleanup"
echo "================================================"

# Step 1: Get provisioning artifact ID
PA_ID=$(aws servicecatalog describe-product \
  --id $PRODUCT_ID \
  --region $REGION \
  --query 'ProvisioningArtifacts[0].Id' \
  --output text 2>/dev/null)

echo "Provisioning Artifact ID: $PA_ID"
echo "export PA_ID=\"$PA_ID\"" >> /tmp/lab116-env.sh

# Step 2: Provision the product
echo ""
echo "[1] Provisioning Secure S3 Bucket product..."
PP_ID=$(aws servicecatalog provision-product \
  --product-id $PRODUCT_ID \
  --provisioning-artifact-id $PA_ID \
  --provisioned-product-name "lab116-test-s3-bucket" \
  --provisioning-parameters \
    "Key=BucketPurpose,Value=Artifacts" \
    "Key=RetentionDays,Value=90" \
  --region $REGION \
  --query 'RecordDetail.ProvisionedProductId' \
  --output text 2>/dev/null)

if [ ! -z "$PP_ID" ]; then
  echo "✅ Provisioning started: $PP_ID"
  echo "export PP_ID=\"$PP_ID\"" >> /tmp/lab116-env.sh

  echo ""
  echo "[2] Waiting for provisioning to complete..."
  sleep 30

  aws servicecatalog describe-provisioned-product \
    --id $PP_ID \
    --region $REGION \
    --query 'ProvisionedProductDetail.{Status:Status,StatusMessage:StatusMessage}' \
    --output table 2>/dev/null
else
  echo "⚠️  Provisioning failed or insufficient permissions"
fi

# CLEANUP
echo ""
echo "================================================"
echo "  CLEANUP"
echo "================================================"

# Terminate provisioned product
if [ ! -z "$PP_ID" ]; then
  echo ""
  echo "Terminating provisioned product..."
  aws servicecatalog terminate-provisioned-product \
    --provisioned-product-id $PP_ID \
    --region $REGION 2>/dev/null && echo "✅ Product terminated"
  sleep 30
fi

echo ""
echo "Deleting product from portfolio..."
aws servicecatalog disassociate-product-from-portfolio \
  --product-id $PRODUCT_ID \
  --portfolio-id $PORTFOLIO_ID \
  --region $REGION 2>/dev/null

# Delete constraints
CONSTRAINT_IDS=$(aws servicecatalog list-constraints-for-portfolio \
  --portfolio-id $PORTFOLIO_ID \
  --region $REGION \
  --query 'ConstraintDetails[*].ConstraintId' \
  --output text 2>/dev/null)

for CID in $CONSTRAINT_IDS; do
  aws servicecatalog delete-constraint --id $CID --region $REGION 2>/dev/null
done

aws servicecatalog delete-product \
  --id $PRODUCT_ID \
  --region $REGION 2>/dev/null && echo "✅ Product deleted"

aws servicecatalog delete-portfolio \
  --id $PORTFOLIO_ID \
  --region $REGION 2>/dev/null && echo "✅ Portfolio deleted"

# Delete template S3 bucket
aws s3 rm s3://$TEMPLATE_BUCKET --recursive 2>/dev/null
aws s3 rb s3://$TEMPLATE_BUCKET --force 2>/dev/null && echo "✅ Template bucket deleted"

# Delete IAM role
aws iam delete-role-policy \
  --role-name "lab116-launch-constraint-role" \
  --policy-name "SCLaunchPolicy" 2>/dev/null
aws iam delete-role \
  --role-name "lab116-launch-constraint-role" 2>/dev/null && echo "✅ Launch constraint role deleted"

rm -f /tmp/lab116-env.sh /tmp/lab116-*.json /tmp/lab116-*.yaml
echo "✅ Temp files cleaned"

echo ""
echo "================================================"
echo "Lab 116 Cleanup Complete!"
echo "================================================"
```

---

## ✅ Lab 116 Verification Checklist

```
Lab 116 — Service Catalog Checklist
│
├── Part 1: Portfolio + Product
│     ├── [ ] Portfolio created with provider name
│     ├── [ ] CFN template: encrypted S3, versioning, public block
│     ├── [ ] Template uploaded to S3
│     ├── [ ] Product created with provisioning artifact
│     └── [ ] Product associated with portfolio
│
├── Part 2: Constraints
│     ├── [ ] Launch constraint role trusts SC + CFN principals
│     ├── [ ] Launch constraint role has S3 creation permissions
│     ├── [ ] Launch constraint attached to product in portfolio
│     └── [ ] Template constraint concept reviewed
│
└── Part 3: Provision + Cleanup
      ├── [ ] Product provisioned with parameter values
      ├── [ ] Launch constraint role used (not caller IAM)
      └── [ ] All resources cleaned up
```

---

## 🔑 Lab 116 Key Takeaways

| Concept | What You Practiced |
|---|---|
| Launch constraint | Role trusted by SC + CFN service principals |
| Separation of duty | User needs only ProvisionProduct permission |
| Template constraint | Restricts allowed parameter values |
| Product association | Product must be in portfolio to be usable |
| Provisioned product | Running instance of a deployed product |
| TAINTED status | Failed deployment state |
| Portfolio sharing | Org-level distributes to all accounts |

---

# 📅 Day 47 — Section 3: Lab 117
## AWS Artifact — Compliance Documents + Agreements

---

## 🎯 Lab Objective

> **Note:** AWS Artifact is a documentation and agreement portal — it does not have CLI commands for most operations. This lab is focused on console navigation, policy review, and IAM permission verification.

In this lab you will:
- Verify IAM permissions for Artifact access
- Locate and understand available compliance reports
- Review agreement types (BAA, NDA, GDPR DPA)
- Understand the Shared Responsibility Matrix concept
- Practice identifying correct Artifact documents for compliance scenarios
- Document the Artifact → Organizations integration for BAA

---

## Prerequisites Check

```bash
#!/bin/bash
# Lab 117 - Prerequisites Check
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region || echo "ap-south-1")

cat > /tmp/lab117-env.sh << EOF
export ACCOUNT_ID="$ACCOUNT_ID"
export REGION="$REGION"
export LAB="lab117"
EOF

echo "================================================"
echo "  Lab 117: AWS Artifact Prerequisites"
echo "================================================"
aws sts get-caller-identity --output table

echo ""
echo "[1] Checking Artifact IAM permissions..."
aws iam simulate-principal-policy \
  --policy-source-arn $(aws sts get-caller-identity --query Arn --output text) \
  --action-names "artifact:Get" "artifact:ListReports" \
  --query 'EvaluationResults[*].{Action:EvalActionName,Decision:EvalDecision}' \
  --output table 2>/dev/null || \
  echo "ℹ️  Simulation requires iam:SimulatePrincipalPolicy permission"

echo ""
echo "✅ Environment saved to /tmp/lab117-env.sh"
echo "================================================"
```

---

## Part 1 — Artifact Permissions + Report Inventory

```bash
#!/bin/bash
# Lab 117 - Part 1: Artifact IAM + Report Knowledge
source /tmp/lab117-env.sh

echo "================================================"
echo "  Part 1: Artifact Permissions + Report Types"
echo "================================================"

# Step 1: Required Artifact IAM permissions
echo ""
echo "[1] Required IAM permissions for Artifact..."
cat << 'EOF'
Artifact Actions:
  artifact:Get                   → Download compliance reports
  artifact:ListReports           → List available reports
  artifact:AcceptAgreement       → Accept legal agreements (BAA, NDA, DPA)
  artifact:DownloadAgreement     → Download signed agreements
  artifact:TerminateAgreement    → Terminate accepted agreements

Recommended IAM policy for compliance team:
{
  "Effect": "Allow",
  "Action": [
    "artifact:Get",
    "artifact:ListReports",
    "artifact:AcceptAgreement",
    "artifact:DownloadAgreement"
  ],
  "Resource": "*"
}
EOF

# Step 2: Available compliance reports reference
echo ""
echo "[2] Available AWS Artifact Report Categories..."
cat << 'EOF'
┌─────────────────────────────────────────────────────────────┐
│              AWS ARTIFACT REPORT INVENTORY                   │
├─────────────────┬───────────────────────────────────────────┤
│ SOC Reports     │ SOC 1 Type I/II, SOC 2 Type I/II, SOC 3  │
│                 │ SOC 1 = financial reporting controls       │
│                 │ SOC 2 = security, availability, etc.      │
├─────────────────┼───────────────────────────────────────────┤
│ ISO Certs       │ ISO 27001, ISO 27017, ISO 27018           │
│                 │ ISO 27701 (privacy), ISO 9001             │
├─────────────────┼───────────────────────────────────────────┤
│ PCI-DSS         │ Attestation of Compliance (AOC)           │
│                 │ Responsibility Summary                     │
├─────────────────┼───────────────────────────────────────────┤
│ HIPAA           │ HIPAA Compliance - Eligible Services       │
│                 │ (Not a cert - eligibility list)           │
├─────────────────┼───────────────────────────────────────────┤
│ FedRAMP         │ FedRAMP packages (US gov workloads)       │
├─────────────────┼───────────────────────────────────────────┤
│ CSA STAR        │ Cloud Security Alliance assessments       │
├─────────────────┼───────────────────────────────────────────┤
│ GDPR            │ Data Processing Addendum (DPA)            │
│                 │ GDPR-related whitepapers                  │
└─────────────────┴───────────────────────────────────────────┘
EOF

# Step 3: Agreement types
echo ""
echo "[3] AWS Artifact Agreement Types..."
cat << 'EOF'
┌─────────────┬──────────────────────────────────────────────┐
│ Agreement   │ Purpose                                       │
├─────────────┼──────────────────────────────────────────────┤
│ BAA         │ Business Associate Agreement - HIPAA          │
│             │ Required: AWS handles PHI on your behalf      │
│             │ Location: Artifact → Agreements → HIPAA       │
├─────────────┼──────────────────────────────────────────────┤
│ GDPR DPA    │ Data Processing Addendum - GDPR               │
│             │ Required: AWS processes EU personal data      │
│             │ Location: Artifact → Agreements → GDPR        │
├─────────────┼──────────────────────────────────────────────┤
│ NDA         │ Non-Disclosure Agreement                      │
│             │ Required: Before downloading sensitive reports │
│             │ Accepted inline when downloading              │
└─────────────┴──────────────────────────────────────────────┘

Organizations Integration:
  Accept BAA/DPA in management account → covers ALL member accounts
  No need to accept per-account
  New accounts automatically covered
EOF

echo ""
echo "================================================"
echo "Part 1 Complete!"
echo "================================================"
```

---

## Part 2 — Scenario Mapping + Shared Responsibility

```bash
#!/bin/bash
# Lab 117 - Part 2: Compliance Scenario Mapping
source /tmp/lab117-env.sh

echo "================================================"
echo "  Part 2: Scenario → Artifact Document Mapping"
echo "================================================"

cat << 'EOF'
COMPLIANCE SCENARIO → ARTIFACT DOCUMENT MAPPING
(Practice for exam questions)

Scenario 1: HIPAA-regulated healthcare app
  Need: AWS's BAA
  Document: Artifact Agreements → BAA (Business Associate Addendum)

Scenario 2: QSA needs AWS's PCI-DSS compliance evidence
  Need: PCI Attestation of Compliance
  Document: Artifact Reports → PCI-DSS → AOC + Responsibility Matrix

Scenario 3: ISO 27001 auditor asks for AWS physical security evidence
  Need: AWS ISO certification + SOC 2
  Document: Artifact Reports → ISO 27001 Certificate
              + SOC 2 Type II (covers physical security)

Scenario 4: Financial services needs AWS's financial controls evidence
  Need: SOC 1 report (financial reporting controls)
  Document: Artifact Reports → SOC 1 Type II

Scenario 5: EU customers using app, GDPR compliance required
  Need: AWS's GDPR Data Processing commitments
  Document: Artifact Agreements → GDPR DPA

Scenario 6: US Federal government workload
  Need: FedRAMP authorization evidence
  Document: Artifact Reports → FedRAMP packages

Scenario 7: Compliance team says "does AWS meet NIST 800-53?"
  Need: NIST compliance documentation
  Document: Artifact Reports → NIST 800-53 (various certifications)

Scenario 8: New AWS account added to Org, needs HIPAA BAA
  Need: BAA coverage for new account
  Answer: BAA accepted at Org level automatically covers new accounts
           No per-account acceptance needed
EOF

echo ""
echo "================================================"
echo "  Shared Responsibility Reminder"
echo "================================================"
cat << 'EOF'
AWS Artifact reports cover:
  ✅ AWS physical security
  ✅ AWS network infrastructure
  ✅ AWS service-level controls
  ✅ AWS hypervisor/hardware

Customer must separately demonstrate:
  ❌ Your IAM configuration
  ❌ Your application security
  ❌ Your data encryption choices
  ❌ Your network security group config
  ❌ Your OS patching
  ❌ Your application code security

Artifact = INHERITED CONTROLS evidence
Your assessment = CUSTOMER RESPONSIBILITY evidence
EOF

echo ""
echo "================================================"
echo "Part 2 Complete!"
echo "================================================"
```

---

## Part 3 — Console Navigation Guide + Cleanup

```bash
#!/bin/bash
# Lab 117 - Part 3: Console Navigation Guide
source /tmp/lab117-env.sh

echo "================================================"
echo "  Part 3: Console Navigation Guide"
echo "================================================"

cat << 'EOF'
AWS ARTIFACT CONSOLE NAVIGATION
================================

1. Access Artifact:
   AWS Console → Search "Artifact" → AWS Artifact

2. Download a SOC 2 report:
   Artifact → Reports → SOC → SOC 2 Type II
   → Accept NDA if prompted
   → Click Download

3. Accept HIPAA BAA:
   Artifact → Agreements → Amazon HIPAA BAA
   → Review agreement terms
   → Accept Agreement (for this account OR organization)

4. Accept GDPR DPA:
   Artifact → Agreements → AWS GDPR DPA
   → Accept Agreement

5. Accept BAA for entire Organization:
   Artifact → Agreements → Amazon HIPAA BAA
   → Select: Apply to Organization
   → Accept (management account only)

6. Check accepted agreements:
   Artifact → Agreements → Your Agreements tab

7. Terminate an agreement:
   Artifact → Agreements → Your Agreements
   → Find agreement → Terminate

Required IAM permissions:
  artifact:Get         → Download reports
  artifact:AcceptAgreement → Accept BAA/DPA
  organizations:DescribeOrganization → For Org-level acceptance
EOF

# Verify Artifact access via CLI (limited CLI support)
echo ""
echo "[Checking Artifact CLI access (limited)...]"
aws artifact list-reports \
  --region us-east-1 \
  --query 'reports[*].{Name:name,Category:category}' \
  --output table 2>/dev/null | head -15 || \
  echo "ℹ️  Artifact CLI access requires specific permissions"
  echo "    Most Artifact operations are console-based"

echo ""
echo "Cleaning up temp files..."
rm -f /tmp/lab117-env.sh
echo "✅ Temp files cleaned"

echo ""
echo "================================================"
echo "Lab 117 Complete!"
echo "================================================"
```

---

## ✅ Lab 117 Verification Checklist

```
Lab 117 — AWS Artifact Checklist
│
├── Part 1: Permissions + Reports
│     ├── [ ] Artifact IAM permissions documented
│     ├── [ ] SOC 1 vs SOC 2 distinction clear
│     ├── [ ] PCI AOC purpose understood
│     ├── [ ] HIPAA eligibility list (not cert) understood
│     └── [ ] Agreement types: BAA vs DPA vs NDA
│
├── Part 2: Scenario Mapping
│     ├── [ ] HIPAA → BAA in Agreements
│     ├── [ ] PCI audit → AOC + Responsibility Matrix
│     ├── [ ] ISO 27001 audit → ISO cert + SOC 2
│     ├── [ ] GDPR → DPA in Agreements
│     ├── [ ] New Org account → BAA auto-covered
│     └── [ ] Artifact = AWS controls only, not customer
│
└── Part 3: Console Navigation
      ├── [ ] Report download path understood
      ├── [ ] BAA acceptance path understood
      ├── [ ] Org-level acceptance understood
      └── [ ] Artifact CLI limitations noted
```

---

## 🔑 Lab 117 Key Takeaways

| Concept | What You Practiced |
|---|---|
| Artifact = AWS's compliance | Not your app's compliance |
| BAA = HIPAA | Business Associate Agreement |
| DPA = GDPR | Data Processing Addendum |
| SOC 1 = financial | SOC 2 = security/availability |
| Org BAA | One acceptance covers all accounts |
| NDA inline | Accepted during report download |
| Artifact CLI | Limited — most operations console-based |

---

# 📅 Day 48 — Section 3: Lab 118
## Incident Response Playbooks

---

## 🎯 Lab Objective
In this lab you will:
- Build an automated IR pipeline: GuardDuty → EventBridge → Lambda
- Create an EC2 isolation Lambda function
- Create a credential revocation Lambda function
- Test the automation with a simulated finding
- Build an Athena table for CloudTrail log querying
- Practice IR CLI commands (isolation, credential revocation)
- Cleanup all resources

---

## Prerequisites Check

```bash
#!/bin/bash
# Lab 118 - Prerequisites Check
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region || echo "ap-south-1")

cat > /tmp/lab118-env.sh << EOF
export ACCOUNT_ID="$ACCOUNT_ID"
export REGION="$REGION"
export LAB="lab118"
EOF

echo "================================================"
echo "  Lab 118: Incident Response Prerequisites"
echo "================================================"
aws sts get-caller-identity --output table
echo "Region: $REGION"

echo ""
echo "[1] Checking GuardDuty status..."
GD_DETECTOR_ID=$(aws guardduty list-detectors \
  --region $REGION \
  --query 'DetectorIds[0]' \
  --output text 2>/dev/null)

if [ "$GD_DETECTOR_ID" != "None" ] && [ ! -z "$GD_DETECTOR_ID" ]; then
  echo "✅ GuardDuty active: $GD_DETECTOR_ID"
  echo "export GD_DETECTOR_ID=\"$GD_DETECTOR_ID\"" >> /tmp/lab118-env.sh
else
  echo "ℹ️  GuardDuty not enabled - enabling now..."
  GD_DETECTOR_ID=$(aws guardduty create-detector \
    --enable \
    --region $REGION \
    --query 'DetectorId' \
    --output text)
  echo "✅ GuardDuty enabled: $GD_DETECTOR_ID"
  echo "export GD_DETECTOR_ID=\"$GD_DETECTOR_ID\"" >> /tmp/lab118-env.sh
fi

echo ""
echo "[2] Checking default VPC for test EC2..."
DEFAULT_VPC=$(aws ec2 describe-vpcs \
  --filters Name=isDefault,Values=true \
  --region $REGION \
  --query 'Vpcs[0].VpcId' \
  --output text)
echo "Default VPC: $DEFAULT_VPC"
echo "export DEFAULT_VPC=\"$DEFAULT_VPC\"" >> /tmp/lab118-env.sh

echo ""
echo "✅ Environment saved to /tmp/lab118-env.sh"
echo "================================================"
```

---

## Part 1 — IR Infrastructure (Forensics SG + SNS)

```bash
#!/bin/bash
# Lab 118 - Part 1: IR Infrastructure
source /tmp/lab118-env.sh

echo "================================================"
echo "  Part 1: IR Infrastructure Setup"
echo "================================================"

# Step 1: Create forensics security group (all traffic blocked)
echo ""
echo "[1] Creating forensics security group (all traffic blocked)..."
FORENSICS_SG_ID=$(aws ec2 create-security-group \
  --group-name "lab118-forensics-sg" \
  --description "FORENSICS: All inbound and outbound BLOCKED" \
  --vpc-id $DEFAULT_VPC \
  --region $REGION \
  --query 'GroupId' \
  --output text)

# Remove default outbound allow-all rule
aws ec2 revoke-security-group-egress \
  --group-id $FORENSICS_SG_ID \
  --protocol -1 \
  --port -1 \
  --cidr 0.0.0.0/0 \
  --region $REGION 2>/dev/null

aws ec2 create-tags \
  --resources $FORENSICS_SG_ID \
  --tags Key=Name,Value=FORENSICS-ALL-BLOCKED Key=Purpose,Value=IncidentResponse \
  --region $REGION

echo "✅ Forensics SG: $FORENSICS_SG_ID"
echo "   All inbound: BLOCKED"
echo "   All outbound: BLOCKED"
echo "export FORENSICS_SG_ID=\"$FORENSICS_SG_ID\"" >> /tmp/lab118-env.sh

# Step 2: Create SNS topic for IR notifications
echo ""
echo "[2] Creating IR notification SNS topic..."
SNS_ARN=$(aws sns create-topic \
  --name "lab118-ir-alerts" \
  --region $REGION \
  --query 'TopicArn' \
  --output text)

# Subscribe to SNS (email — for demo; change to your email)
echo "   Note: Add your email subscription manually:"
echo "   aws sns subscribe --topic-arn $SNS_ARN --protocol email --notification-endpoint YOUR@EMAIL.COM"
echo "✅ SNS topic: $SNS_ARN"
echo "export SNS_ARN=\"$SNS_ARN\"" >> /tmp/lab118-env.sh

echo ""
echo "================================================"
echo "Part 1 Complete!"
echo "================================================"
```

---

## Part 2 — IR Lambda Functions

```bash
#!/bin/bash
# Lab 118 - Part 2: IR Lambda Functions
source /tmp/lab118-env.sh

echo "================================================"
echo "  Part 2: IR Lambda Functions"
echo "================================================"

# Step 1: Create Lambda execution role for IR
echo ""
echo "[1] Creating IR Lambda execution role..."
cat > /tmp/lab118-lambda-trust.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF

IR_ROLE_ARN=$(aws iam create-role \
  --role-name "lab118-ir-lambda-role" \
  --assume-role-policy-document file:///tmp/lab118-lambda-trust.json \
  --description "Lab118 IR automation Lambda role" \
  --query 'Role.Arn' \
  --output text)

aws iam attach-role-policy \
  --role-name "lab118-ir-lambda-role" \
  --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

cat > /tmp/lab118-ir-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:ModifyInstanceAttribute",
        "ec2:DescribeInstances",
        "ec2:CreateSnapshot",
        "ec2:DescribeVolumes",
        "ec2:CreateTags"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "iam:PutRolePolicy",
        "iam:GetRole"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["sns:Publish"],
      "Resource": "$SNS_ARN"
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name "lab118-ir-lambda-role" \
  --policy-name "IRAutomationPolicy" \
  --policy-document file:///tmp/lab118-ir-policy.json

echo "✅ IR Lambda role: $IR_ROLE_ARN"
echo "export IR_ROLE_ARN=\"$IR_ROLE_ARN\"" >> /tmp/lab118-env.sh
sleep 10

# Step 2: Create EC2 Isolation Lambda
echo ""
echo "[2] Creating EC2 Isolation Lambda..."
mkdir -p /tmp/lab118-lambda

cat > /tmp/lab118-lambda/ec2_isolate.py << PYEOF
import boto3
import json
import os
import logging
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

FORENSICS_SG_ID = os.environ.get('FORENSICS_SG_ID')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
REGION = os.environ.get('AWS_REGION', 'ap-south-1')

def lambda_handler(event, context):
    """
    IR Automation: Isolate compromised EC2 instance
    Triggered by GuardDuty finding via EventBridge
    """
    logger.info(f"Received event: {json.dumps(event)}")

    # Extract instance ID from GuardDuty finding
    try:
        finding = event.get('detail', {})
        instance_id = (
            finding.get('resource', {})
                   .get('instanceDetails', {})
                   .get('instanceId')
        )
        finding_type = finding.get('type', 'Unknown')
        severity = finding.get('severity', 0)
    except Exception as e:
        logger.error(f"Error parsing finding: {e}")
        instance_id = event.get('test_instance_id')
        finding_type = 'TEST'
        severity = 9.0

    if not instance_id:
        logger.warning("No instance ID found in finding")
        return {'status': 'no_instance_id'}

    ec2 = boto3.client('ec2', region_name=REGION)
    sns = boto3.client('sns', region_name=REGION)

    results = {
        'instance_id': instance_id,
        'finding_type': finding_type,
        'severity': severity,
        'actions': []
    }

    # Step 1: Create EBS snapshot for forensics
    try:
        instance_info = ec2.describe_instances(InstanceIds=[instance_id])
        volumes = [
            bdm['Ebs']['VolumeId']
            for reservation in instance_info['Reservations']
            for instance in reservation['Instances']
            for bdm in instance.get('BlockDeviceMappings', [])
            if 'Ebs' in bdm
        ]

        for vol_id in volumes:
            snapshot = ec2.create_snapshot(
                VolumeId=vol_id,
                Description=f"FORENSICS-{instance_id}-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
                TagSpecifications=[{
                    'ResourceType': 'snapshot',
                    'Tags': [
                        {'Key': 'Purpose', 'Value': 'Forensics'},
                        {'Key': 'InstanceId', 'Value': instance_id},
                        {'Key': 'FindingType', 'Value': finding_type},
                        {'Key': 'CaseId', 'Value': f'IR-{datetime.utcnow().strftime("%Y%m%d")}'}
                    ]
                }]
            )
            logger.info(f"Snapshot created: {snapshot['SnapshotId']} for {vol_id}")
            results['actions'].append(f"snapshot:{snapshot['SnapshotId']}")

    except Exception as e:
        logger.error(f"Snapshot creation failed: {e}")

    # Step 2: Isolate instance (swap security group)
    try:
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[FORENSICS_SG_ID]
        )
        logger.info(f"Instance {instance_id} isolated with forensics SG: {FORENSICS_SG_ID}")
        results['actions'].append(f"isolated:{FORENSICS_SG_ID}")

    except Exception as e:
        logger.error(f"Isolation failed: {e}")

    # Step 3: Notify IR team
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"IR ALERT: EC2 Isolated - {instance_id}",
            Message=json.dumps({
                'incident': 'EC2_COMPROMISE_DETECTED',
                'instance_id': instance_id,
                'finding_type': finding_type,
                'severity': severity,
                'actions_taken': results['actions'],
                'timestamp': datetime.utcnow().isoformat(),
                'next_steps': [
                    'Review CloudTrail for instance activity',
                    'Analyze EBS snapshot in forensics account',
                    'Check VPC Flow Logs for network activity',
                    'Rotate any credentials the instance had access to'
                ]
            }, indent=2)
        )
        results['actions'].append('notified:sns')
    except Exception as e:
        logger.error(f"SNS notification failed: {e}")

    logger.info(f"IR actions completed: {results}")
    return results
PYEOF

cd /tmp/lab118-lambda
zip -r ec2_isolate.zip ec2_isolate.py

EC2_IR_LAMBDA_ARN=$(aws lambda create-function \
  --function-name "lab118-ec2-isolate" \
  --runtime python3.12 \
  --role "$IR_ROLE_ARN" \
  --handler "ec2_isolate.lambda_handler" \
  --zip-file "fileb:///tmp/lab118-lambda/ec2_isolate.zip" \
  --timeout 60 \
  --environment "Variables={FORENSICS_SG_ID=$FORENSICS_SG_ID,SNS_TOPIC_ARN=$SNS_ARN}" \
  --description "Lab118 IR: EC2 isolation automation" \
  --region $REGION \
  --query 'FunctionArn' \
  --output text)

aws lambda wait function-active \
  --function-name "lab118-ec2-isolate" \
  --region $REGION

echo "✅ EC2 Isolation Lambda: $EC2_IR_LAMBDA_ARN"
echo "export EC2_IR_LAMBDA_ARN=\"$EC2_IR_LAMBDA_ARN\"" >> /tmp/lab118-env.sh

echo ""
echo "================================================"
echo "Part 2 Complete!"
echo "================================================"
```

---

## Part 3 — EventBridge Rule + Test IR Pipeline

```bash
#!/bin/bash
# Lab 118 - Part 3: EventBridge + Test
source /tmp/lab118-env.sh

echo "================================================"
echo "  Part 3: EventBridge Rule + IR Pipeline Test"
echo "================================================"

# Step 1: Add Lambda permission for EventBridge
echo ""
echo "[1] Granting EventBridge permission to invoke Lambda..."
aws lambda add-permission \
  --function-name "lab118-ec2-isolate" \
  --statement-id "EventBridgeInvoke" \
  --action "lambda:InvokeFunction" \
  --principal "events.amazonaws.com" \
  --source-account "$ACCOUNT_ID" \
  --region $REGION 2>/dev/null
echo "✅ Permission granted"

# Step 2: Create EventBridge rule for GuardDuty findings
echo ""
echo "[2] Creating EventBridge rule for GuardDuty findings..."
aws events put-rule \
  --name "lab118-guardduty-ec2-compromise" \
  --description "Lab118: Route EC2 compromise GD findings to IR Lambda" \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "severity": [{"numeric": [">=", 7.0]}],
      "resource": {
        "resourceType": ["Instance"]
      }
    }
  }' \
  --state ENABLED \
  --region $REGION

echo "✅ EventBridge rule created: lab118-guardduty-ec2-compromise"

# Step 3: Add Lambda as EventBridge target
aws events put-targets \
  --rule "lab118-guardduty-ec2-compromise" \
  --targets "Id=ec2-isolate,Arn=$EC2_IR_LAMBDA_ARN" \
  --region $REGION
echo "✅ Lambda target added to EventBridge rule"

# Step 4: Create a test EC2 instance to simulate isolation on
echo ""
echo "[3] Creating test EC2 instance for isolation demo..."
DEFAULT_SUBNET=$(aws ec2 describe-subnets \
  --filters Name=vpc-id,Values=$DEFAULT_VPC \
  --region $REGION \
  --query 'Subnets[0].SubnetId' \
  --output text)

# Use latest Amazon Linux 2 AMI
AMI_ID=$(aws ec2 describe-images \
  --owners amazon \
  --filters \
    "Name=name,Values=amzn2-ami-hvm-*-x86_64-gp2" \
    "Name=state,Values=available" \
  --query 'sort_by(Images,&CreationDate)[-1].ImageId' \
  --output text \
  --region $REGION)

TEST_INSTANCE_ID=$(aws ec2 run-instances \
  --image-id $AMI_ID \
  --instance-type t3.micro \
  --subnet-id $DEFAULT_SUBNET \
  --no-associate-public-ip-address \
  --tag-specifications \
    "ResourceType=instance,Tags=[{Key=Name,Value=lab118-test-victim},{Key=Lab,Value=lab118}]" \
  --region $REGION \
  --query 'Instances[0].InstanceId' \
  --output text)

echo "✅ Test instance launched: $TEST_INSTANCE_ID"
echo "export TEST_INSTANCE_ID=\"$TEST_INSTANCE_ID\"" >> /tmp/lab118-env.sh

echo ""
echo "[4] Waiting for instance to reach running state..."
aws ec2 wait instance-running \
  --instance-ids $TEST_INSTANCE_ID \
  --region $REGION
echo "✅ Instance running"

# Step 5: Test IR pipeline with simulated GuardDuty-like payload
echo ""
echo "[5] Testing IR pipeline with simulated finding..."
cat > /tmp/lab118-test-event.json << EOF
{
  "test_instance_id": "$TEST_INSTANCE_ID",
  "detail": {
    "type": "Backdoor:EC2/C&CActivity.B!DNS",
    "severity": 8.0,
    "resource": {
      "resourceType": "Instance",
      "instanceDetails": {
        "instanceId": "$TEST_INSTANCE_ID"
      }
    }
  }
}
EOF

aws lambda invoke \
  --function-name "lab118-ec2-isolate" \
  --payload file:///tmp/lab118-test-event.json \
  --region $REGION \
  --log-type Tail \
  /tmp/lab118-ir-output.json \
  --query 'LogResult' --output text | base64 -d

echo ""
echo "IR Response output:"
cat /tmp/lab118-ir-output.json | python3 -m json.tool

# Step 6: Verify isolation
echo ""
echo "[6] Verifying instance isolation..."
sleep 5
aws ec2 describe-instances \
  --instance-ids $TEST_INSTANCE_ID \
  --region $REGION \
  --query 'Reservations[0].Instances[0].{
    InstanceId:InstanceId,
    State:State.Name,
    SecurityGroups:SecurityGroups[*].GroupId
  }' \
  --output table

echo ""
echo "================================================"
echo "Part 3 Complete!"
echo "================================================"
```

---

## Part 4 — CloudTrail Athena Query Setup + IR CLI Reference

```bash
#!/bin/bash
# Lab 118 - Part 4: Athena IR Setup + CLI Reference
source /tmp/lab118-env.sh

echo "================================================"
echo "  Part 4: Athena for IR + CLI Reference"
echo "================================================"

# Step 1: Key IR CLI commands reference
echo ""
echo "[1] Critical IR CLI Commands Cheat Sheet..."
cat << IREOF

# ─── CREDENTIAL CONTAINMENT ───────────────────────────────────

# Deactivate an access key immediately
aws iam update-access-key \
  --access-key-id AKIAEXAMPLE \
  --status Inactive

# Revoke all STS sessions for a role (TokenIssueTime technique)
# Add this inline deny policy to the role:
DENY_POLICY='{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Deny",
    "Action":"*",
    "Resource":"*",
    "Condition":{
      "DateLessThan":{
        "aws:TokenIssueTime":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"
      }
    }
  }]
}'
aws iam put-role-policy \
  --role-name ROLE_NAME \
  --policy-name EmergencyRevoke \
  --policy-document "\$DENY_POLICY"

# ─── EC2 CONTAINMENT ──────────────────────────────────────────

# Isolate EC2 (replace with forensics SG - all blocked)
aws ec2 modify-instance-attribute \
  --instance-id i-INSTANCEID \
  --groups sg-FORENSICS_SG_ID

# Create forensic EBS snapshot
aws ec2 create-snapshot \
  --volume-id vol-VOLUMEID \
  --description "FORENSICS-$(date +%Y%m%d-%H%M%S)" \
  --tag-specifications 'ResourceType=snapshot,Tags=[{Key=Purpose,Value=Forensics}]'

# Lambda kill switch
aws lambda put-function-concurrency \
  --function-name FUNCTION_NAME \
  --reserved-concurrent-executions 0

# ─── S3 CONTAINMENT ───────────────────────────────────────────

# Block all public access on compromised bucket
aws s3api put-public-access-block \
  --bucket BUCKET_NAME \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# ─── ATHENA CLOUDTRAIL QUERIES ────────────────────────────────

# Who called GetSecretValue in the last 24 hours?
# SELECT eventtime, useridentity.arn, sourceipaddress, requestparameters
# FROM cloudtrail_logs
# WHERE eventname = 'GetSecretValue'
# AND eventtime > '2024-01-01T00:00:00Z'
# ORDER BY eventtime DESC

# What did compromised key AKIAEXAMPLE do?
# SELECT eventtime, eventname, sourceipaddress, requestparameters
# FROM cloudtrail_logs
# WHERE useridentity.accesskeyid = 'AKIAEXAMPLE'
# ORDER BY eventtime ASC

# Find all IAM changes in last 7 days (backdoor check)
# SELECT eventtime, eventname, useridentity.arn, requestparameters
# FROM cloudtrail_logs
# WHERE eventsource = 'iam.amazonaws.com'
# AND eventtime > '2024-01-01T00:00:00Z'
# ORDER BY eventtime ASC

IREOF

# Step 2: GuardDuty sample finding generation
echo ""
echo "[2] Generating GuardDuty sample finding for testing..."
SAMPLE_FINDING_ID=$(aws guardduty create-sample-findings \
  --detector-id $GD_DETECTOR_ID \
  --finding-types "UnauthorizedAccess:EC2/SSHBruteForce" \
  --region $REGION 2>/dev/null && echo "✅ Sample finding created" || \
  echo "⚠️  Sample finding generation may require specific permissions")

# Step 3: View GuardDuty findings
echo ""
echo "[3] Recent GuardDuty findings..."
aws guardduty list-findings \
  --detector-id $GD_DETECTOR_ID \
  --region $REGION \
  --finding-criteria '{"Criterion":{"severity":{"Gte":4}}}' \
  --max-results 5 \
  --query 'FindingIds[]' \
  --output table 2>/dev/null | head -10

echo ""
echo "================================================"
echo "Part 4 Complete!"
echo "================================================"
```

---

## Part 5 — Cleanup

```bash
#!/bin/bash
# Lab 118 - Part 5: Cleanup
source /tmp/lab118-env.sh

echo "================================================"
echo "  Part 5: Cleanup All Lab 118 Resources"
echo "================================================"

echo ""
echo "[1] Terminating test EC2 instance..."
aws ec2 terminate-instances \
  --instance-ids $TEST_INSTANCE_ID \
  --region $REGION 2>/dev/null && echo "✅ Instance terminated"

echo ""
echo "[2] Deleting EventBridge rule..."
aws events remove-targets \
  --rule "lab118-guardduty-ec2-compromise" \
  --ids "ec2-isolate" \
  --region $REGION 2>/dev/null
aws events delete-rule \
  --name "lab118-guardduty-ec2-compromise" \
  --region $REGION 2>/dev/null && echo "✅ EventBridge rule deleted"

echo ""
echo "[3] Deleting Lambda function..."
aws lambda delete-function \
  --function-name "lab118-ec2-isolate" \
  --region $REGION 2>/dev/null && echo "✅ Lambda deleted"

echo ""
echo "[4] Deleting SNS topic..."
aws sns delete-topic \
  --topic-arn $SNS_ARN \
  --region $REGION 2>/dev/null && echo "✅ SNS topic deleted"

echo ""
echo "[5] Waiting for EC2 termination before deleting SG..."
aws ec2 wait instance-terminated \
  --instance-ids $TEST_INSTANCE_ID \
  --region $REGION 2>/dev/null
echo "✅ Instance terminated"

echo ""
echo "[6] Deleting forensics security group..."
aws ec2 delete-security-group \
  --group-id $FORENSICS_SG_ID \
  --region $REGION 2>/dev/null && echo "✅ Forensics SG deleted"

echo ""
echo "[7] Deleting IAM role..."
aws iam detach-role-policy \
  --role-name "lab118-ir-lambda-role" \
  --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole" 2>/dev/null
aws iam delete-role-policy \
  --role-name "lab118-ir-lambda-role" \
  --policy-name "IRAutomationPolicy" 2>/dev/null
aws iam delete-role \
  --role-name "lab118-ir-lambda-role" 2>/dev/null && echo "✅ IAM role deleted"

echo ""
echo "[8] Archiving GuardDuty sample findings..."
FINDING_IDS=$(aws guardduty list-findings \
  --detector-id $GD_DETECTOR_ID \
  --region $REGION \
  --query 'FindingIds[]' \
  --output text 2>/dev/null)

if [ ! -z "$FINDING_IDS" ]; then
  aws guardduty archive-findings \
    --detector-id $GD_DETECTOR_ID \
    --finding-ids $FINDING_IDS \
    --region $REGION 2>/dev/null && echo "✅ Sample findings archived"
fi

echo ""
echo "[9] Cleanup temp files..."
rm -f /tmp/lab118-env.sh /tmp/lab118-*.json \
      /tmp/lab118-lambda-trust.json \
      /tmp/lab118-ir-policy.json
rm -rf /tmp/lab118-lambda/
echo "✅ Temp files cleaned"

echo ""
echo "================================================"
echo "Lab 118 Cleanup Complete!"
echo "================================================"
```

---

## ✅ Lab 118 Verification Checklist

```
Lab 118 — Incident Response Checklist
│
├── Part 1: IR Infrastructure
│     ├── [ ] Forensics SG created (all traffic blocked)
│     ├── [ ] No outbound rules on forensics SG
│     └── [ ] SNS IR alert topic created
│
├── Part 2: IR Lambda Functions
│     ├── [ ] IR Lambda role: least privilege (specific EC2 + IAM + SNS)
│     ├── [ ] EC2 isolation Lambda deployed
│     ├── [ ] Lambda: snapshot → isolate → notify flow implemented
│     └── [ ] Snapshots tagged with forensics metadata
│
├── Part 3: EventBridge + Pipeline Test
│     ├── [ ] EventBridge rule: GD severity >= 7.0, Instance resource type
│     ├── [ ] Lambda target added to EventBridge rule
│     ├── [ ] Test EC2 instance created
│     ├── [ ] IR pipeline tested with simulated finding
│     └── [ ] Instance security group changed to forensics SG
│
├── Part 4: IR CLI Reference
│     ├── [ ] Access key deactivation command practiced
│     ├── [ ] STS session revocation (TokenIssueTime) understood
│     ├── [ ] EC2 isolation via modify-instance-attribute practiced
│     ├── [ ] Forensic snapshot creation command practiced
│     ├── [ ] Athena CloudTrail query templates reviewed
│     └── [ ] GuardDuty sample finding generated
│
└── Part 5: Cleanup
      └── [ ] All resources deleted
```

---

## 🔑 Lab 118 Key Takeaways

| Concept | What You Practiced |
|---|---|
| Forensics SG | No inbound OR outbound — complete isolation |
| GD → EB → Lambda | Real-time automated IR response pipeline |
| EB pattern matching | severity >= 7.0, resource type: Instance |
| Snapshot before terminate | Evidence preservation order |
| Forensic snapshot tags | CaseId, Purpose, InstanceId, FindingType |
| TokenIssueTime | Revoke ALL STS sessions for a role instantly |
| Athena + CloudTrail | SQL queries over S3 log data at scale |
| Lambda kill switch | reserved-concurrent-executions = 0 |
| SNS in IR | Always notify team even with automation |

---

# 🎉 Days 40–48 Labs — All Complete!

```
Lab Summary:
├── Lab 110: Lambda Security (VPC + SM + KMS + concurrency)
├── Lab 111: ECS/EKS Security (task roles + awsvpc + ECR)
├── Lab 112: Secrets in Containers (SM + SSM + rotation)
├── Lab 113: AWS Config (recorder + managed rules + custom rule)
├── Lab 114: AWS Organizations SCPs (protect services + region)
├── Lab 115: Control Tower (guardrails + Account Factory)
├── Lab 116: Service Catalog (portfolio + launch constraint)
├── Lab 117: AWS Artifact (compliance documents + agreements)
└── Lab 118: Incident Response (GuardDuty → EB → Lambda + Athena)
```
