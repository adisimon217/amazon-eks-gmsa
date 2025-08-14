# AWS Managed Active Directory Setup for EKS gMSA Integration

This guide provides step-by-step instructions to provision AWS Managed Microsoft Active Directory in an existing VPC for use with EKS gMSA integration.

## Prerequisites

- Existing VPC with at least 2 subnets in different AZs
- AWS CLI configured with appropriate permissions
- PowerShell (for parameter configuration)

## Configuration Variables

Set these variables before running the setup commands:

```bash
# Required - Replace with your values
export AD_USER_PASSWORD="YourStrongPassword123!" # AD admin password (for default 'Admin' user)
export VPC_ID="vpc-0165c53ecb1625c38" # Your existing VPC ID
export SUBNETS="subnet-015a4e3e09e7bbaec,subnet-0aee26bc2f76199c0" # Private subnet IDs (comma separated)

# Optional - Modify if needed
export AD_DIRECTORY_NAME="sandbox.aws.corp.com" # AD domain name
export AD_DIRECTORY_SHORT_NAME="sandbox" # AD NetBIOS name
export REGION="ap-southeast-1" # AWS region
```

## Step 1: Create Customer Managed KMS Key

```bash
# Create KMS key for encrypting AD passwords
aws cloudformation create-stack \
    --stack-name cmkstack \
    --template-body file://cloudformation/kms-custom-cmk.yaml \
    --parameters \
        ParameterKey=CMKAlias,ParameterValue=gMSAKey \
        ParameterKey=CMKDescription,ParameterValue="Encrypt or Decrypt gMSA active directory admin password" \
    --region $REGION

# Wait for stack completion
aws cloudformation wait stack-create-complete --stack-name cmkstack --region $REGION

# Get KMS key details
CMK_ID=$(aws cloudformation describe-stacks \
    --stack-name cmkstack \
    --query "Stacks[0].Outputs[?OutputKey=='CMKID'].OutputValue" \
    --output text \
    --region $REGION)

CMK_ARN=$(aws cloudformation describe-stacks \
    --stack-name cmkstack \
    --query "Stacks[0].Outputs[?OutputKey=='CMKARN'].OutputValue" \
    --output text \
    --region $REGION)

echo "KMS Key ID: $CMK_ID"
echo "KMS Key ARN: $CMK_ARN"
```

## Step 2: Create IAM Policy for KMS Access

```bash
# Create KMS decrypt policy
cat > kmspolicy-temp.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["kms:Decrypt"],
            "Resource": ["$CMK_ARN"]
        }
    ]
}
EOF

# Create IAM policy
aws iam create-policy \
    --policy-name cmk-decrypt \
    --policy-document file://kmspolicy-temp.json \
    --region $REGION

# Clean up temp file
rm kmspolicy-temp.json
```

## Step 3: Create SSM Parameters

```bash
# Store AD configuration in SSM Parameter Store
aws ssm put-parameter \
    --name "gMSA-demo-DirectoryName" \
    --value "$AD_DIRECTORY_NAME" \
    --type "String" \
    --region $REGION

aws ssm put-parameter \
    --name "gMSA-demo-ADUserPassword" \
    --value "$AD_USER_PASSWORD" \
    --key-id "$CMK_ID" \
    --type "SecureString" \
    --region $REGION
```

## Step 4: Deploy AWS Managed Active Directory

```bash
# Create AWS Managed AD
aws cloudformation create-stack \
    --stack-name gmsaADstack \
    --template-body file://cloudformation/aws_managed_ad_cloudformation.yaml \
    --parameters \
        ParameterKey=DirectoryNameParameter,ParameterValue=gMSA-demo-DirectoryName \
        ParameterKey=ShortName,ParameterValue="$AD_DIRECTORY_SHORT_NAME" \
        ParameterKey=Subnets,ParameterValue="\"$SUBNETS\"" \
        ParameterKey=VpcId,ParameterValue="$VPC_ID" \
    --region $REGION

# Wait for AD creation (takes ~20 minutes)
echo "Creating AWS Managed AD... This will take approximately 20 minutes."
aws cloudformation wait stack-create-complete --stack-name gmsaADstack --region $REGION

# Get AD DNS IP addresses
DNS_IPS=$(aws cloudformation describe-stacks \
    --stack-name gmsaADstack \
    --query "Stacks[0].Outputs[?OutputKey=='DnsIpAddresses'].OutputValue" \
    --output text \
    --region $REGION)

# Store DNS IPs in SSM
aws ssm put-parameter \
    --name "gMSA-demo-AD-dnsIPAddresses" \
    --value "$DNS_IPS" \
    --type "String" \
    --region $REGION

echo "AWS Managed AD created successfully!"
echo "DNS IP Addresses: $DNS_IPS"
```

## Step 5: Verify Deployment

```bash
# Check stacks are created successfully
echo "Checking CloudFormation stacks..."
aws cloudformation describe-stacks --stack-name cmkstack --query "Stacks[0].StackStatus" --output text --region $REGION
aws cloudformation describe-stacks --stack-name gmsaADstack --query "Stacks[0].StackStatus" --output text --region $REGION

# Display AD information
echo "AWS Managed AD Details:"
echo "Domain Name: $AD_DIRECTORY_NAME"
echo "NetBIOS Name: $AD_DIRECTORY_SHORT_NAME"
echo "DNS IP Addresses: $DNS_IPS"
echo "Admin Username: Admin" # Default user created by AWS Managed AD
echo "Directory ID: $(aws ds describe-directories --query 'DirectoryDescriptions[?Name==`'$AD_DIRECTORY_NAME'`].DirectoryId' --output text --region $REGION)"
```

## Next Steps

After completing this setup:

1. **Create gMSA accounts** in Active Directory (can be done via AWS Directory Service APIs or a separate Windows management instance)
2. **Store gMSA credentials** in AWS Secrets Manager for your applications to use
3. **Configure EKS applications** to retrieve gMSA credentials from Secrets Manager
4. **Deploy gMSA-enabled Linux applications** on your EKS cluster

**Note**: For Linux gMSA integration, you don't need to domain-join EKS nodes. Applications retrieve credentials via AWS Secrets Manager.

## Cleanup

To remove all resources created by this setup:

```bash
# Delete CloudFormation stacks
aws cloudformation delete-stack --stack-name gmsaADstack --region $REGION
aws cloudformation delete-stack --stack-name cmkstack --region $REGION

# Delete SSM parameters
aws ssm delete-parameter --name "gMSA-demo-DirectoryName" --region $REGION
aws ssm delete-parameter --name "gMSA-demo-ADUserPassword" --region $REGION
aws ssm delete-parameter --name "gMSA-demo-AD-dnsIPAddresses" --region $REGION

# Delete IAM policy
aws iam delete-policy --policy-arn "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/cmk-decrypt"
```

## Troubleshooting

- **Stack creation fails**: Check CloudFormation events for detailed error messages
- **AD creation timeout**: AWS Managed AD creation can take up to 45 minutes
- **DNS resolution issues**: Ensure subnets have proper route tables and security groups
- **SSM document execution fails**: Verify IAM permissions and parameter values

For additional support, refer to the [AWS Managed Microsoft AD documentation](https://docs.aws.amazon.com/directoryservice/latest/admin-guide/directory_microsoft_ad.html).