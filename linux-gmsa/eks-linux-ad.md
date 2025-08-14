# Active Directory Integration for Linux ASP.NET Core on EKS

This guide demonstrates how to deploy AD-aware ASP.NET Core applications on Linux containers using gMSA credentials stored in AWS Secrets Manager.

## Prerequisites

- Completed the basic EKS setup from [readme.md](./readme.md)
- AWS Managed Microsoft AD accessible from EKS cluster. Follow [managed-ad-setup.md](./managed-ad-setup.md) if you need to create a new Active Directory Domain.
- gMSA permissions are pre-configured with your AWS Managed Microsoft AD (KDS root key generation not required)
- A domain-joined Windows instance to run Active Directory management commands
- AWS Secrets Manager access configured

## Configuration Variables

Set these variables before running the setup commands:

```bash
# Required - Replace with your values
export AD_DOMAIN_NAME="sandbox.aws.corp.com"  # Your AD domain name
export AD_NETBIOS_NAME="sandbox"              # Your AD NetBIOS name
export GMSA_SERVICE_ACCOUNT="eks-gmsa-svc"    # gMSA service account name
export GMSA_USER_ACCOUNT="eks-svc-user"       # Service user account name
export GMSA_USER_PASSWORD="YourSecurePassword123!"  # Service user password
export REGION="ap-southeast-1"                # AWS region

# Optional - Modify if needed
export GMSA_GROUP_NAME="EKS-gMSA-Users"        # AD group for gMSA access
export GMSA_GROUP_SAM="EKSgMSAUsers"           # AD group SAM account name
export SECRET_NAME="eks-gmsa-credentials"      # AWS Secrets Manager secret name
```

## Understanding gMSA for Linux Containers

For **Linux containers**, gMSA integration works differently than Windows containers:

- **Linux containers cannot domain-join** - They can't natively retrieve gMSA passwords from Active Directory
- **A regular user account acts as a "proxy"** - It has permission to retrieve the gMSA password on behalf of the Linux application
- **The gMSA account is still password-free** - Active Directory automatically manages its password rotation

**Authentication Flow:**
```
Linux Container → AWS Secrets Manager → Regular User Credentials → AD → gMSA Password → Application Uses gMSA Identity
```

**What each account does:**
- `eks-gmsa-svc` (gMSA): The actual service identity your application uses for AD operations (password-free, auto-rotated)
- `eks-svc-user` (regular user): A "retrieval account" that can fetch the gMSA password from Active Directory
- AD Group: Controls which accounts can retrieve the gMSA password

## Step 1: Create gMSA Account in Active Directory

> **Note:** The following PowerShell commands must be run on a domain-joined Windows instance with Active Directory PowerShell module installed.

> **Optional:** If you need to provision a directory management EC2 instance, you can use the AWS SSM document:
> ```bash
> # Get your Directory ID (replace with your actual directory ID)
> DIRECTORY_ID=$(aws ds describe-directories --query 'DirectoryDescriptions[0].DirectoryId' --output text --region $REGION)
> 
> # Create directory management instance
> aws ssm start-automation-execution \
>     --document-name "AWS-CreateDSManagementInstance" \
>     --document-version "\$DEFAULT" \
>     --parameters '{
>         "DirectoryId":["'$DIRECTORY_ID'"],
>         "KeyPairName":["NoKeyPair"],
>         "IamInstanceProfileName":["AmazonSSMDirectoryServiceInstanceProfileRole"],
>         "SecurityGroupName":["AmazonSSMDirectoryServiceSecurityGroup"],
>         "AmiId":["{{ssm:/aws/service/ami-windows-latest/Windows_Server-2019-English-Full-Base}}"],
>         "InstanceType":["t3.medium"],
>         "MetadataOptions":["{\"HttpEndpoint\":\"enabled\",\"HttpTokens\":\"optional\"}"]}
>     }' \
>     --region $REGION
> ```

### 1.1 Create gMSA and Service Account
```powershell
# Set PowerShell variables (replace with your values)
$AD_DOMAIN_NAME = "sandbox.aws.corp.com"
$AD_NETBIOS_NAME = "sandbox"
$GMSA_SERVICE_ACCOUNT = "eks-gmsa-svc"
$GMSA_USER_ACCOUNT = "eks-svc-user"
$GMSA_USER_PASSWORD = "YourSecurePassword123!"
$GMSA_GROUP_NAME = "EKS-gMSA-Users"
$GMSA_GROUP_SAM = "EKSgMSAUsers"

# Create AD group for gMSA access
New-ADGroup -Name $GMSA_GROUP_NAME -SamAccountName $GMSA_GROUP_SAM -GroupScope DomainLocal

# Create gMSA account
New-ADServiceAccount -Name $GMSA_SERVICE_ACCOUNT -DnsHostName "$GMSA_SERVICE_ACCOUNT.$AD_DOMAIN_NAME" -ServicePrincipalNames "$AD_NETBIOS_NAME/$GMSA_SERVICE_ACCOUNT", "$AD_NETBIOS_NAME/$GMSA_SERVICE_ACCOUNT.$AD_DOMAIN_NAME" -PrincipalsAllowedToRetrieveManagedPassword $GMSA_GROUP_SAM

# Create service user for gMSA retrieval
New-ADUser -Name $GMSA_USER_ACCOUNT -AccountPassword (ConvertTo-SecureString -AsPlainText $GMSA_USER_PASSWORD -Force) -Enabled $true

# Add service user to gMSA group
Add-ADGroupMember -Identity $GMSA_GROUP_SAM -Members $GMSA_USER_ACCOUNT
```

### 1.2 Validate the Setup
```powershell
# Verify gMSA account was created
Get-ADServiceAccount -Identity $GMSA_SERVICE_ACCOUNT

# Verify regular user account was created
Get-ADUser -Identity $GMSA_USER_ACCOUNT

# Verify AD group was created and contains the user
Get-ADGroupMember -Identity $GMSA_GROUP_SAM

# Verify gMSA permissions (shows which principals can retrieve the password)
Get-ADServiceAccount -Identity $GMSA_SERVICE_ACCOUNT -Properties PrincipalsAllowedToRetrieveManagedPassword
```

**Expected Output:**
```
DistinguishedName                          : CN=eks-gmsa-svc,CN=Managed Service
                                             Accounts,DC=sandbox,DC=aws,DC=corp,DC=com
Enabled                                    : True
Name                                       : eks-gmsa-svc
ObjectClass                                : msDS-GroupManagedServiceAccount
ObjectGUID                                 : b0c28776-61a3-4488-8d72-fd28c89c5fe3
PrincipalsAllowedToRetrieveManagedPassword : {CN=EKS-gMSA-Users,OU=Users,OU=sandbox,DC=sandbox,DC=aws,DC=corp,DC=com}
SamAccountName                             : eks-gmsa-svc$
SID                                        : S-1-5-21-1485181390-1510379540-1491249750-1148
UserPrincipalName                          :
```

**Key validation points:**
- ✅ `Enabled: True` - gMSA account is active
- ✅ `ObjectClass: msDS-GroupManagedServiceAccount` - Confirms it's a gMSA
- ✅ `PrincipalsAllowedToRetrieveManagedPassword` contains your AD group
- ✅ `SamAccountName` ends with `$` (indicates service account)

> **Side Note:** If you are not using AWS Managed Microsoft AD, you will need to create a KDS root key before creating gMSA accounts:
> ```powershell
> # Check if KDS root key exists
> Get-KdsRootKey
> 
> # If no key exists, create one
> Add-KdsRootKey -EffectiveImmediately
> ```

## Step 2: Store gMSA Credentials in AWS Secrets Manager

> **Note:** The following commands should be run on your Linux instance (not the Windows domain management instance). Switch back to your Linux environment where you have AWS CLI configured.

**Set the environment variables on your Linux instance:**
```bash
# Set the same variables from the Configuration Variables section
export AD_DOMAIN_NAME="sandbox.aws.corp.com"
export AD_NETBIOS_NAME="sandbox"
export GMSA_SERVICE_ACCOUNT="eks-gmsa-svc"
export GMSA_USER_ACCOUNT="eks-svc-user"
export GMSA_USER_PASSWORD="YourSecurePassword123!"
export REGION="ap-southeast-1"
export GMSA_GROUP_NAME="EKS-gMSA-Users"
export GMSA_GROUP_SAM="EKSgMSAUsers"
export SECRET_NAME="eks-gmsa-credentials"
export CLUSTER_NAME="linux-aspnet-demo"  # EKS cluster name
```

### 2.1 Create the secret
```bash
# Create secret with gMSA credentials
aws secretsmanager create-secret \
    --name "$SECRET_NAME" \
    --description "gMSA credentials for EKS Linux containers" \
    --secret-string '{
        "username": "'$GMSA_USER_ACCOUNT'@'$AD_DOMAIN_NAME'",
        "password": "'$GMSA_USER_PASSWORD'",
        "domain": "'$AD_DOMAIN_NAME'",
        "gmsaAccount": "'$GMSA_SERVICE_ACCOUNT'$"
    }' \
    --region $REGION
```

### 2.2 Create IAM policy for secret access
```bash
cat > /tmp/gmsa-secret-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "secretsmanager:GetSecretValue"
            ],
            "Resource": "arn:aws:secretsmanager:$REGION:*:secret:$SECRET_NAME*"
        }
    ]
}
EOF

# Create IAM policy
aws iam create-policy \
    --policy-name EKS-gMSA-SecretsManager-Policy \
    --policy-document file:///tmp/gmsa-secret-policy.json

# Clean up temporary file
rm /tmp/gmsa-secret-policy.json
```

## Step 3: Create Service Account with IAM Role

### 3.1 Create IAM role for service account
```bash
# Get OIDC issuer URL
OIDC_ISSUER=$(aws eks describe-cluster --name $CLUSTER_NAME --region $REGION --query "cluster.identity.oidc.issuer" --output text)

# Create trust policy
cat > /tmp/trust-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):oidc-provider/${OIDC_ISSUER#https://}"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "${OIDC_ISSUER#https://}:sub": "system:serviceaccount:default:gmsa-service-account",
                    "${OIDC_ISSUER#https://}:aud": "sts.amazonaws.com"
                }
            }
        }
    ]
}
EOF

# Create IAM role
aws iam create-role \
    --role-name EKS-gMSA-Role \
    --assume-role-policy-document file:///tmp/trust-policy.json

# Attach policy to role
aws iam attach-role-policy \
    --role-name EKS-gMSA-Role \
    --policy-arn arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/EKS-gMSA-SecretsManager-Policy

# Clean up temporary file
rm /tmp/trust-policy.json
```

### 3.2 Create Kubernetes service account
```bash
kubectl create serviceaccount gmsa-service-account

kubectl annotate serviceaccount gmsa-service-account \
    eks.amazonaws.com/role-arn=arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/EKS-gMSA-Role
```

### 3.3 Validate the setup
```bash
# Verify service account was created
kubectl get serviceaccount gmsa-service-account

# Verify IAM role annotation
kubectl describe serviceaccount gmsa-service-account

# Verify IAM role exists
aws iam get-role --role-name EKS-gMSA-Role --region $REGION
```

## Step 4: Deploy AD-Aware ASP.NET Application

### 4.1 Understanding the Application Configuration

Before deploying, it's important to understand how the application securely retrieves gMSA credentials:

**Credentials are NOT hardcoded** in the YAML file. Instead, they're retrieved dynamically at runtime through this secure flow:

1. **Environment Variables** (in YAML):
   ```yaml
   env:
   - name: AWS_REGION
     value: "ap-southeast-1"
   - name: SECRET_NAME
     value: "eks-gmsa-credentials"
   ```

2. **Service Account with IAM Role** (links to Step 3):
   ```yaml
   serviceAccountName: gmsa-service-account
   ```

3. **Runtime Credential Retrieval** (application code):
   ```csharp
   // Gets secret name from environment variable
   var secretName = Environment.GetEnvironmentVariable("SECRET_NAME");
   
   // Uses AWS SDK to retrieve secret from Secrets Manager
   var response = await secretsManager.GetSecretValueAsync(request);
   
   // Parses JSON secret containing gMSA credentials
   var secret = JsonSerializer.Deserialize<Dictionary<string, string>>(response.SecretString);
   var username = secret["username"];     // eks-svc-user@sandbox.aws.corp.com
   var gmsaAccount = secret["gmsaAccount"]; // eks-gmsa-svc$
   ```

**Security Flow:**
```
Pod starts → Uses service account → Assumes IAM role → Calls Secrets Manager → Gets gMSA credentials → Uses them for AD operations
```

**Why this approach is secure:**
- ✅ No credentials stored in code or YAML files
- ✅ Only authorized pods can access the secret
- ✅ AWS handles encryption and access control
- ✅ Credentials can be rotated without code changes

### 4.2 Deploy the application
```bash
# Deploy the ASP.NET application with gMSA integration
kubectl apply -f aspnet-ad-app.yaml
```

> **Note:** If you encounter a `CrashLoopBackOff` with `/app/Program.cs: No such file or directory` error, the deployment has been updated to fix this issue. Simply redeploy:
> ```bash
> kubectl delete -f aspnet-ad-app.yaml
> kubectl apply -f aspnet-ad-app.yaml
> ```

## Step 5: Verify AD Integration

### 5.1 Check deployment status
```bash
# Check pods
kubectl get pods -l app=aspnet-ad-app

# Check service and LoadBalancer status
kubectl get service aspnet-ad-service

# Wait for LoadBalancer to get external IP (may take 2-3 minutes)
kubectl get service aspnet-ad-service -w

# Check if LoadBalancer is ready (should show EXTERNAL-IP, not <pending>)
kubectl get service aspnet-ad-service -o wide

```

### 5.2 Test the application
```bash
# Get external URL
AD_APP_URL=$(kubectl get service aspnet-ad-service -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')

# Test the application
curl -I http://$AD_APP_URL

# View in browser
echo "AD Integration Demo URL: http://$AD_APP_URL"
```

### 5.3 Verify gMSA functionality
```bash
# Check application logs (no output from grep is expected - this means no errors occurred)
kubectl logs -l app=aspnet-ad-app | grep -i "secret\|credential\|error"

# Better verification: Check if application is responding successfully
kubectl logs -l app=aspnet-ad-app --tail=10

# Verify the web application is working by checking HTTP response
AD_APP_URL=$(kubectl get service aspnet-ad-service -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
curl -s http://$AD_APP_URL | grep -i "SUCCESS.*retrieved.*credentials"

# Test LDAP connectivity (if configured)
kubectl exec -it $(kubectl get pod -l app=aspnet-ad-app -o jsonpath='{.items[0].metadata.name}') -- /bin/bash
```

> **Note:** If the grep command returns nothing, that's **good news** - it means no errors occurred during credential retrieval. The AWS SDK handles authentication silently for security reasons.

## Step 6: Test LDAP Operations

The application also includes a real LDAP query endpoint that demonstrates Active Directory integration:

### 6.1 Test the LDAP functionality
```bash
# Get the application URL
AD_APP_URL=$(kubectl get service aspnet-ad-service -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')

# Test the LDAP query endpoint
curl -s http://$AD_APP_URL/ldap | grep -i "computers found\|not found\|access denied\|error"

# Or visit in browser
echo "LDAP Query URL: http://$AD_APP_URL/ldap"
```

### 6.2 What the LDAP query does

The `/ldap` endpoint performs the following operations:

1. **Retrieves gMSA credentials** from AWS Secrets Manager
2. **Connects to Active Directory** using the service user credentials
3. **Queries the "Domain Computers" group** using LDAP filter: `(&(objectClass=group)(cn=Domain Computers))`
4. **Counts the members** in the group
5. **Handles errors gracefully**:
   - **Access denied**: Insufficient permissions
   - **Group not found**: "Domain Computers" group doesn't exist
   - **Connection errors**: Network or authentication issues
   - **Unexpected errors**: Any other exceptions

### 6.3 Expected results

- **Success**: "Successfully queried 'Domain Computers' group: X computers found"
- **Not found**: "Group 'Domain Computers' not found in Active Directory"
- **Access denied**: "Access denied: Insufficient permissions to query Active Directory"
- **Error**: Detailed error message for troubleshooting

## Current Status

✅ **gMSA Account**: Created in Active Directory  
✅ **AWS Secrets Manager**: Storing gMSA credentials securely  
✅ **IAM Integration**: Service account with proper permissions  
✅ **AD-Aware App**: ASP.NET Core app using gMSA credentials  
✅ **Linux Containers**: Running on EKS with AD integration  
✅ **LDAP Operations**: Real Active Directory queries working  

## Troubleshooting

### Common Issues

1. **Secret Access Denied**: Check IAM role and policy attachments
2. **gMSA Authentication Failed**: Verify AD group membership and permissions
3. **Pod Startup Issues**: Check container logs and resource limits
4. **Network Connectivity**: Ensure EKS can reach AD domain controllers

### Useful Commands

```bash
# Check service account annotations
kubectl describe serviceaccount gmsa-service-account

# Verify IAM role assumption
kubectl logs -l app=aspnet-ad-app | grep -i "assume\|role\|token"

# Test secret access
aws secretsmanager get-secret-value --secret-id eks-gmsa-credentials --region $REGION

# Check AD connectivity from pod
kubectl exec -it $(kubectl get pod -l app=aspnet-ad-app -o jsonpath='{.items[0].metadata.name}') -- nslookup yourdomain.com
```

## Cleanup

```bash
# Delete AD application
kubectl delete -f aspnet-ad-app.yaml

# Delete service account
kubectl delete serviceaccount gmsa-service-account

# Delete IAM resources
aws iam detach-role-policy --role-name EKS-gMSA-Role --policy-arn arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/EKS-gMSA-SecretsManager-Policy
aws iam delete-role --role-name EKS-gMSA-Role
aws iam delete-policy --policy-arn arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/EKS-gMSA-SecretsManager-Policy

# Delete secret
aws secretsmanager delete-secret --secret-id eks-gmsa-credentials --region $REGION
```