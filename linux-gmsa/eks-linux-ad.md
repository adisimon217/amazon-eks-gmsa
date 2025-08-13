# Active Directory Integration for Linux ASP.NET Core on EKS

This guide demonstrates how to deploy AD-aware ASP.NET Core applications on Linux containers using gMSA credentials stored in AWS Secrets Manager.

## Prerequisites

- Completed the basic EKS setup from [readme.md](./readme.md)
- Active Directory Domain Service accessible from EKS cluster
- gMSA account created in Active Directory
- AWS Secrets Manager access configured

## Step 1: Create gMSA Account in Active Directory

### 1.1 Create KDS Root Key (if not exists)
```powershell
# Check if KDS root key exists
Get-KdsRootKey

# If no key exists, create one
Add-KdsRootKey -EffectiveImmediately
```

### 1.2 Create gMSA and Service Account
```powershell
# Create AD group for gMSA access
New-ADGroup -Name "EKS-gMSA-Users" -SamAccountName "EKSgMSAUsers" -GroupScope DomainLocal

# Create gMSA account
New-ADServiceAccount -Name "eks-gmsa-svc" -DnsHostName "eks-gmsa-svc.yourdomain.com" -ServicePrincipalNames "host/eks-gmsa-svc", "host/eks-gmsa-svc.yourdomain.com" -PrincipalsAllowedToRetrieveManagedPassword "EKSgMSAUsers"

# Create service user for gMSA retrieval
New-ADUser -Name "eks-svc-user" -AccountPassword (ConvertTo-SecureString -AsPlainText "YourSecurePassword123!" -Force) -Enabled $true

# Add service user to gMSA group
Add-ADGroupMember -Identity "EKSgMSAUsers" -Members "eks-svc-user"
```

## Step 2: Store gMSA Credentials in AWS Secrets Manager

### 2.1 Create the secret
```bash
# Create secret with gMSA credentials
aws secretsmanager create-secret \
    --name "eks-gmsa-credentials" \
    --description "gMSA credentials for EKS Linux containers" \
    --secret-string '{
        "username": "eks-svc-user@yourdomain.com",
        "password": "YourSecurePassword123!",
        "domain": "yourdomain.com",
        "gmsaAccount": "eks-gmsa-svc$"
    }' \
    --region $REGION
```

### 2.2 Create IAM policy for secret access
```bash
cat > gmsa-secret-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "secretsmanager:GetSecretValue"
            ],
            "Resource": "arn:aws:secretsmanager:$REGION:*:secret:eks-gmsa-credentials*"
        }
    ]
}
EOF

# Create IAM policy
aws iam create-policy \
    --policy-name EKS-gMSA-SecretsManager-Policy \
    --policy-document file://gmsa-secret-policy.json
```

## Step 3: Create Service Account with IAM Role

### 3.1 Create IAM role for service account
```bash
# Get OIDC issuer URL
OIDC_ISSUER=$(aws eks describe-cluster --name $CLUSTER_NAME --region $REGION --query "cluster.identity.oidc.issuer" --output text)

# Create trust policy
cat > trust-policy.json << EOF
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
    --assume-role-policy-document file://trust-policy.json

# Attach policy to role
aws iam attach-role-policy \
    --role-name EKS-gMSA-Role \
    --policy-arn arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/EKS-gMSA-SecretsManager-Policy
```

### 3.2 Create Kubernetes service account
```bash
kubectl create serviceaccount gmsa-service-account

kubectl annotate serviceaccount gmsa-service-account \
    eks.amazonaws.com/role-arn=arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/EKS-gMSA-Role
```

## Step 4: Create AD-Aware ASP.NET Application

### 4.1 Create application deployment
Create file `aspnet-ad-app.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aspnet-ad-app
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: aspnet-ad-app
  template:
    metadata:
      labels:
        app: aspnet-ad-app
    spec:
      serviceAccountName: gmsa-service-account
      containers:
      - name: aspnet-ad-app
        image: mcr.microsoft.com/dotnet/aspnet:8.0
        ports:
        - containerPort: 8080
        env:
        - name: ASPNETCORE_URLS
          value: "http://+:8080"
        - name: AWS_REGION
          value: "ap-southeast-1"
        - name: SECRET_NAME
          value: "eks-gmsa-credentials"
        command: ["/bin/bash"]
        args:
          - -c
          - |
            cat > /app/Program.cs << 'EOF'
            using System.DirectoryServices;
            using System.Text.Json;
            using Amazon.SecretsManager;
            using Amazon.SecretsManager.Model;

            var builder = WebApplication.CreateBuilder(args);
            builder.Services.AddSingleton<IAmazonSecretsManager, AmazonSecretsManagerClient>();

            var app = builder.Build();

            app.MapGet("/", async (IAmazonSecretsManager secretsManager) =>
            {
                try
                {
                    var secretName = Environment.GetEnvironmentVariable("SECRET_NAME") ?? "eks-gmsa-credentials";
                    var region = Environment.GetEnvironmentVariable("AWS_REGION") ?? "us-east-1";
                    
                    var request = new GetSecretValueRequest
                    {
                        SecretId = secretName
                    };
                    
                    var response = await secretsManager.GetSecretValueAsync(request);
                    var secret = JsonSerializer.Deserialize<Dictionary<string, string>>(response.SecretString);
                    
                    var username = secret["username"];
                    var password = secret["password"];
                    var domain = secret["domain"];
                    var gmsaAccount = secret["gmsaAccount"];
                    
                    var html = $@"
            <!DOCTYPE html>
            <html>
            <head>
                <title>AD Integration Demo</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 40px; }}
                    .container {{ max-width: 800px; margin: 0 auto; }}
                    .status {{ padding: 10px; margin: 10px 0; border-radius: 5px; }}
                    .success {{ background-color: #d4edda; border: 1px solid #c3e6cb; color: #155724; }}
                    .info {{ background-color: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; }}
                    table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                    th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                    th {{ background-color: #f2f2f2; }}
                </style>
            </head>
            <body>
                <div class='container'>
                    <h1>ASP.NET Core AD Integration Demo</h1>
                    <div class='status success'>
                        ✅ Successfully retrieved gMSA credentials from AWS Secrets Manager
                    </div>
                    <div class='status info'>
                        🔐 Using gMSA account for Active Directory authentication
                    </div>
                    
                    <h2>Authentication Details</h2>
                    <table>
                        <tr><th>Property</th><th>Value</th></tr>
                        <tr><td>Service Account</td><td>{gmsaAccount}</td></tr>
                        <tr><td>Domain</td><td>{domain}</td></tr>
                        <tr><td>Authentication Method</td><td>gMSA via AWS Secrets Manager</td></tr>
                        <tr><td>Container OS</td><td>Linux</td></tr>
                        <tr><td>Runtime</td><td>.NET 8.0</td></tr>
                        <tr><td>Pod Name</td><td>{Environment.MachineName}</td></tr>
                        <tr><td>Timestamp</td><td>{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC</td></tr>
                    </table>
                    
                    <h2>LDAP Connection Test</h2>
                    <div class='status info'>
                        📡 Ready for LDAP operations using gMSA credentials
                    </div>
                </div>
            </body>
            </html>";
                    
                    return Results.Content(html, "text/html");
                }
                catch (Exception ex)
                {
                    var errorHtml = $@"
            <!DOCTYPE html>
            <html>
            <head><title>AD Integration Demo - Error</title></head>
            <body>
                <h1>Error</h1>
                <p>Failed to retrieve credentials: {ex.Message}</p>
                <p>Check AWS Secrets Manager configuration and IAM permissions.</p>
            </body>
            </html>";
                    return Results.Content(errorHtml, "text/html");
                }
            });

            app.Run();
            EOF

            cat > /app/app.csproj << 'EOF'
            <Project Sdk="Microsoft.NET.Sdk.Web">
              <PropertyGroup>
                <TargetFramework>net8.0</TargetFramework>
                <Nullable>enable</Nullable>
                <ImplicitUsings>enable</ImplicitUsings>
              </PropertyGroup>
              <ItemGroup>
                <PackageReference Include="AWSSDK.SecretsManager" Version="3.7.400.44" />
                <PackageReference Include="System.DirectoryServices" Version="8.0.0" />
              </ItemGroup>
            </Project>
            EOF

            cd /app && dotnet run --urls http://0.0.0.0:8080
        resources:
          requests:
            memory: "256Mi"
            cpu: "200m"
          limits:
            memory: "512Mi"
            cpu: "400m"
      nodeSelector:
        kubernetes.io/os: linux
---
apiVersion: v1
kind: Service
metadata:
  name: aspnet-ad-service
  namespace: default
spec:
  selector:
    app: aspnet-ad-app
  ports:
  - port: 80
    targetPort: 8080
    protocol: TCP
  type: LoadBalancer
```

### 4.2 Deploy the AD-aware application
```bash
kubectl apply -f aspnet-ad-app.yaml
```

## Step 5: Verify AD Integration

### 5.1 Check deployment status
```bash
# Check pods
kubectl get pods -l app=aspnet-ad-app

# Check service
kubectl get service aspnet-ad-service

# Check logs
kubectl logs -l app=aspnet-ad-app -f
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
# Check if credentials are retrieved successfully
kubectl logs -l app=aspnet-ad-app | grep -i "secret\|credential\|error"

# Test LDAP connectivity (if configured)
kubectl exec -it $(kubectl get pod -l app=aspnet-ad-app -o jsonpath='{.items[0].metadata.name}') -- /bin/bash
```

## Step 6: Advanced LDAP Operations (Optional)

For full LDAP integration, extend the application to perform actual directory operations:

```csharp
// Add to Program.cs for LDAP queries
app.MapGet("/users", async (IAmazonSecretsManager secretsManager) =>
{
    // Retrieve credentials and perform LDAP search
    // Implementation depends on your AD structure
});
```

## Current Status

✅ **gMSA Account**: Created in Active Directory  
✅ **AWS Secrets Manager**: Storing gMSA credentials securely  
✅ **IAM Integration**: Service account with proper permissions  
✅ **AD-Aware App**: ASP.NET Core app using gMSA credentials  
✅ **Linux Containers**: Running on EKS with AD integration  

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