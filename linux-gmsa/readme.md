# Linux-based ASP.NET Core Authentication Demo for Amazon EKS

This guide demonstrates how to deploy ASP.NET Core applications on Amazon EKS using Linux containers, providing a foundation for Active Directory integration scenarios.

## Overview

This workshop covers:
1. Creating an EKS cluster with Linux worker nodes
2. Deploying a sample ASP.NET Core application
3. Setting up infrastructure for AD-aware applications (future steps)

## Prerequisites

* AWS CLI configured with appropriate permissions
* An AWS key pair for SSH access to nodes

## Step 1: Install Required Tools

### Install kubectl (Kubernetes command-line tool)
```bash
# Detect architecture and download correct kubectl binary
ARCH=$(uname -m)
if [ "$ARCH" = "aarch64" ]; then
    KUBECTL_ARCH="arm64"
else
    KUBECTL_ARCH="amd64"
fi

curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/${KUBECTL_ARCH}/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/
```

### Install eksctl (EKS cluster management tool)
```bash
# Detect architecture and download correct eksctl binary
ARCH=$(uname -m)
if [ "$ARCH" = "aarch64" ]; then
    EKSCTL_ARCH="arm64"
else
    EKSCTL_ARCH="amd64"
fi

curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_${EKSCTL_ARCH}.tar.gz" | tar xz -C /tmp
sudo mv /tmp/eksctl /usr/local/bin
```

### Verify installations
```bash
kubectl version --client
eksctl version
```

## Step 2: Set Configuration Parameters

```bash
##### ACTION REQUIRED - START #####
REGION="ap-southeast-1" # AWS region where cluster will be created
SSH_KEY="sandbox-sg-pem" # Your existing AWS key pair name
PRIVATE_SUBNETS="subnet-05e7df1325d2227f5,subnet-04c89c31213a7cec0" # Private subnet IDs (comma separated)
##### ACTION REQUIRED - END #####

##### DEFAULT VALUES - START #####
CLUSTER_NAME="linux-aspnet-demo" # EKS cluster name
LINUX_NODE_TYPE="m5.large" # Linux node instance type
LINUX_NODE_COUNT="2" # Number of Linux nodes
##### DEFAULT VALUES - END #####
```

## Step 3: Create EKS Cluster with Linux Nodes

### Create the cluster (using existing VPC)
```bash
eksctl create cluster \
  --name $CLUSTER_NAME \
  --region $REGION \
  --with-oidc \
  --ssh-access \
  --ssh-public-key $SSH_KEY \
  --vpc-private-subnets $PRIVATE_SUBNETS \
  --node-private-networking \
  --node-type $LINUX_NODE_TYPE \
  --nodes $LINUX_NODE_COUNT
```

### Configure kubectl
```bash
aws eks update-kubeconfig --region $REGION --name $CLUSTER_NAME
```

### Verify cluster setup
```bash
# Check cluster status
kubectl get nodes

# Verify Linux nodes are present
kubectl get nodes -o wide

# Check Kubernetes version
kubectl version
```

## Step 4: Deploy Sample ASP.NET Core Application

### Create the application deployment
Create file `aspnet-helloworld.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aspnet-helloworld
  namespace: default
spec:
  replicas: 2
  selector:
    matchLabels:
      app: aspnet-helloworld
  template:
    metadata:
      labels:
        app: aspnet-helloworld
    spec:
      containers:
      - name: aspnet-app
        image: mcr.microsoft.com/dotnet/samples:aspnetapp
        ports:
        - containerPort: 8080
        env:
        - name: ASPNETCORE_URLS
          value: "http://+:8080"
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "200m"
      nodeSelector:
        kubernetes.io/os: linux
---
apiVersion: v1
kind: Service
metadata:
  name: aspnet-helloworld-service
  namespace: default
spec:
  selector:
    app: aspnet-helloworld
  ports:
  - port: 80
    targetPort: 8080
    protocol: TCP
  type: LoadBalancer
```

### Deploy the application
```bash
kubectl apply -f aspnet-helloworld.yaml
```

### Verify deployment
```bash
# Check deployment status
kubectl get deployments

# Check pods
kubectl get pods -o wide

# Check service and get external URL
kubectl get services

# Wait for LoadBalancer to be ready
kubectl get service aspnet-helloworld-service --watch
```

### Test the application
```bash
# Get the external URL
EXTERNAL_URL=$(kubectl get service aspnet-helloworld-service -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')

# Test the application
curl -I http://$EXTERNAL_URL

# View the application in browser
echo "Application URL: http://$EXTERNAL_URL"
```

## Step 5: Verify Application Details

### Check application information
```bash
# Get detailed pod information
kubectl describe pods -l app=aspnet-helloworld

# Check application logs
kubectl logs -l app=aspnet-helloworld

# Access application details
curl -s http://$EXTERNAL_URL | grep -E "(\.NET|Operating system|Architecture)"
```

## Current Status

✅ **EKS Cluster**: Running with Linux worker nodes  
✅ **ASP.NET Core App**: Deployed and accessible via LoadBalancer  
✅ **Container Runtime**: .NET running on Alpine Linux  
✅ **Networking**: VPC CNI with proper IP allocation  

## Next Steps

The infrastructure is now ready for:

1. **[AD Integration Setup](./eks-linux-ad.md)**: Deploy AD-aware ASP.NET applications with gMSA
2. **Authentication Services**: Implement LDAP operations and directory queries
3. **Security Configuration**: Implement proper RBAC and network policies
4. **Monitoring**: Add logging and monitoring solutions

### Continue with AD Integration

Once your basic ASP.NET application is running, proceed to [eks-linux-ad.md](./eks-linux-ad.md) to:
- Configure gMSA accounts in Active Directory
- Store credentials securely in AWS Secrets Manager
- Deploy AD-aware applications using Linux containers
- Test authentication and directory operations

## Cleanup

When finished, clean up resources:

```bash
# Delete the application
kubectl delete -f aspnet-helloworld.yaml

# Delete the cluster
eksctl delete cluster --name $CLUSTER_NAME --region $REGION
```

## Troubleshooting

### Common Issues

1. **Cluster Creation Fails**: Check AWS permissions and quotas
2. **Pods Not Starting**: Verify node resources and image availability
3. **LoadBalancer Not Ready**: Wait 2-3 minutes for AWS ELB provisioning
4. **Application Not Accessible**: Check security groups and VPC configuration

### Useful Commands

```bash
# Check cluster info
kubectl cluster-info

# Check node resources
kubectl top nodes

# Check pod resources
kubectl top pods

# Describe problematic pods
kubectl describe pod <pod-name>

# Check events
kubectl get events --sort-by=.metadata.creationTimestamp
```