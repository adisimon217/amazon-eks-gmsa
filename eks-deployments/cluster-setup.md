# EKS Cluster Setup for gMSA Workshop

This guide covers the prerequisite step of creating an EKS cluster with Windows support before following the main gMSA workshop.

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
CLUSTER_NAME="gmsa-eks" # EKS cluster name
WINDOWS_NODE_TYPE="m5.large" # Windows node instance type
WINDOWS_NODE_COUNT="2" # Number of Windows nodes
WINDOWS_AMI_FAMILY="WindowsServer2019FullContainer" # Windows AMI family
##### DEFAULT VALUES - END #####
```

## Step 3: Create EKS Cluster

### Create the cluster with Linux nodes (using existing VPC)
```bash
eksctl create cluster \
  --name $CLUSTER_NAME \
  --region $REGION \
  --with-oidc \
  --ssh-access \
  --ssh-public-key $SSH_KEY \
  --vpc-private-subnets $PRIVATE_SUBNETS \
  --node-private-networking
```

**Note:** Using unmanaged node groups (no `--managed` flag) to create AutoScaling Groups for easier domain joining.

**OPTIONAL: To upgrade cluster later:**
```bash
# Check available versions
eksctl get cluster --name $CLUSTER_NAME --region $REGION

# Upgrade to specific version
eksctl upgrade cluster --name $CLUSTER_NAME --region $REGION --version 1.33
```

## Step 4: Add Windows Node Group

```bash
eksctl create nodegroup \
  --cluster $CLUSTER_NAME \
  --region $REGION \
  --name windows-nodes \
  --node-type $WINDOWS_NODE_TYPE \
  --nodes $WINDOWS_NODE_COUNT \
  --subnet-ids $PRIVATE_SUBNETS \
  --node-private-networking \
  --node-ami-family $WINDOWS_AMI_FAMILY
```

**Note:** Windows nodes are placed in private subnets across two AZs for security and availability.

## Step 5: Configure kubectl

```bash
aws eks update-kubeconfig --region $REGION --name $CLUSTER_NAME
```

## Step 6: Verify Cluster Setup

```bash
# Check cluster status
kubectl get nodes

# Verify both Linux and Windows nodes are present
kubectl get nodes -o wide

# Check Kubernetes version
kubectl version
```

You should see both Linux and Windows nodes in the output.

## Step 7: gMSA Feature Gates (Optional)

**For Kubernetes 1.18+**: gMSA is GA and enabled by default - no feature gates needed.

**For older versions only**: If your cluster runs Kubernetes < 1.18, you would need to enable feature gates by modifying the kubelet configuration on Windows nodes:

```bash
# This is only needed for Kubernetes < 1.18
# Add to kubelet configuration on Windows nodes:
# --feature-gates=WindowsGMSA=true
```

**Check if feature gates are needed:**
```bash
# If server version is 1.18+, you're good to go
kubectl version | grep "Server Version"
```

## Next Steps

Once your cluster is ready, proceed with the main workshop:

1. **Infrastructure Setup** - Follow [cloud-formation-templates/README.md](./cloud-formation-templates/README.md)
2. **Windows Workers Configuration** - Follow the main [README.md](./README.md) starting from step 2
3. **EKS Deployment** - Deploy Kubernetes resources
4. **Sample Applications** - Deploy and test applications

## Cleanup

When you're done with the workshop, clean up resources:

```bash
# Delete the cluster (this will delete all node groups too)
eksctl delete cluster --name $CLUSTER_NAME --region $REGION
```

## Troubleshooting

* If cluster creation fails, check your AWS permissions and quotas
* Ensure your AWS CLI is configured with the correct region
* Windows nodes may take longer to join the cluster than Linux nodes