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

## Step 2: Create EKS Cluster

### Create the cluster with Linux nodes (using existing VPC)
```bash
eksctl create cluster \
  --name gmsa-eks \
  --region ap-southeast-1 \
  --with-oidc \
  --ssh-access \
  --ssh-public-key sandbox-sg-pem \
  --vpc-private-subnets subnet-05e7df1325d2227f5,subnet-04c89c31213a7cec0 \
  --node-private-networking \
  --managed
```

## Step 3: Add Windows Node Group

```bash
eksctl create nodegroup \
  --cluster gmsa-eks \
  --region ap-southeast-1 \
  --name windows-nodes \
  --node-type m5.large \
  --nodes 2 \
  --subnets subnet-05e7df1325d2227f5,subnet-04c89c31213a7cec0 \
  --node-ami-family WindowsServer2019FullContainer
```

**Note:** Windows nodes are placed in private subnets across two AZs for security and availability.

## Step 4: Configure kubectl

```bash
aws eks update-kubeconfig --region ap-southeast-1 --name gmsa-workshop
```

## Step 5: Verify Cluster Setup

```bash
# Check cluster status
kubectl get nodes

# Verify both Linux and Windows nodes are present
kubectl get nodes -o wide
```

You should see both Linux and Windows nodes in the output.

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
eksctl delete cluster --name gmsa-workshop --region ap-southeast-1
```

## Troubleshooting

* If cluster creation fails, check your AWS permissions and quotas
* Ensure your AWS CLI is configured with the correct region
* Windows nodes may take longer to join the cluster than Linux nodes