Refer: https://aws.amazon.com/blogs/containers/domainless-windows-authentication-for-amazon-eks-windows-pods/
# Domainless Windows Authentication for Amazon EKS Windows pods
.NET Developers commonly design Windows-based applications with Active Directory (AD) integration running on domain-joined servers to facilitate authentication and authorization between services and users. Since containers cannot be domain-joined, running these applications in a Windows-based containers required configuring group Managed Service Accounts (gMSA), domain-joined Kubernetes Windows nodes, webhooks and cluster roles to enable Windows Authentication on Windows-based containers. This created additional management overhead such as AD computer account clean-up on each scaling event, as well as drastically increasing bootstrap time on each Windows node due to the domain-join process. That was, until now.

Starting in 2022, on Windows Server 2019 / 2022, Microsoft made the ICcgDomainAuthCredentials interface available, allowing developers to develop a plugin that enables non-domain-joined Windows nodes to retrieve gMSA credentials by replacing the domain-joined host approach with a portable user identity instead of a host computer account.

AWS developed its own plugin and, which is built-in in the Amazon Elastic Kubernetes Service (Amazon EKS) Optimized Windows AMI, resolving the scaling management overhead and simplifying the process of running Windows-based container workloads on Amazon EKS.

## Solution Overview
1. First, the Windows Pod references GMSACredentialSpec available in the windows.k8s.io/v1 API. Second, the gMSA validating webhook ensures the Windows pod has permission to reference GMSACredentialSpec. Finally, the mutating webhook expands GMSACredentialSpec to full JSON format in the pod.
2. The ccg.exe process running on the Windows node launches the plugin specified in the CredSpec in the PluginID field and then and retrieves the portable identity credentials from AWS Secrets Manager or AWS System Manager Parameter Store.
3. The ccg.exe uses the portable identity credentials to authenticate against the AWS Managed AD or Amazon Elastic Compute Cloud (Amazon EC2) self-managed AD to retrieve the gMSA password.
ccg.exe makes the gMSA password available to the Windows pod.
4. The Windows pod uses the gMSA password to authenticate against the AWS Managed AD or Amazon EC2 self-managed AD to get a Kerberos Ticket-Granting token (TGT).
5. Token is cached and application running as Network Service or Local System in the pod, which can authenticate and access domain resources (i.e., File shares, SQL Server databases, IIS Sites, etc.)

This article covers the required steps to configure this functionality for Windows pods running on non-domain-joined Windows worker nodes on Amazon EKS.

### Prerequisites and assumptions:
- You have an Amazon EKS cluster running version 1.22 or newer with Windows nodes.
- Self-managed or Managed Windows nodes based on the Amazon EKS Optimized Windows AMI.
- You have properly installed and configured AWS Command Line Interface (AWS CLI) and kubectl on Amazon EC2 Linux.
- You have an Active Directory Domain Service (AD DS) that’s accessible from the Amazon EKS cluster. This can either be a self-managed AD or AWS Managed Microsoft AD.
- Your Windows nodes running in the Amazon EKS cluster can resolve the AD domain FQDN.

Overview of the tasks we’ll cover in this article:
- Create an AD gMSA account, portable identity, and group.
- Deploy Windows gMSA Admission Webhook Controller in Amazon EKS cluster.
- Create a gMSA CredentialSpec resources and use AWS Secret Manager as a credential store.
- Create a Kubernetes ClusterRole and RoleBinding.
- Configure the gMSA CredentialSpec in the Windows pod specification.
- Test the Windows Authentication from inside the Windows pod.
- Logging locations.
- (Optional) Using AWS System Manager Parameter Store as a credential store.


## Walkthrough
### 1. Create and configure gMSA account on Active Directory Domain
If you have not already created a gMSA Service Account in your domain, you’ll need to first generate a Key Distribution Service (KDS) root key. The KDS is responsible for creating, rotating, and releasing the gMSA password to authorized hosts. When the ccg.exe needs to retrieve gMSA credentials, it contact KDS to retrieve the current password. 

**If you are using AWS Managed AD, then you can skip directly to step 2.3.** gMSA permissions are pre-configured with your AWS managed Microsoft AD. As a result, you are not required to generate KDS root key to generate the gMSA passwords.

1.1 To check if the KDS root key has already been created, run the following PowerShell cmdlet with domain admin privileges on a domain controller using the AD PowerShell module:

```powershell
Get-KdsRootKey
```

1.2 If the command returns a key ID, you’re all set. Otherwise, create the KDS root key by running the following command:

```powershell
Add-KdsRootKey -EffectiveImmediately
```

Although the command implies the key is effective immediately, you need to wait 10 hours before the KDS root key is replicated and available for use on all domain controllers. If you’re interesting in better understanding gMSA Accounts, then refer to the Microsoft official documentation.

1.3 To create the gMSA account and allow the ccg.exe to retrieve the gMSA password, run the following PowerShell commands from a Windows Server or Client with access to the AD domain.

```powershell
# Install the RSAT AD Feature
Install-WindowsFeature RSAT-AD-PowerShell

# Create the AD group - Replace Name and SamAccountName values with yours preference.
New-ADGroup -Name "Amazon EKS Authorized Portable Identity" -SamAccountName "EKSPortableIdentity" -GroupScope DomainLocal

# Create the gMSA - Replace Name value with yours preference
New-ADServiceAccount -Name "gmsaeks" -DnsHostName "gmsaeks.YOURDOMAIN_FQDN" -ServicePrincipalNames "host/gmsaeks", "host/gmsaeks.YOURDOMAIN_FQDN" -PrincipalsAllowedToRetrieveManagedPassword "EKSPortableIdentity"

# Create the portable identity user account - Replace Name value with yours preference
New-ADUser -Name "eks-portable-identity" -AccountPassword (ConvertTo-SecureString -AsPlainText "YOUR_PASSWORD" -Force) -Enabled 1 

# Add your Windows Worker Node the AD group
Add-ADGroupMember -Identity "EKSPortableIdentity" -Members "eks-portable-identity"
```

Note: Replace YOURDOMAIN_FQDN with your fully qualified domain name. Replace YOUR_PASSWORD with a unique password and store in a secret store to be retrieved by the CCG plugin.


### 2. Deploy Windows gMSA Admission Webhook Controller in Amazon EKS cluster
The [Windows gMSA](https://github.com/kubernetes-sigs/windows-gmsa) repository deploys two webhooks, as per the [Kubernetes documentation](https://kubernetes.io/docs/tasks/configure-pod-container/configure-gmsa/#install-webhooks-to-validate-gmsa-users), they are:

1. A mutating webhook that expands references to GMSAs (by name from a Pod specification) into the full CredentialSpec in JSON form within the Pod specification.
2. A validating webhook ensures all references to GMSAs are authorized to be used by the Pod service account.

According to the Amazon EKS [certificate signing](https://docs.aws.amazon.com/eks/latest/userguide/cert-signing.html) documentation, all clusters running Amazon EKS version 1.22 or newer support the signer beta.eks.amazonaws.com/app-serving for Kubernetes Certificate Signing Requests (CSR). As a result, we ‘ll replace the `kubernetes.io/kubelet-serving` signer in the gMSA admission webhook certificate file with the Amazon EKS supported `beta.eks.amazonaws.com/app-serving` signer.

2.1 From a Linux based system, run the following command. This deploys the gMSA Webhook Admission Controller and update the signer file.

```bash
git clone https://github.com/kubernetes-sigs/windows-gmsa.git
cd windows-gmsa/admission-webhook/deploy
sed -i.back "s/signerName: kubernetes.io\/kubelet-serving/signerName: beta.eks.amazonaws.com\/app-serving/g" create-signed-cert.sh
./deploy-gmsa-webhook.sh --file ./gmsa-manifests --overwrite
```

Note: Always check for the latest gMSA admission-webhook version on the [kubernetes-sigs/windows-gmsa](https://github.com/kubernetes-sigs/windows-gmsa/tree/master/admission-webhook).


### 3. Create gMSA CredentialSpec resources and use AWS Secret Manager as a credential store.
With the gMSA resources successfully deployed in the Amazon EKS cluster, along with the CredentialSpec CRD and gMSA webhooks to populate and validate the resource across the cluster, we‘ll now generate and deploy the gMSA CredentialSpec resource into the Amazon EKS cluster.

The gMSA CredentialSpec contains metadata that the `ccg.exe` process on the host node uses to determine which gMSA account to retrieve, the portable identity credentials, and the ID of the plugin to use. In this first example, we’ll use AWS Secrets Manager to store the portable identity credential.

3.1 First, let’s create an AWS Secret Manager to store the portable identity credential. Run the following AWS CLI command and replace the user, password, and domainName to match your environment and save the ARN to be used in step 4.2.

```bash
aws secretsmanager create-secret \
--name gmsa-plugin-input \
--description "Amazon EKS - gMSA Portable Identity." \
--secret-string "{\"username\":\"eks-portable-identity\",\"password\":\"YOURPASSWORD\",\"domainName\":\"YOURDOMAIN_FQDN\"}"
Note: Replace user with your portable identity credential. Replace YOUR_PASSWORD the portable identity password with the one you create in step 1.3. Replace YOURDOMAIN_FQDN with your fully qualified domain name.
```

Note: Replace user with your portable identity credential. Replace YOUR_PASSWORD the portable identity password with the one you create in step 1.3. Replace YOURDOMAIN_FQDN with your fully qualified domain name.

3.2 Add the following AWS Identity and Access Management (AWS IAM) in-line policy to the existing Windows node AWS IAM role. This AWS IAM policy allows the Windows nodes to read the secret created in the previous step.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "secretsmanager:GetSecretValue",
            "Resource": "ARN-SECRET"
        }
    ]
}
```

Note: Replace SECRET-ARN with your secret ARN created on the AWS Secret Manager.

3.3 Now, let’s create the gMSA CredentialSpec file and apply it to the Amazon EKS cluster. Create a file containing the code below and save it as domainless-credspec-secretmanager.yaml.

```yaml
apiVersion: windows.k8s.io/v1
kind: GMSACredentialSpec
metadata:
  name: gmsaeks-domainless
credspec:
  CmsPlugins:
  - ActiveDirectory
  DomainJoinConfig:
    Sid: gMSA-ACCOUNT-SID
    MachineAccountName: gMSA-ACCOUNT-NAME
    Guid: gMSA-ACCOUNT-GUID
    DnsTreeName: YOURDOMAIN_FQDN
    DnsName: YOURDOMAIN_FQDN
    NetBiosName: YOURDOMAIN_NETBIOS
  ActiveDirectoryConfig:
    GroupManagedServiceAccounts:
    - Name: gMSA-ACCOUNT-NAME
      Scope: YOURDOMAIN_FQDN
    - Name: gMSA-ACCOUNT-NAME
      Scope: YOURDOMAIN_NETBIOS
    HostAccountConfig:
      PortableCcgVersion: "1"
      PluginGUID: "{859E1386-BDB4-49E8-85C7-3070B13920E1}"
      PluginInput: "{\"credentialArn\":\"ARN-SECRET\"}"
```

Note: Replace values to match your environment. You can run the following PowerShell command in a Windows terminal with access to your Active Directory domain in order to retrieve SID and GUID from the gMSA account: Get-ADServiceAccount -Identity gMSA-ACCOUNT-NAME

Your file should look like the following:

```yaml
apiVersion: windows.k8s.io/v1
kind: GMSACredentialSpec
metadata:
  name: gmsaeks-domainless
credspec:
  CmsPlugins:
  - ActiveDirectory
  DomainJoinConfig:
    Sid: S-1-5-21-857038504-468933455-1338018723
    MachineAccountName: gmsaeks
    Guid: 59d60a02-be02-4fd3-8a7f-c7c6c0daceaa
    DnsTreeName: marciomorales.local
    DnsName: marciomorales.local
    NetBiosName: marciomorales
  ActiveDirectoryConfig:
    GroupManagedServiceAccounts:
    - Name: gmsaeks
      Scope: marciomorales.local
    - Name: gmsaeks
      Scope: marciomorales
    HostAccountConfig:
      PortableCcgVersion: "1"
      PluginGUID: "{859E1386-BDB4-49E8-85C7-3070B13920E1}"
      PluginInput: "{\"credentialArn\":\"arn:aws:secretsmanager:us-east-1:0123456789:secret:gmsa-plugin-input-tBOL0j\"}"
```

3.4 Create the gMSA CredentialSpec resource on the cluster with the following command:

```bash
kubectl create -f domainless-credspec-secretmanager.yaml
```

### 4. Create a Kubernetes ClusterRole and RoleBinding

A ClusterRole and RoleBinding are required to allow the gMSA CredentialSpec to be used by your pod.

4.1 Create file containing the code below and save it as `gmsa-domainless-clusterrole.yaml`.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: eksgmsa-role-domainless
rules:
- apiGroups: ["windows.k8s.io"]
  resources: ["gmsacredentialspecs"]
  verbs: ["use"]
  resourceNames: ["gmsaeks-domainless"]
  
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: gmsa-assign-role-domainless
  namespace: default
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
roleRef:
  kind: ClusterRole
  name: eksgmsa-role-domainless
  apiGroup: rbac.authorization.k8s.io
```

Note: Replace resourceNames with the one generated in step 4.3 if it’s different from what we specified.

4.2 Create the ClusterRole and RoleBinding on the cluster with the following command:

```bash
kubectl apply -f gmsa-domainless-clusterrole.yaml
```

### 5. Configure the gMSA CredentialSpec in the Windows pod spec

To test our configuration is working, we ‘ll need to deploy a Windows pod with the specification field securityContext.windowsOptions.gmsaCredentialSpecName to reference our gMSA CredentialSpec custom resource we created and deployed in step 4.

5.1 Create file containing the code below and save it as windows-auth-pod.yaml.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    run: amazon-eks-gmsa-domainless
  name: amazon-eks-gmsa-domainless
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      run: amazon-eks-gmsa-domainless
  template:
    metadata:
      labels:
        run: amazon-eks-gmsa-domainless
    spec:
      securityContext:
        windowsOptions:
          gmsaCredentialSpecName: gmsaeks-domainless
      containers:
      - image: mcr.microsoft.com/windows/servercore:ltsc2019
        imagePullPolicy: Always
        name: gmsadomainless
        command:
          - "powershell.exe"
          - "-Command"
          - "while (1) { sleep 1 }"
      nodeSelector:
        kubernetes.io/os: windows
```

Note: Replace gmsaCredentialSpecName value with the name of the gMSA CredentialSpec you created in step 4.2. For this post, we used gmsaeks-domainless.

5.2 Deploy the Windows pod using following command:

```bash
kubectl apply -f windows-auth-pod.yaml
```

### 6. Test the Windows Authentication from inside the Windows pod
6.1 Run the following command to open a PowerShell session within our test pod from step 7.2:

```bash
kubectl exec -it PODNAME -- powershell.exe
```

Note: Replace PODNAME with the name of your pod. You can retrieve the name of the pod from the list of outputs when you run kubectl get pods.

6.2 From within the pod’s PowerShell session, execute the following command to verify the gMSA identity and client name. In this post, gmsaeks is the identity, this can be seen in the following diagram.

```powershell
klist get krbtgt
```

6.3 Additionally, you can use nltest to verify the Trusted DC connection is made successfully by running the following command:

```powershell
nltest /sc_verify:YOURDOMAINFQDN
```

### 7. Logging locations
- Events are logged in the Microsoft-Windows-Containers-CCG log file and can be found in the Event Viewer under Applications and Services Logs\Microsoft\Windows\Containers-CCG\Admin. See more debugging tips in Microsoft provided guide: [Troubleshoot gMSAs for Windows containers](https://learn.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/gmsa-troubleshooting#non-domain-joined-container-hosts-use-event-logs-to-identify-configuration-issues).
- Basic logging for plugin on the non-domain-joined Windows node: C:/programdata/Amazon/gmsa-plugin/


### 8. (Optional) Using AWS System Manager Parameter Store as a credential store.
You may prefer to use AWS System Manager Parameter Store as a credential store instead of an AWS Secret Manager. The AWS plugin supports both options, but just one can be used per portable identity. If this is the case, then create the parameter on SSM to store the portable identity credential.

8.1 Create a JSON file that contains the values that will compose the SSM parameter:

```json
{
    "Name": "gmsa-plugin-input",
    "Value": "{\n\"username\": \"eks-portable-identity\",\n\"password\": \"YOUR_PASSWORD\",\n\"domainName\": \"YOURDOMAIN_FQDN\"\n}",
    "Type": "SecureString"
}
```

Note: Replace username with your portable identity credential. Replace YOUR_PASSWORD the portable identity password with the one you create in step 1.3. Replace YOURDOMAIN_FQDN with your fully qualified domain name.

8.2 Create the SSM Parameter using the following command:

```bash
aws ssm put-parameter \
    --type "SecureString" \
    --key-id "KMS-KEY-ARN" \
    --cli-input-json file://gmsa-json-parameterstore.json
```

Note: Replace key-id value with the KMS Key ARN that you want to encrypt the parameter. Replace the file path with the one you saved the JSON file.

8.3 Add the following AWS IAM in-line policy to the existing Windows node AWS IAM role. This AWS IAM policy allows the Windows nodes to read the secret stored on the AWS System Manager Parameter Store.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ssm:GetParameters"
            ],
            "Resource": [
                "ARN-PARAMETER-STORE"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt"
            ],
            "Resource": [
                "ARN-KMS-KEY"
            ]
        }
    ]
}
```
8.4 Create the gMSA CredentialSpec resource on the cluster that points to use the Parameter Store with the following command and save it as domainless-credspec-parameterstore.yaml.

```yaml
apiVersion: windows.k8s.io/v1
kind: GMSACredentialSpec
metadata:
  name: gmsaeks-domainless
credspec:
  CmsPlugins:
  - ActiveDirectory
  DomainJoinConfig:
    Sid: gMSA-ACCOUNT-SID
    MachineAccountName: gMSA-ACCOUNT-NAME
    Guid: gMSA-ACCOUNT-GUID
    DnsTreeName: YOURDOMAIN_FQDN
    DnsName: YOURDOMAIN_FQDN
    NetBiosName: YOURDOMAIN_NETBIOS
  ActiveDirectoryConfig:
    GroupManagedServiceAccounts:
    - Name: gMSA-ACCOUNT-NAME
      Scope: YOURDOMAIN_FQDN
    - Name: gMSA-ACCOUNT-NAME
      Scope: YOURDOMAIN_NETBIOS
    HostAccountConfig:
      PortableCcgVersion: "1"
      PluginGUID: "{859E1386-BDB4-49E8-85C7-3070B13920E1}"
      PluginInput: "{\"credentialArn\":\"ARN-PARAMETER-STORE\"}"
```

8.5 Create the gMSA CredentialSpec resource on the cluster with the following command:

```bash
kubectl create -f domainless-credspec-parameterstore.yaml
```