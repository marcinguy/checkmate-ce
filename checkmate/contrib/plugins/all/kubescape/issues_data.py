# -*- coding: utf-8 -*-


issues_data = {

  "C-0030": {
    "title": "Ingress and Egress blocked",
    "display_name": "Ingress and Egress blocked",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Disable Ingress and Egress traffic on all pods wherever possible. It is recommended to define restrictive network policy on all new PODs, and then enable sources/destinations that this POD must communicate with."
  },
  "C-0075": {
    "title": "Image pull policy on latest tag",
    "display_name": "Image pull policy on latest tag",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "While usage of the latest tag is not generally recommended, in some cases this is necessary. If it is, the ImagePullPolicy must be set to Always, otherwise Kubernetes may run an older image with the same name that happens to be present in the node cache. Note that using Always will not cause additional image downloads because Kubernetes will check the image hash of the local local against the registry and only pull the image if this hash has changed, which is exactly what users want when use the latest tag. This control will identify all PODs with latest tag that have ImagePullSecret not set to Always."
  },
  "C-0063": {
    "title": "Portforwarding privileges",
    "display_name": "Portforwarding privileges",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Attackers with relevant RBAC permission can use \u201ckubectl portforward\u201d command to establish direct communication with PODs from within the cluster or even remotely. Such communication will most likely bypass existing security measures in the cluster. This control determines which subjects have permissions to use this command."
  },
  "C-0034": {
    "title": "Automatic mapping of service account",
    "display_name": "Automatic mapping of service account",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Potential attacker may gain access to a POD and steal its service account token. Therefore, it is recommended to disable automatic mapping of the service account tokens in service account configuration and enable it only for PODs that need to use them."
  },
  "C-0002": {
    "title": "Exec into container",
    "display_name": "Exec into container",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Attackers with relevant permissions can run malicious commands in the context of legitimate containers in the cluster using \u201ckubectl exec\u201d command. This control determines which subjects have permissions to use this command."
  },
  "C-0001": {
    "title": "Forbidden Container Registries",
    "display_name": "Forbidden Container Registries",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "In cases where the Kubernetes cluster is provided by a CSP (e.g., AKS in Azure, GKE in GCP, or EKS in AWS), compromised cloud credential can lead to the cluster takeover. Attackers may abuse cloud account credentials or IAM mechanism to the cluster\u2019s management layer."
  },
  "C-0006": {
    "title": "Allowed hostPath",
    "display_name": "Allowed hostPath",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Mounting host directory to the container can be abused to get access to sensitive data and gain persistence on the host machine."
  },
  "C-0007": {
    "title": "Data Destruction",
    "display_name": "Data Destruction",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Attackers may attempt to destroy data and resources in the cluster. This includes deleting deployments, configurations, storage, and compute resources. This control identifies all subjects that can delete resources."
  },
  "C-0004": {
    "title": "Resources memory limit and request",
    "display_name": "Resources memory limit and request",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This control identifies all Pods for which the memory limit is not set."
  },
  "C-0005": {
    "title": "Control plane hardening",
    "display_name": "Control plane hardening",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Kubernetes control plane API is running with non-secure port enabled which allows attackers to gain unprotected access to the cluster."
  },
  "C-0024": {
    "title": "Vulnerable application",
    "display_name": "Vulnerable application",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Running a vulnerable application in a cluster can enable an attacker initial access to the cluster. This control determines if pods/deployments have vulnerable images using ARMO vulnerability scan (must run vulnerability scan before running posture scan). "
  },
  "C-0025": {
    "title": "Application exploit (RCE)",
    "display_name": "Application exploit (RCE)",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Applications that are vulnerable to a remote code execution enable attackers to run malicious code in the cluster. This control determines if pods have vulnerable images with remote code execution using ARMO vulnerability scan (must run vulnerability scan before running posture scan)."
  },
  "C-0044": {
    "title": "Container hostPort",
    "display_name": "Container hostPort",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Configuring hostPort requires a particular port number. If two objects specify the same HostPort, they could not be deployed to the same node. It may prevent the second object from starting, even if Kubernetes will try reschedule it on another node, provided there are available nodes with sufficient amount of resources. Also, if the number of replicas of such workload is higher than the number of nodes, the deployment will consistently fail."
  },
  "C-0009": {
    "title": "Resource policies",
    "display_name": "Resource policies",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "CPU and memory resources should have a limit set for every container or a namespace to prevent resource exhaustion. This control identifies all the Pods without resource limit definitions by checking their yaml definition file as well as their namespace LimitRange objects. It is also recommended to use ResourceQuota object to restrict overall namespace resources, but this is not verified by this control."
  },
  "C-0020": {
    "title": "Mount service principal",
    "display_name": "Mount service principal",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "When a cluster is deployed in the cloud, in some cases attackers can leverage their access to a container in the cluster to gain cloud credentials. This control determines if any workload contains a hostPath volume."
  },
  "C-0021": {
    "title": "Exposed sensitive interfaces",
    "display_name": "Exposed sensitive interfaces",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Exposing a sensitive interface to the internet poses a security risk. It might enable attackers to run malicious code or deploy containers in the cluster. This control checks if known components (e.g. Kubeflow, Argo Workflows, etc.) are deployed and exposed services externally."
  },
  "C-0026": {
    "title": "Kubernetes CronJob",
    "display_name": "Kubernetes CronJob",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Attackers may use Kubernetes CronJob for scheduling execution of malicious code that would run as a POD in the cluster. This control lists all the CronJobs that exist in the cluster for the user to approve."
  },
  "C-0068": {
    "title": "PSP enabled",
    "display_name": "PSP enabled",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "PSP enable fine-grained authorization of pod creation and it is important to enable it"
  },
  "C-0069": {
    "title": "Disable anonymous access to Kubelet service",
    "display_name": "Disable anonymous access to Kubelet service",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "By default, requests to the kubelet's HTTPS endpoint that are not rejected by other configured authentication methods are treated as anonymous requests, and given a username of system:anonymous and a group of system:unauthenticated."
  },
  "C-0048": {
    "title": "HostPath mount",
    "display_name": "HostPath mount",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Mounting host directory to the container can be used by attackers to get access to the underlying host. This control identifies all the PODs using hostPath mount."
  },
  "C-0049": {
    "title": "Network mapping",
    "display_name": "Network mapping",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If no network policy is defined, attackers who gain access to a single container may use it to probe the network. This control lists all namespaces in which no network policies are defined."
  },
  "C-0046": {
    "title": "Insecure capabilities",
    "display_name": "Insecure capabilities",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Giving insecure or excsessive capabilities to a container can increase the impact of the container compromise. This control identifies all the PODs with dangerous capabilities (see documentation pages for details)."
  },
  "C-0047": {
    "title": "Exposed dashboard",
    "display_name": "Exposed dashboard",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Kubernetes dashboard versions before v2.0.1 do not support user authentication. If exposed externally, it will allow unauthenticated remote management of the cluster. This control checks presence of the kubernetes-dashboard deployment and its version number."
  },
  "C-0062": {
    "title": "Sudo in container entrypoint",
    "display_name": "Sudo in container entrypoint",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Adding sudo to a container entry point command may escalate process privileges and allow access to forbidden resources. This control checks all the entry point commands in all containers in the POD to find those that have sudo command."
  },
  "C-0045": {
    "title": "Writable hostPath mount",
    "display_name": "Writable hostPath mount",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Mounting host directory to the container can be used by attackers to get access to the underlying host and gain persistence."
  },
  "C-0042": {
    "title": "SSH server running inside container",
    "display_name": "SSH server running inside container",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "An SSH server that is running inside a container may be used by attackers to get remote access to the container. This control checks if pods have an open SSH port (22/2222)."
  },
  "C-0065": {
    "title": "No impersonation",
    "display_name": "No impersonation",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Impersonation is an explicit RBAC permission to use other roles rather than the one assigned to a user, group or service account. This is sometimes needed for testing purposes. However, it is highly recommended not to use this capability in the production environments for daily operations. This control identifies all subjects whose roles include impersonate verb."
  },
  "C-0066": {
    "title": "Secret/ETCD encryption enabled",
    "display_name": "Secret/ETCD encryption enabled",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "All Kubernetes Secrets are stored primarily in etcd therefore it is important to encrypt it."
  },
  "C-0041": {
    "title": "HostNetwork access",
    "display_name": "HostNetwork access",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Potential attackers may gain access to a POD and inherit access to the entire host network. For example, in AWS case, they will have access to the entire VPC. This control identifies all the PODs with host network access enabled."
  },
  "C-0088": {
    "title": "RBAC enabled",
    "display_name": "RBAC enabled",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "RBAC is the most advanced and well accepted mode of authorizing users of the Kubernetes API"
  },
  "C-0086": {
    "title": "CVE-2022-0492-cgroups-container-escape",
    "display_name": "CVE-2022-0492-cgroups-container-escape",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Linux Kernel vulnerability CVE-2022-0492 may allow malicious code running inside container to escape container isolation and gain root privileges on the entire node. When fixed Kernel version numbers will become available, this control will be modified to verify them and avoid false positive detections. This control identifies all the resources that don't deploy neither AppArmor nor SELinux, run as root or allow privige escalation or have corresponding dangerous capabilities."
  },
  "C-0039": {
    "title": "Malicious admission controller (mutating)",
    "display_name": "Malicious admission controller (mutating)",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Attackers may use mutating webhooks to intercept and modify all the resources in the cluster. This control lists all mutating webhook configurations that must be verified."
  },
  "C-0083": {
    "title": "Workloads with Critical vulnerabilities exposed to external traffic",
    "display_name": "Workloads with Critical vulnerabilities exposed to external traffic",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Container images with known critical vulnerabilities pose elevated risk if they are exposed to the external traffic. This control lists all images with such vulnerabilities if either LoadBalancer or NodePort service is assigned to them."
  },
  "C-0081": {
    "title": "CVE-2022-24348-argocddirtraversal",
    "display_name": "CVE-2022-24348-argocddirtraversal",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "CVE-2022-24348 is a major software supply chain 0-day vulnerability in the popular open source CD platform Argo CD which can lead to privilege escalation and information disclosure."
  },
  "C-0035": {
    "title": "Cluster-admin binding",
    "display_name": "Cluster-admin binding",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Attackers who have cluster admin permissions (can perform any action on any resource), can take advantage of their privileges for malicious activities. This control determines which subjects have cluster admin permissions."
  },
  "C-0087": {
    "title": "CVE-2022-23648-containerd-fs-escape",
    "display_name": "CVE-2022-23648-containerd-fs-escape",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "CVE-2022-23648 is a vulnerability of containerd enabling attacker to gain access to read-only copies of arbitrary files from the host using aspecially-crafted POD configuration yamls"
  },
  "C-0084": {
    "title": "Workloads with RCE vulnerabilities exposed to external traffic",
    "display_name": "Workloads with RCE vulnerabilities exposed to external traffic",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Container images with known Remote Code Execution (RCE) vulnerabilities pose significantly higher risk if they are exposed to the external traffic. This control lists all images with such vulnerabilities if their POD has either LoadBalancer or NodePort service."
  },
  "C-0085": {
    "title": "Workloads with excessive amount of vulnerabilities",
    "display_name": "Workloads with excessive amount of vulnerabilities",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Container images with multiple Critical and High sevirity vulnerabilities increase the risk of potential exploit. This control lists all such images according to the threashold provided by the customer."
  },
  "C-0060": {
    "title": "Namespace without service accounts",
    "display_name": "Namespace without service accounts",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "It is recommended not to use default service account anywhere in production environment. This control identifies all namespaces without explicit non-default service account."
  },
  "C-0074": {
    "title": "Containers mounting Docker socket",
    "display_name": "Containers mounting Docker socket",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Mounting Docker socket (Unix socket) enables container to access Docker internals, retrieve sensitive information and execute Docker commands, if Docker runtime is available. This control identifies PODs that attempt to mount Docker socket for accessing Docker runtime."
  },
  "C-0061": {
    "title": "Pods in default namespace",
    "display_name": "Pods in default namespace",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "It is recommended to avoid running PODs in cluster without explicit namespace assignment. This control identifies all the PODs running in the default namespace."
  },
  "C-0073": {
    "title": "Naked PODs",
    "display_name": "Naked PODs",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "It is not recommended to create PODs without parental Deployment, ReplicaSet, StatefulSet etc.Manual creation if PODs may lead to a configuration drifts and other untracked changes in the system. Such PODs won't be automatically rescheduled by Kubernetes in case of a crash or infrastructure failure. This control identifies every POD that does not have corresponding parental object."
  },
  "C-0038": {
    "title": "Host PID/IPC privileges",
    "display_name": "Host PID/IPC privileges",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Containers should be isolated from the host machine as much as possible. The hostPID and hostIPC fields in deployment yaml may allow cross-container influence and may expose the host itself to potentially malicious or destructive actions. This control identifies all PODs using hostPID or hostIPC privileges."
  },
  "C-0067": {
    "title": "Audit logs enabled",
    "display_name": "Audit logs enabled",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Audit logging is an important security feature in Kubernetes, it enables the operator to track requests to the cluster. It is important to use it so the operator has a record of events happened in Kubernetes"
  },
  "C-0077": {
    "title": "K8s common labels usage",
    "display_name": "K8s common labels usage",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Kubernetes common labels help manage and monitor Kubernetes cluster using different tools such as kubectl, dashboard and others in an interoperable way. Refer to https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/ for more information. This control helps you find objects that don't have any of these labels defined."
  },
  "C-0076": {
    "title": "Label usage for resources",
    "display_name": "Label usage for resources",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "It is recommended to set labels that identify semantic attributes of your application or deployment. For example, { app: myapp, tier: frontend, phase: test, deployment: v3 }. These labels can used to assign policies to logical groups of the deployments as well as for presentation and tracking purposes. This control helps you find deployments without any of the expected labels."
  },
  "C-0013": {
    "title": "Non-root containers",
    "display_name": "Non-root containers",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Potential attackers may gain access to a container and leverage its existing privileges to conduct an attack. Therefore, it is not recommended to deploy containers with root privileges unless it is absolutely necessary. This control identifies all the Pods running as root or can escalate to root."
  },
  "C-0012": {
    "title": "Applications credentials in configuration files",
    "display_name": "Applications credentials in configuration files",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Attackers who have access to configuration files can steal the stored secrets and use them. This control checks if ConfigMaps or pod specifications have sensitive information in their configuration."
  },
  "C-0015": {
    "title": "List Kubernetes secrets",
    "display_name": "List Kubernetes secrets",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Attackers who have permissions to access secrets can access sensitive information that might include credentials to various services. This control determines which user, group or service account can list/get secrets."
  },
  "C-0014": {
    "title": "Access Kubernetes dashboard",
    "display_name": "Access Kubernetes dashboard",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Attackers who gain access to the dashboard service account or have its RBAC permissions can use its network access to retrieve information about resources in the cluster or change them. This control checks if a subject that is not dashboard service account is bound to dashboard role/clusterrole, or - if anyone that is not the dashboard pod is associated with dashboard service account."
  },
  "C-0017": {
    "title": "Immutable container filesystem",
    "display_name": "Immutable container filesystem",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Mutable container filesystem can be abused to inject malicious code or data into containers. Use immutable (read-only) filesystem to limit potential attacks."
  },
  "C-0070": {
    "title": "Enforce Kubelet client TLS authentication",
    "display_name": "Enforce Kubelet client TLS authentication",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Kubelets are the node level orchestrator in Kubernetes control plane. They are publishing service port 10250 where they accept commands from API server. Operator must make sure that only API server is allowed to submit commands to Kubelet. This is done through client certificate verification, must configure Kubelet with client CA file to use for this purpose."
  },
  "C-0019": {
    "title": "Bash/cmd inside container",
    "display_name": "Bash/cmd inside container",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Attackers who can run new processes inside a container might use cmd/bash script inside a container to execute malicious code. This control determines which containers have bash/cmd inside it."
  },
  "C-0018": {
    "title": "Configured readiness probe",
    "display_name": "Configured readiness probe",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Readiness probe is intended to ensure that workload is ready to process network traffic. It is highly recommended to define readiness probe for every worker container. This control finds all the PODs where the readiness probe is not configured."
  },
  "C-0031": {
    "title": "Delete Kubernetes events",
    "display_name": "Delete Kubernetes events",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Attackers may delete Kubernetes events to avoid detection of their activity in the cluster. This control identifies all the subjects that can delete Kubernetes events."
  },
  "C-0016": {
    "title": "Allow privilege escalation",
    "display_name": "Allow privilege escalation",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Attackers may gain access to a container and uplift its privilege to enable excessive capabilities."
  },
  "C-0037": {
    "title": "CoreDNS poisoning",
    "display_name": "CoreDNS poisoning",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If attackers have permissions to modify the coredns ConfigMap they can change the behavior of the cluster\u2019s DNS, poison it, and override the network identity of other services. This control identifies all subjects allowed to update the 'coredns' configmap."
  },
  "C-0036": {
    "title": "Malicious admission controller (validating)",
    "display_name": "Malicious admission controller (validating)",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Attackers can use validating webhooks to intercept and discover all the resources in the cluster. This control lists all the validating webhook configurations that must be verified."
  },
  "C-0079": {
    "title": "CVE-2022-0185-linux-kernel-container-escape",
    "display_name": "CVE-2022-0185-linux-kernel-container-escape",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "CVE-2022-0185 is a kernel vulnerability enabling privilege escalation and it can lead attackers to escape containers and take control over nodes. This control alerts on vulnerable kernel versions of Kubernetes nodes"
  },
  "C-0078": {
    "title": "Images from allowed registry",
    "display_name": "Images from allowed registry",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This control is intended to ensure that all the used container images are taken from the authorized repositories. It allows user to list all the approved repositories and will fail all the images taken from any repository outside of this list."
  },
  "C-0033": {
    "title": "Access tiller endpoint",
    "display_name": "Access tiller endpoint",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Attackers may run code on any container that is accessible to the tiller\u2019s service and perform actions in the cluster, using the tiller\u2019s service account, which often has high privileges. This control checks if unauthenticated version of the Tiller runs in the cluster."
  },
  "C-0059": {
    "title": "CVE-2021-25742-nginx-ingress-snippet-annotation-vulnerability",
    "display_name": "CVE-2021-25742-nginx-ingress-snippet-annotation-vulnerability",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Security issue in ingress-nginx where a user that can create or update ingress objects can use the custom snippets feature to obtain all secrets in the cluster (see more at https://github.com/kubernetes/ingress-nginx/issues/7837)"
  },
  "C-0058": {
    "title": "CVE-2021-25741 - Using symlink for arbitrary host file system access.",
    "display_name": "CVE-2021-25741 - Using symlink for arbitrary host file system access.",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A user may be able to create a container with subPath or subPathExpr volume mounts to access files & directories anywhere on the host filesystem. Following Kubernetes versions are affected: v1.22.0 - v1.22.1, v1.21.0 - v1.21.4, v1.20.0 - v1.20.10, version v1.19.14 and lower. This control checks the vulnerable versions and the actual usage of the subPath feature in all Pods in the cluster. If you want to learn more about the CVE, please refer to the CVE link: https://nvd.nist.gov/vuln/detail/CVE-2021-25741"
  },
  "C-0055": {
    "title": "Linux hardening",
    "display_name": "Linux hardening",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Containers may be given more privileges than they actually need. This can increase the potential impact of a container compromise."
  },
  "C-0054": {
    "title": "Cluster internal networking",
    "display_name": "Cluster internal networking",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If no network policy is defined, attackers who gain access to a container may use it to move laterally in the cluster. This control lists namespaces in which no network policy is defined."
  },
  "C-0057": {
    "title": "Privileged container",
    "display_name": "Privileged container",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Potential attackers may gain access to privileged containers and inherit access to the host resources. Therefore, it is not recommended to deploy privileged containers unless it is absolutely necessary. This control identifies all the privileged Pods."
  },
  "C-0056": {
    "title": "Configured liveness probe",
    "display_name": "Configured liveness probe",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Liveness probe is intended to ensure that workload remains healthy during its entire execution lifecycle, or otherwise restrat the container. It is highly recommended to define liveness probe for every worker container. This control finds all the PODs where the Liveness probe is not configured."
  },
  "C-0050": {
    "title": "Resources CPU limit and request",
    "display_name": "Resources CPU limit and request",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This control identifies all Pods for which the CPU limit is not set."
  },
  "C-0053": {
    "title": "Access container service account",
    "display_name": "Access container service account",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Attackers who obtain access to a pod can use its SA token to communicate with KubeAPI server. All PODs with SA token mounted (if such token has a Role or a ClusterRole binding) are considerred potentially dangerous."
  },
  "C-0052": {
    "title": "Instance Metadata API",
    "display_name": "Instance Metadata API",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Attackers who gain access to a container, may query the metadata API service for getting information about the underlying node. This control checks if there is access from the nodes to cloud providers instance metadata services."
  }
}
