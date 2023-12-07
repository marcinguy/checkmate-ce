issues_data = {   'C-0001': {   'categories': ['security'],
                  'description': 'In cases where the Kubernetes cluster is '
                                 'provided by a CSP (e.g., AKS in Azure, GKE '
                                 'in GCP, or EKS in AWS), compromised cloud '
                                 'credential can lead to the cluster takeover. '
                                 'Attackers may abuse cloud account '
                                 'credentials or IAM mechanism to the '
                                 'cluster’s management layer.',
                  'display_name': 'Forbidden Container Registries',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Forbidden Container Registries'},
    'C-0002': {   'categories': ['security'],
                  'description': 'Attackers with relevant permissions can run '
                                 'malicious commands in the context of '
                                 'legitimate containers in the cluster using '
                                 '“kubectl exec” command. This control '
                                 'determines which subjects have permissions '
                                 'to use this command.',
                  'display_name': 'Exec into container',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Exec into container'},
    'C-0004': {   'categories': ['security'],
                  'description': 'This control identifies all Pods for which '
                                 'the memory limit is not set.',
                  'display_name': 'Resources memory limit and request',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Resources memory limit and request'},
    'C-0005': {   'categories': ['security'],
                  'description': 'Kubernetes control plane API is running with '
                                 'non-secure port enabled which allows '
                                 'attackers to gain unprotected access to the '
                                 'cluster.',
                  'display_name': 'Control plane hardening',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Control plane hardening'},
    'C-0006': {   'categories': ['security'],
                  'description': 'Mounting host directory to the container can '
                                 'be abused to get access to sensitive data '
                                 'and gain persistence on the host machine.',
                  'display_name': 'Allowed hostPath',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Allowed hostPath'},
    'C-0007': {   'categories': ['security'],
                  'description': 'Attackers may attempt to destroy data and '
                                 'resources in the cluster. This includes '
                                 'deleting deployments, configurations, '
                                 'storage, and compute resources. This control '
                                 'identifies all subjects that can delete '
                                 'resources.',
                  'display_name': 'Data Destruction',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Data Destruction'},
    'C-0009': {   'categories': ['security'],
                  'description': 'CPU and memory resources should have a limit '
                                 'set for every container or a namespace to '
                                 'prevent resource exhaustion. This control '
                                 'identifies all the Pods without resource '
                                 'limit definitions by checking their yaml '
                                 'definition file as well as their namespace '
                                 'LimitRange objects. It is also recommended '
                                 'to use ResourceQuota object to restrict '
                                 'overall namespace resources, but this is not '
                                 'verified by this control.',
                  'display_name': 'Resource policies',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Resource policies'},
    'C-0012': {   'categories': ['security'],
                  'description': 'Attackers who have access to configuration '
                                 'files can steal the stored secrets and use '
                                 'them. This control checks if ConfigMaps or '
                                 'pod specifications have sensitive '
                                 'information in their configuration.',
                  'display_name': 'Applications credentials in configuration '
                                  'files',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Applications credentials in configuration files'},
    'C-0013': {   'categories': ['security'],
                  'description': 'Potential attackers may gain access to a '
                                 'container and leverage its existing '
                                 'privileges to conduct an attack. Therefore, '
                                 'it is not recommended to deploy containers '
                                 'with root privileges unless it is absolutely '
                                 'necessary. This control identifies all the '
                                 'Pods running as root or can escalate to '
                                 'root.',
                  'display_name': 'Non-root containers',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Non-root containers'},
    'C-0014': {   'categories': ['security'],
                  'description': 'Attackers who gain access to the dashboard '
                                 'service account or have its RBAC permissions '
                                 'can use its network access to retrieve '
                                 'information about resources in the cluster '
                                 'or change them. This control checks if a '
                                 'subject that is not dashboard service '
                                 'account is bound to dashboard '
                                 'role/clusterrole, or - if anyone that is not '
                                 'the dashboard pod is associated with '
                                 'dashboard service account.',
                  'display_name': 'Access Kubernetes dashboard',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Access Kubernetes dashboard'},
    'C-0015': {   'categories': ['security'],
                  'description': 'Attackers who have permissions to access '
                                 'secrets can access sensitive information '
                                 'that might include credentials to various '
                                 'services. This control determines which '
                                 'user, group or service account can list/get '
                                 'secrets.',
                  'display_name': 'List Kubernetes secrets',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'List Kubernetes secrets'},
    'C-0016': {   'categories': ['security'],
                  'description': 'Attackers may gain access to a container and '
                                 'uplift its privilege to enable excessive '
                                 'capabilities.',
                  'display_name': 'Allow privilege escalation',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Allow privilege escalation'},
    'C-0017': {   'categories': ['security'],
                  'description': 'Mutable container filesystem can be abused '
                                 'to inject malicious code or data into '
                                 'containers. Use immutable (read-only) '
                                 'filesystem to limit potential attacks.',
                  'display_name': 'Immutable container filesystem',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Immutable container filesystem'},
    'C-0018': {   'categories': ['security'],
                  'description': 'Readiness probe is intended to ensure that '
                                 'workload is ready to process network '
                                 'traffic. It is highly recommended to define '
                                 'readiness probe for every worker container. '
                                 'This control finds all the PODs where the '
                                 'readiness probe is not configured.',
                  'display_name': 'Configured readiness probe',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Configured readiness probe'},
    'C-0019': {   'categories': ['security'],
                  'description': 'Attackers who can run new processes inside a '
                                 'container might use cmd/bash script inside a '
                                 'container to execute malicious code. This '
                                 'control determines which containers have '
                                 'bash/cmd inside it.',
                  'display_name': 'Bash/cmd inside container',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Bash/cmd inside container'},
    'C-0020': {   'categories': ['security'],
                  'description': 'When a cluster is deployed in the cloud, in '
                                 'some cases attackers can leverage their '
                                 'access to a container in the cluster to gain '
                                 'cloud credentials. This control determines '
                                 'if any workload contains a hostPath volume.',
                  'display_name': 'Mount service principal',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Mount service principal'},
    'C-0021': {   'categories': ['security'],
                  'description': 'Exposing a sensitive interface to the '
                                 'internet poses a security risk. It might '
                                 'enable attackers to run malicious code or '
                                 'deploy containers in the cluster. This '
                                 'control checks if known components (e.g. '
                                 'Kubeflow, Argo Workflows, etc.) are deployed '
                                 'and exposed services externally.',
                  'display_name': 'Exposed sensitive interfaces',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Exposed sensitive interfaces'},
    'C-0024': {   'categories': ['security'],
                  'description': 'Running a vulnerable application in a '
                                 'cluster can enable an attacker initial '
                                 'access to the cluster. This control '
                                 'determines if pods/deployments have '
                                 'vulnerable images using ARMO vulnerability '
                                 'scan (must run vulnerability scan before '
                                 'running posture scan). ',
                  'display_name': 'Vulnerable application',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Vulnerable application'},
    'C-0025': {   'categories': ['security'],
                  'description': 'Applications that are vulnerable to a remote '
                                 'code execution enable attackers to run '
                                 'malicious code in the cluster. This control '
                                 'determines if pods have vulnerable images '
                                 'with remote code execution using ARMO '
                                 'vulnerability scan (must run vulnerability '
                                 'scan before running posture scan).',
                  'display_name': 'Application exploit (RCE)',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Application exploit (RCE)'},
    'C-0026': {   'categories': ['security'],
                  'description': 'Attackers may use Kubernetes CronJob for '
                                 'scheduling execution of malicious code that '
                                 'would run as a POD in the cluster. This '
                                 'control lists all the CronJobs that exist in '
                                 'the cluster for the user to approve.',
                  'display_name': 'Kubernetes CronJob',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Kubernetes CronJob'},
    'C-0030': {   'categories': ['security'],
                  'description': 'Disable Ingress and Egress traffic on all '
                                 'pods wherever possible. It is recommended to '
                                 'define restrictive network policy on all new '
                                 'PODs, and then enable sources/destinations '
                                 'that this POD must communicate with.',
                  'display_name': 'Ingress and Egress blocked',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Ingress and Egress blocked'},
    'C-0031': {   'categories': ['security'],
                  'description': 'Attackers may delete Kubernetes events to '
                                 'avoid detection of their activity in the '
                                 'cluster. This control identifies all the '
                                 'subjects that can delete Kubernetes events.',
                  'display_name': 'Delete Kubernetes events',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Delete Kubernetes events'},
    'C-0033': {   'categories': ['security'],
                  'description': 'Attackers may run code on any container that '
                                 'is accessible to the tiller’s service and '
                                 'perform actions in the cluster, using the '
                                 'tiller’s service account, which often has '
                                 'high privileges. This control checks if '
                                 'unauthenticated version of the Tiller runs '
                                 'in the cluster.',
                  'display_name': 'Access tiller endpoint',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Access tiller endpoint'},
    'C-0034': {   'categories': ['security'],
                  'description': 'Potential attacker may gain access to a POD '
                                 'and steal its service account token. '
                                 'Therefore, it is recommended to disable '
                                 'automatic mapping of the service account '
                                 'tokens in service account configuration and '
                                 'enable it only for PODs that need to use '
                                 'them.',
                  'display_name': 'Automatic mapping of service account',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Automatic mapping of service account'},
    'C-0035': {   'categories': ['security'],
                  'description': 'Attackers who have cluster admin permissions '
                                 '(can perform any action on any resource), '
                                 'can take advantage of their privileges for '
                                 'malicious activities. This control '
                                 'determines which subjects have cluster admin '
                                 'permissions.',
                  'display_name': 'Cluster-admin binding',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Cluster-admin binding'},
    'C-0036': {   'categories': ['security'],
                  'description': 'Attackers can use validating webhooks to '
                                 'intercept and discover all the resources in '
                                 'the cluster. This control lists all the '
                                 'validating webhook configurations that must '
                                 'be verified.',
                  'display_name': 'Malicious admission controller (validating)',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Malicious admission controller (validating)'},
    'C-0037': {   'categories': ['security'],
                  'description': 'If attackers have permissions to modify the '
                                 'coredns ConfigMap they can change the '
                                 'behavior of the cluster’s DNS, poison it, '
                                 'and override the network identity of other '
                                 'services. This control identifies all '
                                 "subjects allowed to update the 'coredns' "
                                 'configmap.',
                  'display_name': 'CoreDNS poisoning',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'CoreDNS poisoning'},
    'C-0038': {   'categories': ['security'],
                  'description': 'Containers should be isolated from the host '
                                 'machine as much as possible. The hostPID and '
                                 'hostIPC fields in deployment yaml may allow '
                                 'cross-container influence and may expose the '
                                 'host itself to potentially malicious or '
                                 'destructive actions. This control identifies '
                                 'all PODs using hostPID or hostIPC '
                                 'privileges.',
                  'display_name': 'Host PID/IPC privileges',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Host PID/IPC privileges'},
    'C-0039': {   'categories': ['security'],
                  'description': 'Attackers may use mutating webhooks to '
                                 'intercept and modify all the resources in '
                                 'the cluster. This control lists all mutating '
                                 'webhook configurations that must be '
                                 'verified.',
                  'display_name': 'Malicious admission controller (mutating)',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Malicious admission controller (mutating)'},
    'C-0041': {   'categories': ['security'],
                  'description': 'Potential attackers may gain access to a POD '
                                 'and inherit access to the entire host '
                                 'network. For example, in AWS case, they will '
                                 'have access to the entire VPC. This control '
                                 'identifies all the PODs with host network '
                                 'access enabled.',
                  'display_name': 'HostNetwork access',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'HostNetwork access'},
    'C-0042': {   'categories': ['security'],
                  'description': 'An SSH server that is running inside a '
                                 'container may be used by attackers to get '
                                 'remote access to the container. This control '
                                 'checks if pods have an open SSH port '
                                 '(22/2222).',
                  'display_name': 'SSH server running inside container',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'SSH server running inside container'},
    'C-0044': {   'categories': ['security'],
                  'description': 'Configuring hostPort requires a particular '
                                 'port number. If two objects specify the same '
                                 'HostPort, they could not be deployed to the '
                                 'same node. It may prevent the second object '
                                 'from starting, even if Kubernetes will try '
                                 'reschedule it on another node, provided '
                                 'there are available nodes with sufficient '
                                 'amount of resources. Also, if the number of '
                                 'replicas of such workload is higher than the '
                                 'number of nodes, the deployment will '
                                 'consistently fail.',
                  'display_name': 'Container hostPort',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Container hostPort'},
    'C-0045': {   'categories': ['security'],
                  'description': 'Mounting host directory to the container can '
                                 'be used by attackers to get access to the '
                                 'underlying host and gain persistence.',
                  'display_name': 'Writable hostPath mount',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Writable hostPath mount'},
    'C-0046': {   'categories': ['security'],
                  'description': 'Giving insecure or excsessive capabilities '
                                 'to a container can increase the impact of '
                                 'the container compromise. This control '
                                 'identifies all the PODs with dangerous '
                                 'capabilities (see documentation pages for '
                                 'details).',
                  'display_name': 'Insecure capabilities',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Insecure capabilities'},
    'C-0047': {   'categories': ['security'],
                  'description': 'Kubernetes dashboard versions before v2.0.1 '
                                 'do not support user authentication. If '
                                 'exposed externally, it will allow '
                                 'unauthenticated remote management of the '
                                 'cluster. This control checks presence of the '
                                 'kubernetes-dashboard deployment and its '
                                 'version number.',
                  'display_name': 'Exposed dashboard',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Exposed dashboard'},
    'C-0048': {   'categories': ['security'],
                  'description': 'Mounting host directory to the container can '
                                 'be used by attackers to get access to the '
                                 'underlying host. This control identifies all '
                                 'the PODs using hostPath mount.',
                  'display_name': 'HostPath mount',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'HostPath mount'},
    'C-0049': {   'categories': ['security'],
                  'description': 'If no network policy is defined, attackers '
                                 'who gain access to a single container may '
                                 'use it to probe the network. This control '
                                 'lists all namespaces in which no network '
                                 'policies are defined.',
                  'display_name': 'Network mapping',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Network mapping'},
    'C-0050': {   'categories': ['security'],
                  'description': 'This control identifies all Pods for which '
                                 'the CPU limit is not set.',
                  'display_name': 'Resources CPU limit and request',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Resources CPU limit and request'},
    'C-0052': {   'categories': ['security'],
                  'description': 'Attackers who gain access to a container, '
                                 'may query the metadata API service for '
                                 'getting information about the underlying '
                                 'node. This control checks if there is access '
                                 'from the nodes to cloud providers instance '
                                 'metadata services.',
                  'display_name': 'Instance Metadata API',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Instance Metadata API'},
    'C-0053': {   'categories': ['security'],
                  'description': 'Attackers who obtain access to a pod can use '
                                 'its SA token to communicate with KubeAPI '
                                 'server. All PODs with SA token mounted (if '
                                 'such token has a Role or a ClusterRole '
                                 'binding) are considerred potentially '
                                 'dangerous.',
                  'display_name': 'Access container service account',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Access container service account'},
    'C-0054': {   'categories': ['security'],
                  'description': 'If no network policy is defined, attackers '
                                 'who gain access to a container may use it to '
                                 'move laterally in the cluster. This control '
                                 'lists namespaces in which no network policy '
                                 'is defined.',
                  'display_name': 'Cluster internal networking',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Cluster internal networking'},
    'C-0055': {   'categories': ['security'],
                  'description': 'Containers may be given more privileges than '
                                 'they actually need. This can increase the '
                                 'potential impact of a container compromise.',
                  'display_name': 'Linux hardening',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Linux hardening'},
    'C-0056': {   'categories': ['security'],
                  'description': 'Liveness probe is intended to ensure that '
                                 'workload remains healthy during its entire '
                                 'execution lifecycle, or otherwise restrat '
                                 'the container. It is highly recommended to '
                                 'define liveness probe for every worker '
                                 'container. This control finds all the PODs '
                                 'where the Liveness probe is not configured.',
                  'display_name': 'Configured liveness probe',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Configured liveness probe'},
    'C-0057': {   'categories': ['security'],
                  'description': 'Potential attackers may gain access to '
                                 'privileged containers and inherit access to '
                                 'the host resources. Therefore, it is not '
                                 'recommended to deploy privileged containers '
                                 'unless it is absolutely necessary. This '
                                 'control identifies all the privileged Pods.',
                  'display_name': 'Privileged container',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Privileged container'},
    'C-0058': {   'categories': ['security'],
                  'description': 'A user may be able to create a container '
                                 'with subPath or subPathExpr volume mounts to '
                                 'access files & directories anywhere on the '
                                 'host filesystem. Following Kubernetes '
                                 'versions are affected: v1.22.0 - v1.22.1, '
                                 'v1.21.0 - v1.21.4, v1.20.0 - v1.20.10, '
                                 'version v1.19.14 and lower. This control '
                                 'checks the vulnerable versions and the '
                                 'actual usage of the subPath feature in all '
                                 'Pods in the cluster. If you want to learn '
                                 'more about the CVE, please refer to the CVE '
                                 'link: '
                                 'https://nvd.nist.gov/vuln/detail/CVE-2021-25741',
                  'display_name': 'CVE-2021-25741 - Using symlink for '
                                  'arbitrary host file system access.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'CVE-2021-25741 - Using symlink for arbitrary host '
                           'file system access.'},
    'C-0059': {   'categories': ['security'],
                  'description': 'Security issue in ingress-nginx where a user '
                                 'that can create or update ingress objects '
                                 'can use the custom snippets feature to '
                                 'obtain all secrets in the cluster (see more '
                                 'at '
                                 'https://github.com/kubernetes/ingress-nginx/issues/7837)',
                  'display_name': 'CVE-2021-25742-nginx-ingress-snippet-annotation-vulnerability',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'CVE-2021-25742-nginx-ingress-snippet-annotation-vulnerability'},
    'C-0060': {   'categories': ['security'],
                  'description': 'It is recommended not to use default service '
                                 'account anywhere in production environment. '
                                 'This control identifies all namespaces '
                                 'without explicit non-default service '
                                 'account.',
                  'display_name': 'Namespace without service accounts',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Namespace without service accounts'},
    'C-0061': {   'categories': ['security'],
                  'description': 'It is recommended to avoid running PODs in '
                                 'cluster without explicit namespace '
                                 'assignment. This control identifies all the '
                                 'PODs running in the default namespace.',
                  'display_name': 'Pods in default namespace',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Pods in default namespace'},
    'C-0062': {   'categories': ['security'],
                  'description': 'Adding sudo to a container entry point '
                                 'command may escalate process privileges and '
                                 'allow access to forbidden resources. This '
                                 'control checks all the entry point commands '
                                 'in all containers in the POD to find those '
                                 'that have sudo command.',
                  'display_name': 'Sudo in container entrypoint',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Sudo in container entrypoint'},
    'C-0063': {   'categories': ['security'],
                  'description': 'Attackers with relevant RBAC permission can '
                                 'use “kubectl portforward” command to '
                                 'establish direct communication with PODs '
                                 'from within the cluster or even remotely. '
                                 'Such communication will most likely bypass '
                                 'existing security measures in the cluster. '
                                 'This control determines which subjects have '
                                 'permissions to use this command.',
                  'display_name': 'Portforwarding privileges',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Portforwarding privileges'},
    'C-0065': {   'categories': ['security'],
                  'description': 'Impersonation is an explicit RBAC permission '
                                 'to use other roles rather than the one '
                                 'assigned to a user, group or service '
                                 'account. This is sometimes needed for '
                                 'testing purposes. However, it is highly '
                                 'recommended not to use this capability in '
                                 'the production environments for daily '
                                 'operations. This control identifies all '
                                 'subjects whose roles include impersonate '
                                 'verb.',
                  'display_name': 'No impersonation',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'No impersonation'},
    'C-0066': {   'categories': ['security'],
                  'description': 'All Kubernetes Secrets are stored primarily '
                                 'in etcd therefore it is important to encrypt '
                                 'it.',
                  'display_name': 'Secret/ETCD encryption enabled',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Secret/ETCD encryption enabled'},
    'C-0067': {   'categories': ['security'],
                  'description': 'Audit logging is an important security '
                                 'feature in Kubernetes, it enables the '
                                 'operator to track requests to the cluster. '
                                 'It is important to use it so the operator '
                                 'has a record of events happened in '
                                 'Kubernetes',
                  'display_name': 'Audit logs enabled',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Audit logs enabled'},
    'C-0068': {   'categories': ['security'],
                  'description': 'PSP enable fine-grained authorization of pod '
                                 'creation and it is important to enable it',
                  'display_name': 'PSP enabled',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'PSP enabled'},
    'C-0069': {   'categories': ['security'],
                  'description': "By default, requests to the kubelet's HTTPS "
                                 'endpoint that are not rejected by other '
                                 'configured authentication methods are '
                                 'treated as anonymous requests, and given a '
                                 'username of system:anonymous and a group of '
                                 'system:unauthenticated.',
                  'display_name': 'Disable anonymous access to Kubelet service',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Disable anonymous access to Kubelet service'},
    'C-0070': {   'categories': ['security'],
                  'description': 'Kubelets are the node level orchestrator in '
                                 'Kubernetes control plane. They are '
                                 'publishing service port 10250 where they '
                                 'accept commands from API server. Operator '
                                 'must make sure that only API server is '
                                 'allowed to submit commands to Kubelet. This '
                                 'is done through client certificate '
                                 'verification, must configure Kubelet with '
                                 'client CA file to use for this purpose.',
                  'display_name': 'Enforce Kubelet client TLS authentication',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Enforce Kubelet client TLS authentication'},
    'C-0073': {   'categories': ['security'],
                  'description': 'It is not recommended to create PODs without '
                                 'parental Deployment, ReplicaSet, StatefulSet '
                                 'etc.Manual creation if PODs may lead to a '
                                 'configuration drifts and other untracked '
                                 "changes in the system. Such PODs won't be "
                                 'automatically rescheduled by Kubernetes in '
                                 'case of a crash or infrastructure failure. '
                                 'This control identifies every POD that does '
                                 'not have corresponding parental object.',
                  'display_name': 'Naked PODs',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Naked PODs'},
    'C-0074': {   'categories': ['security'],
                  'description': 'Mounting Docker socket (Unix socket) enables '
                                 'container to access Docker internals, '
                                 'retrieve sensitive information and execute '
                                 'Docker commands, if Docker runtime is '
                                 'available. This control identifies PODs that '
                                 'attempt to mount Docker socket for accessing '
                                 'Docker runtime.',
                  'display_name': 'Containers mounting Docker socket',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Containers mounting Docker socket'},
    'C-0075': {   'categories': ['security'],
                  'description': 'While usage of the latest tag is not '
                                 'generally recommended, in some cases this is '
                                 'necessary. If it is, the ImagePullPolicy '
                                 'must be set to Always, otherwise Kubernetes '
                                 'may run an older image with the same name '
                                 'that happens to be present in the node '
                                 'cache. Note that using Always will not cause '
                                 'additional image downloads because '
                                 'Kubernetes will check the image hash of the '
                                 'local local against the registry and only '
                                 'pull the image if this hash has changed, '
                                 'which is exactly what users want when use '
                                 'the latest tag. This control will identify '
                                 'all PODs with latest tag that have '
                                 'ImagePullSecret not set to Always.',
                  'display_name': 'Image pull policy on latest tag',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Image pull policy on latest tag'},
    'C-0076': {   'categories': ['security'],
                  'description': 'It is recommended to set labels that '
                                 'identify semantic attributes of your '
                                 'application or deployment. For example, { '
                                 'app: myapp, tier: frontend, phase: test, '
                                 'deployment: v3 }. These labels can used to '
                                 'assign policies to logical groups of the '
                                 'deployments as well as for presentation and '
                                 'tracking purposes. This control helps you '
                                 'find deployments without any of the expected '
                                 'labels.',
                  'display_name': 'Label usage for resources',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Label usage for resources'},
    'C-0077': {   'categories': ['security'],
                  'description': 'Kubernetes common labels help manage and '
                                 'monitor Kubernetes cluster using different '
                                 'tools such as kubectl, dashboard and others '
                                 'in an interoperable way. Refer to '
                                 'https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/ '
                                 'for more information. This control helps you '
                                 "find objects that don't have any of these "
                                 'labels defined.',
                  'display_name': 'K8s common labels usage',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'K8s common labels usage'},
    'C-0078': {   'categories': ['security'],
                  'description': 'This control is intended to ensure that all '
                                 'the used container images are taken from the '
                                 'authorized repositories. It allows user to '
                                 'list all the approved repositories and will '
                                 'fail all the images taken from any '
                                 'repository outside of this list.',
                  'display_name': 'Images from allowed registry',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Images from allowed registry'},
    'C-0079': {   'categories': ['security'],
                  'description': 'CVE-2022-0185 is a kernel vulnerability '
                                 'enabling privilege escalation and it can '
                                 'lead attackers to escape containers and take '
                                 'control over nodes. This control alerts on '
                                 'vulnerable kernel versions of Kubernetes '
                                 'nodes',
                  'display_name': 'CVE-2022-0185-linux-kernel-container-escape',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'CVE-2022-0185-linux-kernel-container-escape'},
    'C-0081': {   'categories': ['security'],
                  'description': 'CVE-2022-24348 is a major software supply '
                                 'chain 0-day vulnerability in the popular '
                                 'open source CD platform Argo CD which can '
                                 'lead to privilege escalation and information '
                                 'disclosure.',
                  'display_name': 'CVE-2022-24348-argocddirtraversal',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'CVE-2022-24348-argocddirtraversal'},
    'C-0083': {   'categories': ['security'],
                  'description': 'Container images with known critical '
                                 'vulnerabilities pose elevated risk if they '
                                 'are exposed to the external traffic. This '
                                 'control lists all images with such '
                                 'vulnerabilities if either LoadBalancer or '
                                 'NodePort service is assigned to them.',
                  'display_name': 'Workloads with Critical vulnerabilities '
                                  'exposed to external traffic',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Workloads with Critical vulnerabilities exposed to '
                           'external traffic'},
    'C-0084': {   'categories': ['security'],
                  'description': 'Container images with known Remote Code '
                                 'Execution (RCE) vulnerabilities pose '
                                 'significantly higher risk if they are '
                                 'exposed to the external traffic. This '
                                 'control lists all images with such '
                                 'vulnerabilities if their POD has either '
                                 'LoadBalancer or NodePort service.',
                  'display_name': 'Workloads with RCE vulnerabilities exposed '
                                  'to external traffic',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Workloads with RCE vulnerabilities exposed to '
                           'external traffic'},
    'C-0085': {   'categories': ['security'],
                  'description': 'Container images with multiple Critical and '
                                 'High sevirity vulnerabilities increase the '
                                 'risk of potential exploit. This control '
                                 'lists all such images according to the '
                                 'threashold provided by the customer.',
                  'display_name': 'Workloads with excessive amount of '
                                  'vulnerabilities',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Workloads with excessive amount of '
                           'vulnerabilities'},
    'C-0086': {   'categories': ['security'],
                  'description': 'Linux Kernel vulnerability CVE-2022-0492 may '
                                 'allow malicious code running inside '
                                 'container to escape container isolation and '
                                 'gain root privileges on the entire node. '
                                 'When fixed Kernel version numbers will '
                                 'become available, this control will be '
                                 'modified to verify them and avoid false '
                                 'positive detections. This control identifies '
                                 "all the resources that don't deploy neither "
                                 'AppArmor nor SELinux, run as root or allow '
                                 'privige escalation or have corresponding '
                                 'dangerous capabilities.',
                  'display_name': 'CVE-2022-0492-cgroups-container-escape',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'CVE-2022-0492-cgroups-container-escape'},
    'C-0087': {   'categories': ['security'],
                  'description': 'CVE-2022-23648 is a vulnerability of '
                                 'containerd enabling attacker to gain access '
                                 'to read-only copies of arbitrary files from '
                                 'the host using aspecially-crafted POD '
                                 'configuration yamls',
                  'display_name': 'CVE-2022-23648-containerd-fs-escape',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'CVE-2022-23648-containerd-fs-escape'},
    'C-0088': {   'categories': ['security'],
                  'description': 'RBAC is the most advanced and well accepted '
                                 'mode of authorizing users of the Kubernetes '
                                 'API',
                  'display_name': 'RBAC enabled',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'RBAC enabled'}}
