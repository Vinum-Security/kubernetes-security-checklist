# Kubernetes Security Checklist and Requirements

There are many ways to make your cluster secure, but we have chosen only one, the most difficult and controversial in some places. We do not guarantee that it will be completely suitable for your infrastructure, but we hope this checklist can help you include those things that you may have forgotten and left out.


![Docker Security Guide копия](https://user-images.githubusercontent.com/34271513/136924844-1bb4d2c5-1f23-4c71-91b5-499e7f7f533d.png)

- **Authentication**
  - [ ] It is recommended to use an IdP server as a provider for user authentication to the Kubernetes API (for example, using [OIDC](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens)). Cluster administrators are advised not to use service account tokens for authentication.
  - [ ] It is recommended to use a centralized certificate management service to manage certificates within the cluster (for user and service purposes).
  - [ ] User accounts should be personalized. The names of the service accounts should reflect the purpose access rights of the accounts.
- **Authorization**
  - [ ] For each cluster, a role-based access model should be developed.
  - [ ] [Role-Based Access Control (RBAC)](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) should be configured for the Kubernetes cluster. Rights need to be assigned within the project namespace based on least privilege and separation of duties ([RBAC-tool](https://github.com/alcideio/rbac-tool)).
  - [ ] All services should have a unique service account with configured RBAC rights.
  - [ ] Developers should not have access to a production environment without the approval of the security team.
  - [ ] It is forbidden to use [user impersonation](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation) (the ability to perform actions under other accounts).
  - [ ] It is forbidden to use anonymous authentication, except for ```/healthz```, ```/readyz```, ```/livez```. Exceptions should be agreed upon with the security team.
  - [ ] Cluster administrators and maintainers should interact with the cluster API and infrastructure services through privileged access management systems  ([Teleport](https://goteleport.com/docs/kubernetes-access/introduction/), [Boundary](https://www.hashicorp.com/blog/gating-access-to-kubernetes-with-hashicorp-boundary)).
  - [ ] All information systems should be divided into separate namespaces. It is recommended to avoid the situation when the same maintainer team is responsible for different namespaces.
  - [ ] RBAC Rights should be audited regularly ([KubiScan](https://github.com/cyberark/KubiScan), [Krane](https://github.com/appvia/krane))
- **Secure work with secrets**
  - [ ] Secrets should be stored in third-party storage ([HashiCorp Vault](https://www.vaultproject.io/docs/platform/k8s), [Conjur](https://www.conjur.org/blog/securing-secrets-in-kubernetes/)), or in etcd in encrypted form.
  - [ ] Secrets should be added to the container using the volumeMount mechanism or the secretKeyRef mechanism. For hiding secrets in source codes, for example, the [sealed-secret](https://github.com/bitnami-labs/sealed-secrets) tool can be used.
- **Cluster Configuration Security**
  - [ ] Use TLS encryption between all cluster components.
  - [ ] Use Policy engine ([OPA](https://www.openpolicyagent.org/docs/v0.12.2/kubernetes-admission-control/), [Kyverno](https://kyverno.io/), [jsPolicy](https://www.jspolicy.com), [Kubewarden](https://www.kubewarden.io)).
  - [ ] The cluster configuration is recommended to comply with [CIS Benchmark](https://www.cisecurity.org/benchmark/kubernetes/) except for [PSP requirements](https://kubernetes.io/blog/2021/04/06/podsecuritypolicy-deprecation-past-present-and-future/).
  - [ ] It is recommended to use only the latest versions of cluster components ([CVE list](https://www.container-security.site/general_information/container_cve_list.html)).
  - [ ] For services with increased security requirements, it is recommended to use a low-level run-time with a high degree of isolation ([gVisor](https://gvisor.dev/docs/user_guide/quick_start/kubernetes/), [Kata-runtime](https://github.com/kata-containers/documentation/blob/master/how-to/run-kata-with-k8s.md)).
  - [ ] Cluster Configuration should be audited regularly ([Kube-bench](https://github.com/aquasecurity/kube-bench), [Kube-hunter](https://github.com/aquasecurity/kube-hunter), [Kubestriker](https://www.kubestriker.io/))
- **Audit and Logging**
  - [ ] Log all cases of changing access rights in the cluster.
  - [ ] Log all operations with secrets (including unauthorized access to secrets).
  - [ ] Log all actions related to the deployment of applications and changes in their configuration.
  - [ ] Log all cases of changing parameters, system settings, or configuration of the entire cluster (including OS level).
  - [ ] All registered security events (at the cluster level and  application level both) should be sent to the centralized audit logging system (SIEM).
  - [ ] The audit logging system should be located outside the Kubernetes cluster.
  - [ ] Build observability and visibility processes in order to understand what is happening in infrastructure and services ([Luntry](https://luntry.com/), [WaveScope](https://github.com/weaveworks/scope))
  - [ ] Use third-party security monitoring tool on all cluster nodes ([Falco](https://falco.org/), [Sysdig](https://sysdig.com/), [Aqua Enterpise](https://www.aquasec.com/), [NeuVector](https://neuvector.com/), [Prisma Cloud Compute](https://www.paloaltonetworks.com/prisma/cloud)).
- **Secure OS configuration**
  - [ ] Host administrators and maintainers should interact with cluster nodes through privileged access management systems (or bastion hosts).
  - [ ] It is recommended to configure the OS and software following the baseline and standards ([CIS](https://www.cisecurity.org/cis-benchmarks/), [NIST](https://ncp.nist.gov/repository)).
  - [ ] It is recommended to regularly scan packages and configuration for vulnerabilities([OpenSCAP profiles](https://static.open-scap.org/), [Lynis](https://cisofy.com/lynis/)).
  - [ ] It is recommended to regularly update the OS kernel version ([CVEhound](https://github.com/evdenis/cvehound)).
- **Network Security**
  - [ ] All namespaces should have NetworkPolicy. Interactions between namespaces should be limited to NetworkPolicy following least privileges principles ([Inspektor Gadget](https://github.com/kinvolk/inspektor-gadget)).
  - [ ] It is recommended to use authentication and authorization between all application microservices ([Istio](https://platform9.com/blog/kubernetes-service-mesh-how-to-set-up-istio/), [Linkerd](https://platform9.com/blog/how-to-set-up-linkerd-as-a-service-mesh-for-platform9-managed-kubernetes/), [Consul](https://www.consul.io/docs/architecture)).
  - [ ] The interfaces of the cluster components and infrastructure tools should not be published on the Internet.
  - [ ] Infrastructure services, control plane, and data storage should be located in a separate VLAN on isolated nodes.
  - [ ] External user traffic passing into the cluster should be inspected using WAF.
  - [ ] It is recommended to separate the cluster nodes interacting with the Internet (DMZ) from the cluster nodes interacting with internal services. Delimitation can be within one cluster, or within two different clusters (DMZ and VLAN).
- **Secure configuration of workloads**
  - [ ] Do not run pods under the [root account](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/) - UID 0.
  - [ ] [Set](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-security-context-for-a-pod) ```runAsUser``` parameter for all applications.
  - [ ] [Set](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/) ```allowPrivilegeEscalation - false```.
  - [ ] Do not run the [privileged pod](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/) (```privileged: true```).
  - [ ] It is recommended to [set](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/) ```readonlyRootFilesystem - true```.
  - [ ] [Do not](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces) use ```hostPID``` and ```hostIPC```.
  - [ ] [Do not](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces) use ```hostNetwork```.
  - [ ] [Do not](https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/) use unsafe system calls (sysctl):
    - ```kernel.shm *```,
    - ```kernel.msg *```,
    - ```kernel.sem```,
    - ```fs.mqueue. *```,
  - [ ] [Do not](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems) use ```hostPath```.
  - [ ] [Use](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/) CPU / RAM limits. The values should be the minimum for the containerized application to work.
  - [ ] [Capabilities](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/) should be set according to the principle of least privileges (drop 'ALL', after which all the necessary capacities for the application to work are enumerated, while it is prohibited to use:
    - ```CAP_FSETID```,
    - ```CAP_SETUID```,
    - ```CAP_SETGID```,
    - ```CAP_SYS_CHROOT```,
    - ```CAP_SYS_PTRACE```,
    - ```CAP_CHOWN```,
    - ```CAP_NET_RAW```,
    - ```CAP_NET_ADMIN```,
    - ```CAP_SYS_ADMIN```,
    - ```CAP_NET_BIND_SERVICE```)
  - [ ] Do not use the default namespace (```default```).
  - [ ] The application should have a seccomp, apparmor or selinux profile according to the principles of least privileges ([Udica](https://github.com/containers/udica), [Oci-seccomp-bpf-hook](https://github.com/containers/oci-seccomp-bpf-hook), [Go2seccomp](https://github.com/xfernando/go2seccomp), [Security Profiles Operator](https://github.com/kubernetes-sigs/security-profiles-operator)).
  - [ ] Workload configuration should be audited regularly ([Kics](https://checkmarx.com/product/opensource/kics-open-source-infrastructure-as-code-project/),  [Kubeaudit](https://github.com/Shopify/kubeaudit), [Kubescape](https://github.com/armosec/kubescape), [Conftest](https://github.com/open-policy-agent/conftest),  [Kubesec](https://github.com/controlplaneio/kubesec), [Checkov](https://github.com/bridgecrewio/checkov))
- **Secure image development**
  - [ ] Do not use ```RUN``` construct with ```sudo```.
  - [ ] ```COPY``` is required instead of ```ADD``` instruction.
  - [ ] Do not use automatic package update via ```apt-get upgrade```, ```yum update```, ```apt-get dist-upgrade```.
  - [ ] It is necessary to explicitly indicate the versions of the installed packages. The SBOM building tools ([Syft](https://github.com/anchore/syft)) can be used to determine the list of packages.
  - [ ] Do not store sensitive information (passwords, tokens, certificates) in the Dockerfile.
  - [ ] The composition of the packages in the container image should be minimal enough to work.
  - [ ] The port range forwarded into the container should be minimal enough to work. 
  - [ ] It is not recommended to install ```wget```, ```curl```, ```netcat``` inside the production application image and container.
  - [ ] It is recommended to use ```dockerignore``` to prevent putting sensitive information inside the image.
  - [ ] It is recommended to use a minimum number of layers using a [multi-stage build](https://docs.docker.com/develop/develop-images/multistage-build/).
  - [ ] It is recommended to use ```WORKDIR``` as an absolute path. It is not recommended to use ```cd``` instead of ```WORKDIR```.
  - [ ] It is recommended to beware of recursive copying using ```COPY . ..```
  - [ ] It is recommended not to use the ```latest``` tag.
  - [ ] When downloading packages from the Internet during the build process, it is recommended to check the integrity of these packages.
  - [ ] Do not run remote control tools in a container.
  - [ ] Based on the results of scanning Docker images, an image signature should be generated, which will be verified before deployment ([Notary, Cosign](https://medium.com/sse-blog/verify-container-image-signatures-in-kubernetes-using-notary-or-cosign-or-both-c25d9e79ec45)).
  - [ ] Dockerfile should be checked during development by automated scanners ([Kics](https://checkmarx.com/product/opensource/kics-open-source-infrastructure-as-code-project/), [Hadolint](https://github.com/hadolint/hadolint), [Conftest](https://github.com/open-policy-agent/conftest)).
  - [ ] All images should be checked in the application lifecycle by automated scanners ([Trivy](https://github.com/aquasecurity/trivy), [Clair](https://github.com/quay/clair), [Grype](https://github.com/anchore/grype)). 
  - [ ] Build secure CI and CD as same as suply chain process ([SLSA](https://github.com/slsa-framework/slsa))

#
<a href="https://kubernetes.io/">
    <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/8/83/Telegram_2019_Logo.svg/1200px-Telegram_2019_Logo.svg.png"
         alt="Kubernetes logo" title="Kubernetes" height="50" width="50" />
</a></br>

## Feedback
- Our Telegram-chat: [DevSecOps Chat](https://t.me/sec_devops_chat)
- Our Twitter: [@vinumsec](https://twitter.com/vinumsec)
