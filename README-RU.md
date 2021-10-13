# Kubernetes Security Checklist and Requirements - All in One

- **Аутентификация**
  - [ ] Рекомендуется использовать сторонний IdP сервер в качестве стороннего провайдера для аутентификации пользователей в API Kubernetes (например, с использованием [OIDC](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens)). Администраторам кластера не рекомендуется использовать токены service account для аутентификации.
  - [ ] Для управления сертификатами внутри кластера (пользовательские и сервисные) рекомендуется использовать сторонний централизованный сервис управления сертификатами.
  - [ ] Пользовательские УЗ должны быть персонализированы. Названия сервисных УЗ должны отражать назначение УЗ и используемые права доступа.
- **Авторизация**
  - [ ] Для каждого кластера должна быть проработана ролевая модель доступа. 
  - [ ] Для кластера Kubernetes должен быть настроен Role-Based Access Control ([RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)). Права должны назначаться в пределах пространства имен проекта по принципу наименьших привилегий (least privilege) и разделения полномочий (seperation of duties) ([RBAC-tool](https://github.com/alcideio/rbac-tool)).
  - [ ] Все сервисы должны обладать уникальным service account с настроенными правами RBAC.
  - [ ] Разработчики не должны иметь доступ к препродуктивной и продуктивной среде без согласования с командой безопасности.
  - [ ] Запрещено использовать средства [user impersonation](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation) (возможность выполнять действия под другой УЗ).
  - [ ] Запрещено использовать анонимную аутентификацию, кроме ```/healthz```, ```/readyz```, ```/livez```. Исключения должны согласовываться с командой безопасности.
  - [ ] Администраторы кластера и функциональное сопровождение должны взаимодействовать с API кластера и инфраструктурными сервисами через решение контроля привилегированных пользователей ([Teleport](https://goteleport.com/docs/kubernetes-access/introduction/), [Boundary](https://www.hashicorp.com/blog/gating-access-to-kubernetes-with-hashicorp-boundary)).
  - [ ] Все компоненты каждой информационной системы должны быть разделены на отдельные пространства имен (namespaces), при этом рекоммендуется избегать ситуации, когда одна и та же команда сопровождения ответственная за разные пространства имен.
  - [ ] Права RBAC необходимо регулярно подвергать аудиту ([KubiScan](https://github.com/cyberark/KubiScan), [Krane](https://github.com/appvia/krane))
- **Безопасная работа с секретами**
  - [ ] Сформированные секреты храниться в защищенном стороннем хранилище ([HashiCorp Vault](https://www.vaultproject.io/docs/platform/k8s), [Conjur](https://www.conjur.org/blog/securing-secrets-in-kubernetes/)), либо в etcd в зашифрованном виде.
  - [ ] Объекты типа "secrets" должны добавляться в контейнер с использованием механизма volumeMount или механизма secretKeyRef.  Для сокрытия секретов в исходных кодах может использоваться, например, инструмент [sealed-secret](https://github.com/bitnami-labs/sealed-secrets). 
- **Безопасность конфигурации кластера**
  - [ ] Должно быть включено повсеместное использование шифрования TLS между компонентами кластера. 
  - [ ] Должно использоваться стороннее решение, поддерживающее механизм настраиваемых политик безопасности ([OPA](https://www.openpolicyagent.org/docs/v0.12.2/kubernetes-admission-control/), [Kyverno](https://kyverno.io/)).
  - [ ] Конфигурацию кластера рекомендуется соответствовать [CIS Benchmark](https://www.cisecurity.org/benchmark/kubernetes/) за исключением [требований к PSP](https://kubernetes.io/blog/2021/04/06/podsecuritypolicy-deprecation-past-present-and-future/). 
  - [ ] Рекомендуется использовать только последние версии компонентов кластера ([CVE list](https://www.container-security.site/general_information/container_cve_list.html)).
  - [ ] Для сервисов с повышенными требованиями к безопасности рекомендуется использовать low-lever run-time с высокой степенью изоляцией ([gVisior](https://gvisor.dev/docs/user_guide/quick_start/kubernetes/), [Kata-runtime](https://github.com/kata-containers/documentation/blob/master/how-to/run-kata-with-k8s.md)).
  - [ ] Конфигурация кластера должна регулярно подвергаться аудиту ([Kube-bench](https://github.com/aquasecurity/kube-bench), [Kube-hunter](https://github.com/aquasecurity/kube-hunter), [Kubestriker](https://www.kubestriker.io/))
- **Логирование**
  - [ ] Необходимо фиксировать все случаи изменения прав доступа в кластере.
  - [ ] Необходимо фиксировать все операции с секретами (включая неавторизованный доступ к секретам). При этом фиксация значений секретов должна быть исключена.
  - [ ] Необходимо фиксировать все действия администраторов сопровождения и администраторов кластера, связанных с развертыванием приложений и изменением их конфигурации.
  - [ ] Необходимо фиксировать все случаи изменения параметров, системных настроек или конфигурации всего кластера. В том числе средствами на уровне ОС.
  - [ ] Все зарегистрированные события безопасности, как на уровне кластера, так и на уровне приложения должны передаваться в централизованную систему аудита/логирования (SIEM).
  - [ ] Используемая подсистема аудита должна быть расположена вне кластера Kubernetes.
  - [ ] Выстроить процессы observability и visibility для того, чтобы понимать происходящее в инфраструктуре и сервисах([Luntry](https://luntry.com/), [WaveScope](https://github.com/weaveworks/scope))
  - [ ] На всех нодах должно быть запущено стороннее решение для реализации мониторинга безопасности ([Falco](https://falco.org/), [Sysdig](https://sysdig.com/), [Aqua Enterpise](https://www.aquasec.com/), [NeuVector](https://neuvector.com/), [Prisma Cloud Compute](https://www.paloaltonetworks.com/prisma/cloud)).
- **Безопасность конфигурации ОС**
  - [ ] Администрирование хостов должно осуществляться через стороннее решение, логирующее действия пользователя (в т.ч. bastion host). Также может использоваться ОС без возможности удаленного подключения.
  - [ ] Рекомендуется конфигурировать ОС и ПО в соответствии с baseline и стандартами ([CIS](https://www.cisecurity.org/cis-benchmarks/), [NIST](https://ncp.nist.gov/repository)).
  - [ ] Рекомендуется регулярно сканировать пакеты на наличие уязвимостей([OpenSCAP профили](https://static.open-scap.org/), [Lynis](https://cisofy.com/lynis/)).
  - [ ] Рекомендуется регулярно обновлять версию ядра ОС ([CVEhound](https://github.com/evdenis/cvehound)).
- **Безопасность сети**
  - [ ] Все пространства имен должны обладать NetworkPolicy. Взаимодействия между пространствами имен должны быть ограничены NetworkPolicy по принципам Least Privileges ([Inspektor Gadget](https://github.com/kinvolk/inspektor-gadget)).
  - [ ] При организации микросервисного взаимодействия, рекомендуется, чтобы каждый сервис проходил аутентификацию и авторизацию ([Istio](https://platform9.com/blog/kubernetes-service-mesh-how-to-set-up-istio/), [Linkerd](https://platform9.com/blog/how-to-set-up-linkerd-as-a-service-mesh-for-platform9-managed-kubernetes/), [Consul](https://www.consul.io/docs/architecture)).
  - [ ] Интерфейсы компонентов кластера и инструментов инфраструктуры запрещено публиковать в сети в Интернет.
  - [ ] Инфраструктурные сервисы, control plane и хранилища данных должны быть расположены в отдельном VLAN на изолированных нодах.
  - [ ] Внешний пользовательский трафик, проходящий внутрь кластера, должен инспектироваться с помощью WAF.
  - [ ] Рекомендуется разделять ноды кластера, взаимодействующие с сетью Интернет (DMZ), от нод кластера, взаимодействующих с внутренними сервисами. Разграничение может быть в рамках одного кластера, либо в рамках двух разных кластеров (DMZ и VLAN).
- **Безопасность конфигурации разворачиваемых приложений**
  - [ ] Запрещено запускать поды под учетной записью [root](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/) - UID 0.
  - [ ] Для всех сервисов должен быть установлен [параметр]((https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-security-context-for-a-pod)) ```runAsUser```.
  - [ ] Должен быть выставлен [параметр](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/) ```allowPrivilegeEscalation - false```.
  - [ ] Запрещен запуск [привилегированного пода](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/) (```privileged: true```).
  - [ ] Рекомендуется выставлен [параметр](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/) ```readonlyRootFilesystem - true```.
  - [ ] [Запрещено](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces) использовать ```hostPID``` и ```hostIPC```.
  - [ ] [Запрещено](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces) использовать ```hostNetwork```.
  - [ ] [Запрещено](https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/) использование небезопасных системных вызовов (sysctl):
    - ```kernel.shm*```,
    - ```kernel.msg*```,
    - ```kernel.sem```,
    - ```fs.mqueue.*```,
  - [ ] [Запрещено](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems) использовать ```hostPath```.
  - [ ] Должны быть выставлены [ограничения](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/) на CPU/RAM. Значения должны быть минимально достаточным для работы контейнеризированного приложения. 
  - [ ] [Capabilities](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/) должны выдаваться по принципу наименьших привилегий (drop 'ALL', после чего перечисление всех необходимых сapabilities для работы приложения, при этом запрещено использовать:
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
  - [ ] Запрещено использовать пространство имен по умолчанию (default).
  - [ ] Приложение должно иметь профиль seccomp, apparmor или selinux по принципам least privileges ([Udica](https://github.com/containers/udica), [Oci-seccomp-bpf-hook](https://github.com/containers/oci-seccomp-bpf-hook), [Go2seccomp](https://github.com/xfernando/go2seccomp), [Security Profiles Operator](https://github.com/kubernetes-sigs/security-profiles-operator)).
  -  [ ] Конфигурация приложений должна регулярно подвергаться аудиту ([Kics](https://checkmarx.com/product/opensource/kics-open-source-infrastructure-as-code-project/),  [Kubeaudit](https://github.com/Shopify/kubeaudit), [Kubescape](https://github.com/armosec/kubescape), [Conftest](https://github.com/open-policy-agent/conftest),  [Kubesec](https://github.com/controlplaneio/kubesec), [Checkov](https://github.com/bridgecrewio/checkov))
- **Безопасная разработка образа**
  - [ ] Запрещено использовать конструкцию ```RUN``` с ```sudo```.
  - [ ] Рекомендуется не использовать тэг ```latest```.
  - [ ] Вместо инструкции ```ADD``` требуется использовать ```COPY```. 
  - [ ] Запрещено использовать автоматическое обновление пакетов через ```apt-get upgrade```, ```yum update```, ```apt-get dist-upgrade```. 
  - [ ] Необходимо явно указывать версии устанавливаемых пакетов. Для определения перечня используемых пакетов могут использоваться инструменты для построения SBOM ([Syft](https://github.com/anchore/syft)).
  - [ ] Запрещено хранить чувствительную информацию (пароли, токены, сертификаты) в Dockerfile.
  - [ ] Состав пакетов в образе контейнера должен быть минимально достаточен для работы. Неиспользуемые в ходе работы контейнеризированного приложения пакеты должны отсутствовать в образе контейнера.
  - [ ] Не рекомендуется устанавливать ```wget```, ```curl```, ```netcat```, внутри образа и контейнера продуктивного приложения.
  - [ ] Состав пробрасываемых в контейнер портов должен быть минимально достаточен для работы. Неиспользуемые в ходе работы контейнеризированного приложения порты не должны использоваться в контейнере.
  - [ ] Рекомендуется использовать ```dockerignore``` для предотвращения помещения чувствительной информации внутрь образа.
  - [ ] Рекомендуется использовать минимальное количество слоев используя [многоступенчатую сборку](https://docs.docker.com/develop/develop-images/multistage-build/).
  - [ ] Рекомендуется использовать ```WORKDIR``` в качестве абсолютного пути. Не рекомендуется использовать ```cd``` вместо ```WORKDIR```.
  - [ ] При скачивании пакетов из Интернета в процессе сборки, рекомендуется проверять целостность этих пакетов. 
  - [ ] Рекомендуется остерегаться рекурсивного копирование с помощью конструкции ```COPY . .```
  - [ ] Запрещено запускать средства удаленного управления в контейнере.
  - [ ] По результатам сканирования образов Docker должна формироваться подпись образа, которая будет проверяться перед развертыванием ([Notary, Cosign](https://medium.com/sse-blog/verify-container-image-signatures-in-kubernetes-using-notary-or-cosign-or-both-c25d9e79ec45)).
  - [ ] Dockerfile должны проверяться в процессе разработки автоматизированными сканнерами ([Kics](https://checkmarx.com/product/opensource/kics-open-source-infrastructure-as-code-project/), [Hadolint](https://github.com/hadolint/hadolint), [Conftest](https://github.com/open-policy-agent/conftest)).
  - [ ] Все образы должны проверяться в жизненном цикле приложения автоматизированными сканнерами ([Trivy](https://github.com/aquasecurity/trivy), [Clair](https://github.com/quay/clair), [Grype](https://github.com/anchore/grype)). 
  - [ ] Должна быть выстроена безопасность CI и CD, а также безопасность цепочки поставок([SLSA](https://github.com/slsa-framework/slsa))

#
<a href="https://kubernetes.io/">
    <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/8/83/Telegram_2019_Logo.svg/1200px-Telegram_2019_Logo.svg.png"
         alt="Kubernetes logo" title="Kubernetes" height="50" width="50" />
</a></br>


## Полезный контент
- Обсуждение на тему безопасности Kubernetes можно продолжить в нашем Telegram-чате: [DevSecOps Chat](https://t.me/sec_devops_chat)
- Канал автора чеклиста: [DevSecOps Wine](https://t.me/sec_devops)
- Чеклист был подготовлен при поддержке автора канала [k8security](https://t.me/k8security)








