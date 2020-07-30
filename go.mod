module github.com/openshift/cluster-authentication-operator

go 1.13

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/getsentry/raven-go v0.2.1-0.20190513200303-c977f96e1095 // indirect
	github.com/ghodss/yaml v1.0.0
	github.com/go-bindata/go-bindata v3.1.2+incompatible
	github.com/kubernetes-sigs/kube-storage-version-migrator v0.0.0-20191127225502-51849bc15f17
	github.com/openshift/api v0.0.0-20200723134351-89de68875e7c
	github.com/openshift/apiserver-library-go v0.0.0-20200521171520-a7bc13e3e650
	github.com/openshift/build-machinery-go v0.0.0-20200713135615-1f43d26dccc7
	github.com/openshift/client-go v0.0.0-20200722173614-5a1b0aaeff15
	github.com/openshift/library-go v0.0.0-20200730143437-a1811581365b
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.4.0
	go.etcd.io/etcd v0.5.0-alpha.5.0.20200716221620-18dfb9cca345
	gopkg.in/square/go-jose.v2 v2.2.2
	gopkg.in/yaml.v2 v2.3.0
	k8s.io/api v0.19.0-rc.2
	k8s.io/apimachinery v0.19.0-rc.2
	k8s.io/apiserver v0.19.0-rc.2
	k8s.io/client-go v0.19.0-rc.2
	k8s.io/component-base v0.19.0-rc.2
	k8s.io/klog v1.0.0
	k8s.io/kube-aggregator v0.19.0-rc.2
	k8s.io/utils v0.0.0-20200720150651-0bdb4ca86cbc
)

replace (
	github.com/kubernetes-sigs/kube-storage-version-migrator => github.com/openshift/kubernetes-kube-storage-version-migrator v0.0.3-0.20200312103335-32e07ea4f8ca
	k8s.io/api => k8s.io/api v0.19.0-rc.2
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.19.0-rc.2
	k8s.io/apimachinery => k8s.io/apimachinery v0.19.0-rc.2
	k8s.io/apiserver => k8s.io/apiserver v0.19.0-rc.2
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.19.0-rc.2
	k8s.io/client-go => k8s.io/client-go v0.19.0-rc.2
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.19.0-rc.2
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.19.0-rc.2
	k8s.io/code-generator => k8s.io/code-generator v0.19.0-rc.2
	k8s.io/component-base => k8s.io/component-base v0.19.0-rc.2
	k8s.io/cri-api => k8s.io/cri-api v0.19.0-rc.2
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.19.0-rc.2
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.19.0-rc.2
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.19.0-rc.2
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.19.0-rc.2
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.19.0-rc.2
	k8s.io/kubectl => k8s.io/kubectl v0.19.0-rc.2
	k8s.io/kubelet => k8s.io/kubelet v0.19.0-rc.2
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.19.0-rc.2
	k8s.io/metrics => k8s.io/metrics v0.19.0-rc.2
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.19.0-rc.2
)
