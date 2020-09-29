module github.com/openshift/cluster-authentication-operator

go 1.14

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/getsentry/raven-go v0.2.1-0.20190513200303-c977f96e1095 // indirect
	github.com/ghodss/yaml v1.0.0
	github.com/go-bindata/go-bindata v3.1.2+incompatible
	github.com/openshift/api master 
	github.com/openshift/build-machinery-go master
	github.com/openshift/client-go master
	github.com/openshift/library-go master 
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.4.0
	go.etcd.io/etcd v0.5.0-alpha.5.0.20200819165624-17cef6e3e9d5
	go.uber.org/multierr v1.1.1-0.20180122172545-ddea229ff1df // indirect
	gopkg.in/square/go-jose.v2 v2.2.2
	gopkg.in/yaml.v2 v2.3.0
	k8s.io/api v0.19.2
	k8s.io/apimachinery v0.19.2
	k8s.io/apiserver v0.19.2
	k8s.io/client-go v0.19.2
	k8s.io/component-base v0.19.2
	k8s.io/klog/v2 v2.3.0
	k8s.io/kube-aggregator v0.19.2
	k8s.io/utils v0.0.0-20200729134348-d5654de09c73
	sigs.k8s.io/kube-storage-version-migrator v0.0.3
)

replace vbom.ml/util => github.com/fvbommel/util v0.0.0-20180919145318-efcd4e0f9787
