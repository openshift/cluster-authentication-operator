module github.com/openshift/cluster-authentication-operator

go 1.15

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/ghodss/yaml v1.0.0
	github.com/go-bindata/go-bindata v3.1.2+incompatible
	github.com/openshift/api v0.0.0-20210325044225-ef3741adfc31
	github.com/openshift/build-machinery-go v0.0.0-20200917070002-f171684f77ab
	github.com/openshift/client-go v0.0.0-20201214125552-e615e336eb49
	github.com/openshift/library-go v0.0.0-20210330091740-2cdeb5011837
	github.com/spf13/cobra v1.1.1
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.6.1
	go.etcd.io/etcd v0.5.0-alpha.5.0.20200910180754-dd1b699fc489
	go.uber.org/multierr v1.1.1-0.20180122172545-ddea229ff1df // indirect
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	gopkg.in/square/go-jose.v2 v2.2.2
	gopkg.in/yaml.v2 v2.3.0
	k8s.io/api v0.20.1
	k8s.io/apimachinery v0.20.1
	k8s.io/apiserver v0.20.1
	k8s.io/client-go v0.20.1
	k8s.io/component-base v0.20.1
	k8s.io/klog/v2 v2.4.0
	k8s.io/kube-aggregator v0.20.1
	k8s.io/utils v0.0.0-20201110183641-67b214c5f920
	sigs.k8s.io/kube-storage-version-migrator v0.0.3
)
