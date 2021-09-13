module github.com/openshift/cluster-authentication-operator

go 1.16

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/ghodss/yaml v1.0.0
	github.com/go-bindata/go-bindata v3.1.2+incompatible
	github.com/openshift/api v0.0.0-20210831091943-07e756545ac1
	github.com/openshift/build-machinery-go v0.0.0-20210806203541-4ea9b6da3a37
	github.com/openshift/client-go v0.0.0-20210831095141-e19a065e79f7
	github.com/openshift/library-go v0.0.0-20210906100234-6754cfd64cb5
	github.com/spf13/cobra v1.1.3
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.7.0
	go.etcd.io/etcd/client/v3 v3.5.0
	golang.org/x/net v0.0.0-20210520170846-37e1c6afe023
	gopkg.in/square/go-jose.v2 v2.2.2
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.22.1
	k8s.io/apimachinery v0.22.1
	k8s.io/apiserver v0.22.1
	k8s.io/client-go v0.22.1
	k8s.io/component-base v0.22.1
	k8s.io/klog/v2 v2.9.0
	k8s.io/kube-aggregator v0.22.1
	k8s.io/utils v0.0.0-20210707171843-4b05e18ac7d9
	sigs.k8s.io/kube-storage-version-migrator v0.0.4
)

replace github.com/openshift/library-go => github.com/slaskawi/library-go v0.0.0-20210913165701-8c0166987561
