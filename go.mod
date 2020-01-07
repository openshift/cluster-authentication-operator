module github.com/openshift/cluster-authentication-operator

go 1.13

require (
	github.com/getsentry/raven-go v0.2.1-0.20190513200303-c977f96e1095 // indirect
	github.com/jteeuwen/go-bindata v3.0.8-0.20151023091102-a0ff2567cfb7+incompatible
	github.com/openshift/api v0.0.0-20191219160953-2f4dddbbf3e6
	github.com/openshift/client-go v0.0.0-20191216194936-57f413491e9e
	github.com/openshift/library-go v0.0.0-20200106191802-9821002633e8
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.4.0
	go.uber.org/atomic v1.3.3-0.20181018215023-8dc6146f7569 // indirect
	go.uber.org/multierr v1.1.1-0.20180122172545-ddea229ff1df // indirect
	gopkg.in/yaml.v2 v2.2.4
	k8s.io/api v0.17.0
	k8s.io/apimachinery v0.17.0
	k8s.io/client-go v0.17.0
	k8s.io/component-base v0.17.0
	k8s.io/klog v1.0.0
	monis.app/go v0.0.0-20190702030534-c65526068664
)

replace github.com/prometheus/client_golang => github.com/prometheus/client_golang v0.9.2
