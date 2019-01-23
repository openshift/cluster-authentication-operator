package operator

import "github.com/openshift/cluster-authentication-operator/pkg/boilerplate/controller"

func FilterByNames(names ...string) controller.Filter {
	return controller.FilterByNames(nil, names...)
}
