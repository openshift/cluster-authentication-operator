package libraryapplyconfiguration

import "k8s.io/apimachinery/pkg/runtime/schema"

var (
	coreEventGR = schema.GroupResource{Group: "", Resource: "events"}
	eventGR     = schema.GroupResource{Group: "events.k8s.io", Resource: "events"}
	csrGR       = schema.GroupResource{Group: "certificates.k8s.io", Resource: "certificatesigningrequests"}
)
