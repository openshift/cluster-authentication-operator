#
# The standard name for this image is openshift/origin-cluster-osin-operator
#
FROM openshift/origin-release:golang-1.10
COPY . /go/src/github.com/openshift/cluster-osin-operator
RUN cd /go/src/github.com/openshift/cluster-osin-operator && go build ./cmd/osin-operator

FROM centos:7
COPY --from=0 /go/src/github.com/openshift/cluster-osin-operator/osin /usr/bin/osin-operator

COPY manifests /manifests
LABEL io.openshift.release.operator=true
