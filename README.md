# cluster-authentication-operator
The authentication operator is an 
[OpenShift ClusterOperator](https://github.com/openshift/enhancements/blob/master/enhancements/dev-guide/operators.md#what-is-an-openshift-clusteroperator).    
It installs and maintains the Authentication [Custom Resource](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/) in a cluster and can be viewed with:     
```
oc get clusteroperator authentication -o yaml
```

The [Custom Resource Definition](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/#customresourcedefinitions)
`authentications.operator.openshift.io`    
can be viewed in a cluster with:

```console
$ oc get crd authentications.operator.openshift.io -o yaml
```

Many OpenShift ClusterOperators share common build, test, deployment, and update methods.    
For more information about how to build, deploy, test, update, and develop OpenShift ClusterOperators, see      
[OpenShift ClusterOperator and Operand Developer Document](https://github.com/openshift/enhancements/blob/master/dev-guide/operators.md#how-do-i-buildupdateverifyrun-unit-tests)

This section explains how to deploy OpenShift with your test cluster-authentication-operator image:
[Testing a ClusterOperator/Operand image in a cluster](https://github.com/openshift/enhancements/blob/master/dev-guide/operators.md#how-can-i-test-changes-to-an-openshift-operatoroperandrelease-component)

## Tests

This repository is compatible with the [OpenShift Tests Extension (OTE)](https://github.com/openshift-eng/openshift-tests-extension) framework.

### Building the test binary

```bash
make build
```

### Running test suites and tests

```bash
# Run a specific test suite or test
./cluster-authentication-operator-tests-ext run-suite openshift/authentication-operator/all
./cluster-authentication-operator-tests-ext run-test "test-name"

# Run with JUnit output
./cluster-authentication-operator-tests-ext run-suite openshift/authentication-operator/all --junit-path "${ARTIFACT_DIR}/junit.xml"
```

### Listing available tests and suites

```bash
# List all test suites
./cluster-authentication-operator-tests-ext list suites

# List tests in a suite
./cluster-authentication-operator-tests-ext list tests --suite=openshift/authentication-operator/all
```

For more information about the OTE framework, see the [openshift-tests-extension documentation](https://github.com/openshift-eng/openshift-tests-extension).

## Add a basic IdP to test your stuff
The most common identity provider for demoing and testing is the HTPasswd IdP.

To set it up, take the following steps:

1. Create a new htpasswd file
```
$ htpasswd -bBc /tmp/htpasswd testuser testpasswd
```
2. (optional) Add more users
```
$ htpasswd -bB /tmp/htpasswd testuser2 differentpassword
```
3. Create a secret from that htpasswd in the `openshift-config` namespace
```
oc create secret generic myhtpasswdidp-secret -n openshift-config --from-file=/tmp/htpasswd
```
4. Configure the OAuth server to use the HTPasswd IdP from the secret by editing the spec of the cluster-wide OAuth/cluster object so that it looks like the one in this example:
```
apiVersion: config.openshift.io/v1
kind: OAuth
metadata:
  name: cluster
spec:
  identityProviders:
  - name: htpassidp
    type: HTPasswd
    htpasswd:
      fileData:
        name: myhtpasswdidp-secret
```
5. The operator will now restart the OAuth server deployment and mount the new config
6. When the operator is available again (`oc get clusteroperator authentication`), you should be able to log in:
```
oc login -u testuser -p testpasswd
```
