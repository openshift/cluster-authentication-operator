# cluster-authentication-operator

This is where the amazing cluster-authentication-operator lives.

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
## License 
Apache License Version 2.0
