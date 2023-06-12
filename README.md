
## Kubernetes Trusted Platform Module (TPM) DaemonSet 

Simple kubernetes [DaemonSet](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/) which surfaces node-specific TPM operations.

Specifically, this daemonset allows the containers the ability to interact with the node's TPM though gRPC APIs:

Normally, an application accesses the TPM by directly interacting with the `/dev/tpm0` device.  In the case of GKE, that device is not readily visible to the container without setting the [privileged: true](https://gist.github.com/salrashid123/e2c336e26fc7fc06312e9f2c07857e5a) security context to the pod (which is risky).

The sample here runs a daemonset which does have access to the host's TPM via volume mounts and surfaces several common TPM operations as a gRPC service.

The specific operations contained here are

* TPM [Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html)

  Allows remote parties to confirm signing and encryption keys are associated with a specific TPM

* TPM [Quote-Verify](https://github.com/salrashid123/tpm2/tree/master/quote_verify)

  Allows for verification of PCRs and Evenlogs on the TPM

* PCR bound Transfer of sensitive data (encryption keys)

  This allows decryption of arbitrary data in a way that it can *only* be done on that TPM

* on-TPM RSA Key generation and signature

  Allows the TPM to generate a remote provable/attested RSA key that will exist *only* on that TPM.  
  The key can be used to sign data ensuring an operation happened on a given TPM

![images/gke_tpm.png](images/gke_tpm.png)

The specific gRPC interfaces for the above are:

```proto
option go_package = "github.com/salrashid123/tpm_daemonset/verifier";

service Verifier {
  // get endorsement certificate
  rpc GetEKCert (GetEKCertRequest) returns (GetEKCertResponse) { }

  // get an attestation key
  rpc GetAK (GetAKRequest) returns (GetAKResponse) { }

  // remote attestation
  rpc Attest (AttestRequest) returns (AttestResponse) { }

  // quote/verify
  rpc Quote (QuoteRequest) returns (QuoteResponse) { }

  // decrypt an external encrypted secret on the TPM
  //  the secret is encrypted using that tpm's EK
  rpc ImportBlob (ImportBlobRequest) returns (ImportBlobResponse) { }

  // (unimplemented) load an encrypted external RSA key into TPM
  //   RSA key is encrypted using that tpm's EK
  rpc ImportSigningKey (ImportSigningKeyRequest) returns (ImportSigningKeyResponse) { }

  //  generate a new RSA key embedded on the TPM
  rpc NewKey (NewKeyRequest) returns (NewKeyResponse) { }

  // use embedded TPM rsa key to sign data
  rpc Sign (SignRequest) returns (SignResponse) { }
}
```

The daemonset's API access is visible to the pods in that same node enforced though the `internalTrafficPolicy: Local` directive

```yaml
apiVersion: v1
kind: Service
metadata:
  name: app-service
spec:
  internalTrafficPolicy: Local
  selector:
    name: tpm-ds
  ports:
  - name: http-port
    protocol: TCP
    port: 50051
```

>> note: this repo and code is **not** supported by Google

---

#### References

* [go-attestation](https://github.com/google/go-attestation)
* [go-tpm-tools](https://github.com/google/go-tpm-tools)
* [TPM Remote Attestation protocol using go-tpm and gRPC](https://github.com/salrashid123/go_tpm_remote_attestation)
* [Sealing RSA and Symmetric keys with GCP vTPMs](https://github.com/salrashid123/gcp_tpm_sealed_keys#sealed-asymmetric-key)
* [Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm](https://github.com/salrashid123/tpm2)


---

### Build

You can either use the built image:
`index.docker.io/salrashid123/tpmds@sha256:9c27d15aa7b29f4bce3f06fbfe088d40f0d04ed610449e1de7afa38cadde8e55`

or the daemonset was built using Kaniko:

```bash
 docker run   \
  -v `pwd`:/workspace -v $HOME/.docker/config_docker.json:/kaniko/.docker/config.json:ro \
   -v /var/run/docker.sock:/var/run/docker.sock \
     gcr.io/kaniko-project/executor@sha256:034f15e6fe235490e64a4173d02d0a41f61382450c314fffed9b8ca96dff66b2    \
	 --dockerfile=Dockerfile \
	 --reproducible   \
	     --destination "docker.io/salrashid123/tpmds:server"       --context dir:///workspace/
```

### Run

To use, simply create a GKE cluster, deploy 

```bash
gcloud container clusters create cluster-1  \
   --region=us-central1 --machine-type=n2d-standard-2 --enable-confidential-nodes \
   --enable-shielded-nodes --shielded-secure-boot --shielded-integrity-monitoring --num-nodes=1

$ cd example/
$ kubectl apply -f .
$ kubectl get po,svc,no -o wide
NAME                       READY   STATUS    RESTARTS   AGE   IP           NODE                                       NOMINATED NODE   READINESS GATES
pod/app-5565d6b794-nfb66   1/1     Running   0          28s   10.60.2.47   gke-cluster-1-default-pool-7c317a84-nfc1   <none>           <none>
pod/tpm-ds-747vz           1/1     Running   0          6s    10.60.2.48   gke-cluster-1-default-pool-7c317a84-nfc1   <none>           <none>
pod/tpm-ds-pkvhs           1/1     Running   0          6s    10.60.1.32   gke-cluster-1-default-pool-8dcbbab8-1kck   <none>           <none>
pod/tpm-ds-w5fvd           1/1     Running   0          6s    10.60.0.32   gke-cluster-1-default-pool-380e9ee7-fbk3   <none>           <none>

NAME                  TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)     AGE   SELECTOR
service/app-service   ClusterIP   10.64.11.144   <none>        50051/TCP   6s    name=tpm-ds
service/kubernetes    ClusterIP   10.64.0.1      <none>        443/TCP     22h   <none>

NAME                                            STATUS   ROLES    AGE   VERSION           INTERNAL-IP   EXTERNAL-IP      OS-IMAGE                             KERNEL-VERSION   CONTAINER-RUNTIME
node/gke-cluster-1-default-pool-380e9ee7-fbk3   Ready    <none>   22h   v1.25.8-gke.500   10.128.0.46   34.67.149.29     Container-Optimized OS from Google   5.15.89+         containerd://1.6.18
node/gke-cluster-1-default-pool-7c317a84-nfc1   Ready    <none>   22h   v1.25.8-gke.500   10.128.0.84   34.29.212.72     Container-Optimized OS from Google   5.15.89+         containerd://1.6.18
node/gke-cluster-1-default-pool-8dcbbab8-1kck   Ready    <none>   22h   v1.25.8-gke.500   10.128.0.64   35.232.227.155   Container-Optimized OS from Google   5.15.89+         containerd://1.6.18


$ kubectl exec --stdin --tty pod/app-5565d6b794-nfb66 -- /bin/bash

$ cd /app
$ go run grpc_verifier.go -host app-service:50051 \
   -uid 121123 -kid 213412331 \
   -caCertTLS /certs/root.pem \
   -ekRootCA=/certs/tpm_ek_root_1.pem \
   --ekIntermediate=/certs/tpm_ek_intermediate_3.pem --v=10 -alsologtostderr

```

The output on the verifier will show the outputs of the end-to-end tests:

Note that each invocation returns the EKCert issued to the same NodeVM (in our ase, its `gke-cluster-1-default-pool-7c317a84-nfc1`)...and thats just where the app pod was deployed.  

The EKCert shown in this repo uses the specific certificates signed by google and is verified by the client itself.

```log
root@app-5565d6b794-nfb66:/# /grpc_verifier -host app-service:50051  -uid 121123 -kid 213412331 --v=10 -alsologtostderr
I0612 12:44:36.857804      13 grpc_verifier.go:119] RPC HealthChekStatus:SERVING
I0612 12:44:36.858286      13 grpc_verifier.go:121] =============== start GetEKCert ===============
I0612 12:44:36.859248      13 grpc_verifier.go:151]      EKCert  Issuer CN=tpm_ek_v1_cloud_host-signer-0-2021-10-12T04:22:11-07:00 K:1\, 3:nbvaGZFLcuc:0:18,OU=Cloud,O=Google LLC,L=Mountain View,ST=California,C=US
I0612 12:44:36.859341      13 grpc_verifier.go:152]      EKCert  IssuingCertificateURL [https://pki.goog/cloud_integrity/tpm_ek_intermediate_3.crt]
I0612 12:44:36.859398      13 grpc_verifier.go:156]      EKCert  GCE InstanceID 4570452845155348778
I0612 12:44:36.859420      13 grpc_verifier.go:157]      EKCert  GCE InstanceName gke-cluster-1-default-pool-7c317a84-nfc1
I0612 12:44:36.859465      13 grpc_verifier.go:158]      EKCert  GCE ProjectId mineral-minutia-820
I0612 12:44:36.859486      13 grpc_verifier.go:161]     EkCert Public Key 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxG8/IiqhspLU82beKYU6
nVl0lceMBMmqHq2TTqiVOQwZdOv375TnjOOaw891YmURAWyFK7kKJiDOTv4wQabx
yYk9tTFVhwYOxsaKe+8UOxOCYEIlA4I1SmEmaxli1inVI3JcIbSwk99ip0InfeJh
KzRWAun1BtZZcsZiwFX2isleY1guL+N8BYG2hlmT5u9Q/0ih5NmImGml0Vtb+MlB
HutD34OUEpWonoZGazhIxoiOXjdz0vGZQdcwYa4MsxSyna2xHh/H1p6OeetswedA
8kZVFCsOHXMrrZ9lb9ypoQhOUXYFjzGxCEZTGSjKA2uAy25qK5GZPH2Z5/LLeF+c
UwIDAQAB
-----END PUBLIC KEY-----

I0612 12:44:36.859518      13 grpc_verifier.go:163]     Verifying EKCert
I0612 12:44:36.860280      13 grpc_verifier.go:201]     EKCert Verified
I0612 12:44:36.860309      13 grpc_verifier.go:203] =============== end GetEKCert ===============
I0612 12:44:36.860334      13 grpc_verifier.go:205] =============== start GetAK ===============
I0612 12:44:36.998759      13 grpc_verifier.go:245]       ak public 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5mspgshj9iSyvIL2e0om
JGP29b5NOwGjJm3JmKEPWfVwi4IPEbjHgCGLCXjElijnRfJWUovsT+dLNYSmBABm
3xmIFxhkJY5MtoxIOVXjjZQrGUii2Sq4t154epr7+655jE4Dp9DmpKJYAb2cEYdh
8QMgf4FV2e0ZD93wAMj7a5zfolHIkQoH6E/L8ndkXZhHqEfqX+3PAcX5S5QCqvoz
L+10arCQDmuUqCgBwirP7fpPV6yl8B1NTzggyzgW2wZ+OfSgjQPoJXYBrmBgHR4U
fb6vk73PZgQv4tsxppCDdzgBuZi8DXWH6+HCSKpCnE7IB++wZM+EkcLNb63lug3g
JQIDAQAB
-----END PUBLIC KEY-----

I0612 12:44:36.998820      13 grpc_verifier.go:246] =============== end GetAK ===============
I0612 12:44:36.998847      13 grpc_verifier.go:248] =============== start Attest ===============
I0612 12:44:36.999155      13 grpc_verifier.go:254]       Outbound Secret: 3LZ1GKAZfeU1tLmosHTAXiGRex9PPW5BQAsutQG81/I=
I0612 12:44:37.130164      13 grpc_verifier.go:271]       Inbound Secret: 3LZ1GKAZfeU1tLmosHTAXiGRex9PPW5BQAsutQG81/I=
I0612 12:44:37.130243      13 grpc_verifier.go:273] =============== end Attest ===============
I0612 12:44:37.130301      13 grpc_verifier.go:276]       inbound/outbound Secrets Match; accepting AK
I0612 12:44:37.130333      13 grpc_verifier.go:281] =============== start Quote/Verify ===============
I0612 12:44:37.310285      13 grpc_verifier.go:334]      quotes verified
I0612 12:44:37.311204      13 grpc_verifier.go:347]      secureBoot State enabled true
I0612 12:44:37.311564      13 grpc_verifier.go:353] =============== end Quote/Verify ===============
I0612 12:44:37.311610      13 grpc_verifier.go:355] =============== start ImportBlob ===============
I0612 12:44:37.311715      13 grpc_verifier.go:357]      importSecret G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThW
I0612 12:44:37.350277      13 grpc_verifier.go:378]      Decrypted key G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThW
I0612 12:44:37.350339      13 grpc_verifier.go:379] =============== end ImportBlob ===============
I0612 12:44:37.350480      13 grpc_verifier.go:381] =============== start NewKey ===============
I0612 12:44:37.626104      13 grpc_verifier.go:392]      newkey Public 
-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5ph3SnrcxuhNVfV2fJcN
H/8lDfSbE0hmI2asBSSpe2auUrmNeRac3WNGVxo1wB4wByV2kyWwuJLJ1wuufFJ/
ZAPDOcBjLzKe6oYT8mlfSQ2JA5kjersW3TUBmNStahj3FAeosPdk0BNWepPJzZPZ
oPtA6SiBd1inH1TWtfnUK85DzbP50lTLdnEjPDQtqyUkcRwkq43LcrAjC06CYXsx
y+0yXg9fwXBHA4Eolb4N/AL68iOe8DKmMqsaJN2+/RyskUQatlLHuI0iEICbPxuE
Wej6o1FRpwf0dLJ0UUflK6FqTGR71rt4wg20/cNS6soPmiF/rSyz7AuS99zjsehY
1QIDAQAB
-----END RSA PUBLIC KEY-----
I0612 12:44:37.626497      13 grpc_verifier.go:409]      new key verified
I0612 12:44:37.626561      13 grpc_verifier.go:410] =============== end NewKey ===============
I0612 12:44:37.626618      13 grpc_verifier.go:412] =============== start Sign ===============
I0612 12:44:37.673257      13 grpc_verifier.go:425]      signature: uYzH2dj7RBT6rHh+2j4iTqRYQOs3wwLXlzRI/g306PmD9n8XP0Km/dfNRrh5IQaAskByNmE0qAyxOwYhVBqN+0NGBnPab5Da8YnK1IcSwNyMUBdTbbQPbUkA+CW/U/cdFc7pSsNqB/meque/C6FQJ9KhvosYgojoO1JWLnSHBMdWDxsht7xrO67xB6did5PW79yNFgMkAqDPO3s6uoEjSVEGmKDIjb+KhFOjTmN6qiqOo+LaPQYkYih0JOwZgarMw9iKfClx98+OB+v1+dKl+sheViHffrnu0uEzAVipxTNRAoMWE2Mc4qQ8EFBTKSZj+4fAsll2L+vwdhIhk4sIVw==
I0612 12:44:37.673606      13 grpc_verifier.go:448]      signature verified
I0612 12:44:37.673666      13 grpc_verifier.go:449] =============== end Sign ===============
```

Which corresponds to basic server output (you can increase the verbosity logging flag on boot)

```log
$ kubectl logs pod/tpm-ds-747vz 
I0612 12:44:04.121319       1 grpc_attestor.go:520] Getting EKCert reset
I0612 12:44:04.133801       1 grpc_attestor.go:536] ECCert Issuer: CN=tpm_ek_v1_cloud_host-signer-0-2021-10-12T04:22:11-07:00 K:1\, 3:nbvaGZFLcuc:0:18,OU=Cloud,O=Google LLC,L=Mountain View,ST=California,C=US
I0612 12:44:04.134042       1 grpc_attestor.go:541] Parsing PCRs EKCert 
I0612 12:44:04.134589       1 grpc_attestor.go:585] Starting gRPC server on port :50051
I0612 12:44:36.857103       1 grpc_attestor.go:94] HealthCheck called for Service [attest.Attestor]
I0612 12:44:36.858956       1 grpc_attestor.go:108] ======= GetEKCert ========
I0612 12:44:36.860625       1 grpc_attestor.go:122] ======= GetAK ========
I0612 12:44:36.999592       1 grpc_attestor.go:181] ======= Attest ========
I0612 12:44:37.130705       1 grpc_attestor.go:231] ======= Quote ========
I0612 12:44:37.312895       1 grpc_attestor.go:289] ======= ImportBlob ========
I0612 12:44:37.351034       1 grpc_attestor.go:336] ======= NewKey ========
I0612 12:44:37.627104       1 grpc_attestor.go:420] ======= Sign ========
```

---

#### GCP EK and instance identity specifications

##### EKCert for node

```bash
gcloud compute instances get-shielded-identity gke-cluster-1-default-pool-7c317a84-nfc1 \
 --zone=us-central1-c \
  --format="value(encryptionKey.ekCert)" | awk '/^$/{n=n RS}; /./{printf "%s",n; n=""; print}' -  > /tmp/ekcert.pem

openssl x509 -in /tmp/ekcert.pem -text -noout
```

yields specifications of the node.  Note the value of 

```
            1.3.6.1.4.1.11129.2.1.21: 
us-central1-c....m.et..mineral-minutia-820..?m...(q*.(gke-cluster-1-default-pool-7c317a84-nfc1. 0...............................
```

Thats actually a custom OID you can parse using [server.GetGCEInstanceInfo](https://pkg.go.dev/github.com/google/go-tpm-tools/server#GetGCEInstanceInfo)

In our case, it yields the name of the VM and its instanceID

```log
I0612 12:44:36.859398      13 grpc_verifier.go:156]      EKCert  GCE InstanceID 4570452845155348778
I0612 12:44:36.859420      13 grpc_verifier.go:157]      EKCert  GCE InstanceName gke-cluster-1-default-pool-7c317a84-nfc1
I0612 12:44:36.859465      13 grpc_verifier.go:158]      EKCert  GCE ProjectId mineral-minutia-820
```

To parse the cert:
```
$ openssl x509 -in /tmp/ekcert.pem -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            01:ca:21:a6:a1:fa:1f:55:4f:de:c6:f4:39:74:07:82:fd:c7:1a
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, ST = California, L = Mountain View, O = Google LLC, OU = Cloud, CN = "tpm_ek_v1_cloud_host-signer-0-2021-10-12T04:22:11-07:00 K:1, 3:nbvaGZFLcuc:0:18"
        Validity
            Not Before: Jun 11 13:39:47 2023 GMT
            Not After : Jun  3 13:44:47 2053 GMT
        Subject: 
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:c4:6f:3f:22:2a:a1:b2:92:d4:f3:66:de:29:85:
                    3a:9d:59:74:95:c7:8c:04:c9:aa:1e:ad:93:4e:a8:
                    95:39:0c:19:74:eb:f7:ef:94:e7:8c:e3:9a:c3:cf:
                    75:62:65:11:01:6c:85:2b:b9:0a:26:20:ce:4e:fe:
                    30:41:a6:f1:c9:89:3d:b5:31:55:87:06:0e:c6:c6:
                    8a:7b:ef:14:3b:13:82:60:42:25:03:82:35:4a:61:
                    26:6b:19:62:d6:29:d5:23:72:5c:21:b4:b0:93:df:
                    62:a7:42:27:7d:e2:61:2b:34:56:02:e9:f5:06:d6:
                    59:72:c6:62:c0:55:f6:8a:c9:5e:63:58:2e:2f:e3:
                    7c:05:81:b6:86:59:93:e6:ef:50:ff:48:a1:e4:d9:
                    88:98:69:a5:d1:5b:5b:f8:c9:41:1e:eb:43:df:83:
                    94:12:95:a8:9e:86:46:6b:38:48:c6:88:8e:5e:37:
                    73:d2:f1:99:41:d7:30:61:ae:0c:b3:14:b2:9d:ad:
                    b1:1e:1f:c7:d6:9e:8e:79:eb:6c:c1:e7:40:f2:46:
                    55:14:2b:0e:1d:73:2b:ad:9f:65:6f:dc:a9:a1:08:
                    4e:51:76:05:8f:31:b1:08:46:53:19:28:ca:03:6b:
                    80:cb:6e:6a:2b:91:99:3c:7d:99:e7:f2:cb:78:5f:
                    9c:53
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Authority Key Identifier: 
                67:08:C4:77:11:FD:D5:87:84:D3:2C:1D:6B:4D:97:83:60:84:25:80
            Authority Information Access: 
                CA Issuers - URI:https://pki.goog/cloud_integrity/tpm_ek_intermediate_3.crt
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:https://pki.goog/cloud_integrity/tpm_ek_intermediate_3.crl
            X509v3 Key Usage: critical
                Key Encipherment
            X509v3 Extended Key Usage: 
                2.23.133.8.1
            X509v3 Subject Directory Attributes: 
                0.0...g....1.0...2.0.......
            X509v3 Subject Alternative Name: critical
                DirName:/2.23.133.2.1=id:474F4F47/2.23.133.2.2=vTPM/2.23.133.2.3=id:20160511
            1.3.6.1.4.1.11129.2.1.21: 
us-central1-c....m.et..mineral-minutia-820..?m...(q*.(gke-cluster-1-default-pool-7c317a84-nfc1. 0...............................
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        28:d3:46:0d:bd:72:83:4a:a7:83:e5:fd:1f:0e:67:0b:00:3d:
        04:76:01:2d:13:3c:04:30:c3:47:45:f9:43:ed:a5:8b:87:26:
        1f:10:28:38:68:0e:19:b1:75:92:df:72:a1:b3:0c:66:ad:ee:
        84:45:c9:9b:c1:8f:6e:ff:e1:6b:57:35:0b:67:67:e3:12:b6:
        15:9e:8e:18:40:f2:d3:47:6d:32:19:f7:39:8a:3d:f4:3a:1f:
        32:1f:dc:40:ac:8f:f4:52:cf:7f:2a:9f:3e:73:4b:28:33:f9:
        f6:c3:ac:39:77:76:21:a5:b4:5b:31:4d:bc:d0:ff:f6:8f:ec:
        f2:ce:32:ab:44:a3:89:12:1c:d8:ef:40:8a:2d:48:dd:30:43:
        12:1f:de:04:c3:de:2e:11:63:97:78:a0:5c:e1:93:d3:08:25:
        d1:92:9f:3f:54:91:08:ca:17:e3:d7:2e:cd:3b:64:f4:e2:cc:
        ba:6a:f8:31:80:f5:bd:b3:40:99:c2:f9:6d:15:67:e8:75:fa:
        23:37:9b:53:9d:df:12:83:b2:2c:02:76:d7:e3:ca:fa:4b:43:
        c2:69:47:83:02:90:da:09:64:fd:e8:3e:a9:eb:6e:ef:5b:1e:
        b7:ae:2d:3e:34:ea:88:45:3c:26:b8:c1:35:9e:8a:5a:b0:e7:
        99:66:9b:30

```

##### Instance identity claim for instance_confidentiality

If the daemonset or application pod can access the instances's [indentity_document](https://cloud.google.com/compute/docs/instances/verifying-instance-identity#payload), the applcation will immediately have
a [google-signed OIDC token](https://github.com/salrashid123/google_id_token) that will carry claims denoting the node and vm instance id and even if the vm itself is running in confidential mode (`instance_confidentiality`).

This oidc token can act as a bearer token in conjunction with the TPM's EKCert and can be "joined" using the `instance_id` value present in both 


```
root@app-57db75578b-jr4xs:/app# curl -H "Metadata-Flavor: Google" 'http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://foo.bar&format=full'

{
  "aud": "https://foo.bar",
  "azp": "112179062720391305885",
  "email": "1071284184436-compute@developer.gserviceaccount.com",
  "email_verified": true,
  "exp": 1686583887,
  "google": {
    "compute_engine": {
      "instance_confidentiality": 1,
      "instance_creation_timestamp": 1686491081,
      "instance_id": "4570452845155348778",
      "instance_name": "gke-cluster-1-default-pool-7c317a84-nfc1",
      "project_id": "mineral-minutia-820",
      "project_number": 1071284184436,
      "zone": "us-central1-c"
    }
  },
  "iat": 1686580287,
  "iss": "https://accounts.google.com",
  "sub": "112179062720391305885"
}
```
