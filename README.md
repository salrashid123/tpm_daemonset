
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
  rpc GetEKCert (GetEKCertRequest) returns (GetEKCertResponse) { }
  rpc GetAK (GetAKRequest) returns (GetAKResponse) { }
  rpc Attest (AttestRequest) returns (AttestResponse) { }
  rpc Quote (QuoteRequest) returns (QuoteResponse) { }
  rpc ImportBlob (ImportBlobRequest) returns (ImportBlobResponse) { }
  rpc ImportSigningKey (ImportSigningKeyRequest) returns (ImportSigningKeyResponse) { }
  rpc NewKey (NewKeyRequest) returns (NewKeyResponse) { }
  rpc Sign (SignRequest) returns (SignResponse) { }
}
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
