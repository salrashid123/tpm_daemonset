There's a lot to do with this:


### Support REST

  yeah, not everyone uses gRPC

### Context Volume

Attestation and other TPM-specific context files like the encrypted attestation token or RSA key is saved into an in-memory memory of the daemonset

```yaml
      volumes:
      - name: contexts-volume
        emptyDir: {}
```

which ofcourse means the attestations are lost when the daemonset restarts even if the node doesnt'.


An alternative maybe to write the encrypted contexts to the node's `hostPath` volume

```yaml
      volumes:
      - name: contexts-volume
        hostPath:
          path: /data
```

THis isn't so bad because the context files are wrapped such that it can *only* get decrypted on that TPM.  (i.,e you have to be on that tpm or gain access to the files to use them).

A todo maybe to find someplace else to save these contexts.


### Use kubernetes service account bearer tokens

Maybe use kubernetes service account bearer tokens within each grpc call for authentication of the caller.

see [Using kubernetes TokenReviews go api on pod](https://gist.github.com/salrashid123/75c22afcbdbf1b706ab76d9063122429)


### Use GCE Instance Identity document as confidential VM proxy

If all you want to do is to have a google-signed JWT that asserts "this vm with instanceID=abc in project=efg in zone=us-central1-a is running in confidential VM", then theres a really non-cryptographic solution:

* Just use the gce [instance identity document](https://cloud.google.com/compute/docs/instances/verifying-instance-identity#verify_signature)


```bash
gcloud compute instances create cvm   --machine-type=n2d-standard-2  --zone "us-central1-a"   --confidential-compute --maintenance-policy=TERMINATE --image-family=ubuntu-2204-lts   --image-project=confidential-vm-images

gcloud compute ssh cvm

curl -H "Metadata-Flavor: Google" 'http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience=http://foo.bar&format=full'
```
gives json claims `"instance_confidentiality": 1,` which signals confidential vm is active

```json
{
  "alg": "RS256",
  "kid": "99bcb069340a3f147462794dfefa75e799613634",
  "typ": "JWT"
}.
{
  "aud": "http://foo.bar",
  "azp": "112179062720391305885",
  "email": "1071284184436-compute@developer.gserviceaccount.com",
  "email_verified": true,
  "exp": 1688417242,
  "google": {
    "compute_engine": {
      "instance_confidentiality": 1,
      "instance_creation_timestamp": 1688413580,
      "instance_id": "4080561024171678567",
      "instance_name": "cvm",
      "project_id": "mineral-minutia-820",
      "project_number": 1071284184436,
      "zone": "us-central1-a"
    }
  },
  "iat": 1688413642,
  "iss": "https://accounts.google.com",
  "sub": "112179062720391305885"
}
```

which a verifier can just check separately [Authenticating using Google OpenID Connect Tokens](https://github.com/salrashid123/google_id_token)

### Sign with Atteststation Signing Key

GCE VMs automatically include a the endorsement signing key saved to NV.

This can be used to confirm signatures occured on a TPM without direct attestation.

see [ak_sign_nv](https://github.com/salrashid123/tpm2/tree/master/ak_sign_nv)


### Support `CreateSigningKeyImportBlob`

Which allows the client to encode an RSA key _into_ the tpm [Sealed Asymmetric Key](https://github.com/salrashid123/gcp_tpm_sealed_keys#sealed-asymmetric-key)

the code could be something like this:

- on `grpc_attestor.go`

```golang
var (
	exportedRSACert      = flag.String("rsaCert", "certs/tpm_client.crt", "RSA Public certificate for the key to export")
	exportedRSAKey       = flag.String("rsaKey", "certs/tpm_client.key", "RSA key to export")
)
	glog.V(5).Infof("=============== start ImportSigningKey ===============")

	certPEM, err := ioutil.ReadFile(*exportedRSACert)
	if err != nil {
		glog.Fatalf("Could not find public certificate %v", err)
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		glog.Fatalf("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		glog.Fatalf("failed to parse certificate: " + err.Error())
	}
	glog.V(5).Infof("     Loaded x509 %s", cert.Issuer)

	privateKeyPEM, err := ioutil.ReadFile(*exportedRSAKey)
	if err != nil {
		glog.Fatalf("Could not find private Key %v", err)
	}

	block, _ = pem.Decode(privateKeyPEM)
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		glog.Fatalf("failed to parse private Key: " + err.Error())
	}

	// Generate a test signature using this RSA key.
	glog.V(10).Infof("     Data to sign: %s", *u)
	dataToSign := []byte(*u)
	digest := sha256.Sum256(dataToSign)
	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		glog.Fatalf("Error from signing: %s\n", err)
	}

	glog.V(10).Infof("     Test signature data:  %s", base64.RawStdEncoding.EncodeToString(signature))

	signingImportBlob, err := server.CreateSigningKeyImportBlob(ekPub, priv, vpcrs)
	if err != nil {
		glog.Errorf("Unable to CreateImportBlob : %v", err)
		os.Exit(1)
	}
	sealedOutput, err = proto.Marshal(signingImportBlob)
	if err != nil {
		glog.Errorf("Unable to marshall ImportBlob: ", err)
		os.Exit(1)
	}
	importSignedBlobResponse, err := c.ImportSigningKey(ctx, &verifier.ImportSigningKeyRequest{
		Uid:                 *u,
		Kid:                 kid,
		EncryptedSigningKey: sealedOutput,
	})
	if err != nil {
		glog.Errorf("ImportBlob Failed,  Original Error is: %v", err)
		os.Exit(1)
	}
	glog.V(5).Infof("     importSignedBlobResponse signature %s", base64.RawStdEncoding.EncodeToString(importSignedBlobResponse.Confirmation))
	glog.V(5).Infof("=============== end ImportSigningKey ===============")
```

on `grpc_verifier.go`

```golang
func (s *server) ImportSigningKey(ctx context.Context, in *verifier.ImportSigningKeyRequest) (*verifier.ImportSigningKeyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= ImportSigningKey ========")

	blob := &pb.ImportBlob{}

	err := proto.Unmarshal(in.EncryptedSigningKey, blob)
	if err != nil {
		glog.Errorf("ERROR:  unmarshalling encryptedBLob proto %v", err)
		return &verifier.ImportSigningKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  could not unmarshal encryptedBLob proto"))
	}

	rwc, err := tpm2.OpenTPM(*tpmDevice)
	if err != nil {
		glog.Errorf("ERROR:  error opening TPM %v", err)
		return &verifier.ImportSigningKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error opening TPM"))
	}
	defer rwc.Close()

	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		glog.Errorf("ERROR:  loading EndorsementKeyRSA %v", err)
		return &verifier.ImportSigningKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  loading EndorsementKeyRSA"))
	}
	defer ek.Close()

	key, err := ek.ImportSigningKey(blob)
	if err != nil {
		glog.Errorf("ERROR:  error importing secret %v", err)
		return &verifier.ImportSigningKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error importing secret"))
	}

	importedKeyFile := fmt.Sprintf("%s/%s.%s", *contextsPath, in.Uid, in.Kid)
	glog.V(10).Infof("     Saving Key Handle as %s", importedKeyFile)
	keyHandle := key.Handle()
	defer key.Close()
	keyBytes, err := tpm2.ContextSave(rwc, keyHandle)
	if err != nil {
		glog.Errorf("ERROR:  ContextSave failed for keyHandle:: %v", err)
		return &verifier.ImportSigningKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ContextSave failed for keyHandle: %v", err))
	}
	err = ioutil.WriteFile(importedKeyFile, keyBytes, 0644)
	if err != nil {
		glog.Errorf("ERROR:  FileSave ContextSave failed for keyBytes %v", err)
		return &verifier.ImportSigningKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("FileSave ContextSave failed for keyBytes: %v", err))
	}
	defer tpm2.FlushContext(rwc, keyHandle)

	ss, err := key.SignData([]byte(in.Uid))
	if err != nil {
		glog.Errorf("ERROR:  signing data %v", err)
		return &verifier.ImportSigningKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ERROR:  signing data: %v", err))
	}
	return &verifier.ImportSigningKeyResponse{
		Confirmation: ss,
	}, nil
}
```
