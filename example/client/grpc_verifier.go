package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"hash"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	mrnd "math/rand"
	"time"

	"github.com/golang/glog"
	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/uuid"

	"github.com/google/go-tpm-tools/proto/tpm"
	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm-tools/server"

	"github.com/salrashid123/tpm_daemonset/verifier"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	//"github.com/google/go-attestation/attest"

	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

const ()

var (
	ekRootCA       = flag.String("ekRootCA", "certs/tpm_ek_root_1.pem", "CA for the EKRootSigner")
	ekIntermediate = flag.String("ekIntermediate", "certs/tpm_ek_intermediate_3.pem", "Intermediate for EKCert")

	importBlobSecret     = flag.String("importBlobSecret", "G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThW", "secret")
	expectedPCRMapSHA256 = flag.String("expectedPCRMapSHA256", "0:a0b5ff3383a1116bd7dc6df177c0c2d433b9ee1813ea958fa5d166a202cb2a85", "Sealing and Quote PCRMap (as comma separated key:value).  pcr#:sha256,pcr#sha256.  Default value uses pcr0:sha256")

	u = flag.String("uid", uuid.New().String(), "uid of client")

	kid = flag.String("kid", uuid.New().String(), "keyid to save")

	caCertTLS = flag.String("caCertTLS", "certs/root.pem", "CA Certificate to Trust for TLS")

	letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	address     = flag.String("host", "localhost:50051", "host:port of Attestor")
	serverName  = flag.String("serverName", "attestor.esodemoapp2.com", "SNI")
	handleNames = map[string][]tpm2.HandleType{
		"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    {tpm2.HandleTypeLoadedSession},
		"saved":     {tpm2.HandleTypeSavedSession},
		"transient": {tpm2.HandleTypeTransient},
	}
)

func main() {

	flag.Parse()
	var err error

	var tlsCfg tls.Config
	rootCAs := x509.NewCertPool()
	ca_pem, err := ioutil.ReadFile(*caCertTLS)
	if err != nil {
		glog.Errorf("failed to load root CA certificates  error=%v", err)
		os.Exit(1)
	}
	if !rootCAs.AppendCertsFromPEM(ca_pem) {
		glog.Errorf("no root CA certs parsed from file ")
		os.Exit(1)
	}
	tlsCfg.RootCAs = rootCAs
	tlsCfg.ServerName = *serverName

	mrnd.Seed(time.Now().UTC().UnixNano())

	ce := credentials.NewTLS(&tlsCfg)
	ctx := context.Background()

	conn, err := grpc.Dial(*address, grpc.WithTransportCredentials(ce))
	if err != nil {
		glog.Errorf("did not connect: %v", err)
		os.Exit(1)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{Service: "attest.Attestor"})
	if err != nil {
		glog.Errorf("HealthCheck failed %+v", err)
		os.Exit(1)
	}

	if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		glog.Errorf("service not in serving state: %s", resp.GetStatus().String())
		os.Exit(1)
	}
	glog.V(2).Infof("RPC HealthChekStatus:%v", resp.GetStatus())

	glog.V(5).Infof("=============== start GetEKCert ===============")

	ekReq := &verifier.GetEKCertRequest{}

	c := verifier.NewVerifierClient(conn)
	ekCertResponse, err := c.GetEKCert(ctx, ekReq)
	if err != nil {
		glog.Errorf("GetEKCert Failed,   Original Error is: %v", err)
		os.Exit(1)
	}

	ekcert, err := x509.ParseCertificate(ekCertResponse.EkCert)
	if err != nil {
		glog.Errorf("ERROR:   ParseCertificate: %v", err)
		os.Exit(1)
	}
	spubKey := ekcert.PublicKey.(*rsa.PublicKey)

	skBytes, err := x509.MarshalPKIXPublicKey(spubKey)
	if err != nil {
		glog.Errorf("ERROR:  could  MarshalPKIXPublicKey: %v", err)
		os.Exit(1)
	}
	ekPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: skBytes,
		},
	)

	glog.V(10).Infof("     EKCert  Issuer %v", ekcert.Issuer)
	glog.V(10).Infof("     EKCert  IssuingCertificateURL %v", fmt.Sprint(ekcert.IssuingCertificateURL))

	gceInfo, err := server.GetGCEInstanceInfo(ekcert)
	if err == nil {
		glog.V(10).Infof("     EKCert  GCE InstanceID %d", gceInfo.InstanceId)
		glog.V(10).Infof("     EKCert  GCE InstanceName %s", gceInfo.InstanceName)
		glog.V(10).Infof("     EKCert  GCE ProjectId %s", gceInfo.ProjectId)
	}

	glog.V(10).Infof("    EkCert Public Key \n%s\n", ekPubPEM)

	glog.V(10).Info("    Verifying EKCert")

	rootPEM, err := ioutil.ReadFile(*ekRootCA)
	if err != nil {
		glog.Errorf("Error Reading root %v", err)
		os.Exit(1)
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		glog.Errorf("failed to parse root certificate")
		os.Exit(1)
	}

	interPEM, err := ioutil.ReadFile(*ekIntermediate)
	if err != nil {
		glog.Errorf("Error Reading intermediate %v", err)
		os.Exit(1)
	}

	inters := x509.NewCertPool()
	ok = inters.AppendCertsFromPEM(interPEM)
	if !ok {
		glog.Errorf("failed to parse intermediate certificate")
		os.Exit(1)
	}

	ekcert.UnhandledCriticalExtensions = []asn1.ObjectIdentifier{}
	_, err = ekcert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		glog.Errorf("Error Reading intermediate %v", err)
		os.Exit(1)
	}
	glog.V(10).Info("    EKCert Verified")

	glog.V(5).Infof("=============== end GetEKCert ===============")

	glog.V(5).Infof("=============== start GetAK ===============")
	akResponse, err := c.GetAK(ctx, &verifier.GetAKRequest{
		Uid: *u,
	})
	if err != nil {
		glog.Errorf("GetAK Failed,  Original Error is: %v", err)
		os.Exit(1)
	}

	serverAttestationParameter := &attest.AttestationParameters{}
	reader := bytes.NewReader(akResponse.Ak)
	err = json.NewDecoder(reader).Decode(serverAttestationParameter)
	if err != nil {
		glog.Errorf("Error encoding serverAttestationParamer %v", err)
		os.Exit(1)
	}

	params := attest.ActivationParameters{
		TPMVersion: attest.TPMVersion20,
		EK:         ekcert.PublicKey,
		AK:         *serverAttestationParameter,
	}
	akp, err := attest.ParseAKPublic(attest.TPMVersion20, serverAttestationParameter.Public)
	if err != nil {
		glog.Errorf("Error Parsing AK %v", err)
		os.Exit(1)
	}

	akpPub, err := x509.MarshalPKIXPublicKey(akp.Public)
	if err != nil {
		glog.Errorf("Error MarshalPKIXPublicKey ak %v", err)
		os.Exit(1)
	}
	akPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akpPub,
		},
	)

	glog.V(5).Infof("      ak public \n%s\n", akPubPEM)
	glog.V(5).Infof("=============== end GetAK ===============")

	glog.V(5).Infof("=============== start Attest ===============")
	secret, encryptedCredentials, err := params.Generate()
	if err != nil {
		glog.Errorf("Error generating make credential parameters %v", err)
		os.Exit(1)
	}
	glog.Infof("      Outbound Secret: %s\n", base64.StdEncoding.EncodeToString(secret))

	encryptedCredentialsBytes := new(bytes.Buffer)
	err = json.NewEncoder(encryptedCredentialsBytes).Encode(encryptedCredentials)
	if err != nil {
		glog.Errorf("Error encoding encryptedCredentials %v", err)
		os.Exit(1)
	}

	mcResponse, err := c.Attest(ctx, &verifier.AttestRequest{
		Uid:                  *u,
		EncryptedCredentials: encryptedCredentialsBytes.Bytes(),
	})
	if err != nil {
		glog.Errorf("GetAK Failed,  Original Error is: %v", err)
		os.Exit(1)
	}
	glog.V(5).Infof("      Inbound Secret: %s\n", base64.StdEncoding.EncodeToString(mcResponse.Secret))

	glog.V(5).Infof("=============== end Attest ===============")

	if base64.StdEncoding.EncodeToString(mcResponse.Secret) == base64.StdEncoding.EncodeToString(secret) {
		glog.V(5).Infof("      inbound/outbound Secrets Match; accepting AK")
	} else {
		glog.Error("attestation secrets do not match; exiting")
		os.Exit(1)
	}
	glog.V(5).Infof("=============== start Quote/Verify ===============")

	nonce := []byte("foo")
	quoteResponse, err := c.Quote(ctx, &verifier.QuoteRequest{
		Uid:   *u,
		Nonce: nonce,
	})
	if err != nil {
		glog.Errorf("Quote Failed,  Original Error is: %v", err)
		os.Exit(1)
	}

	// create pcr map for go-tpm-tools
	pcrMap, _, err := getPCRMap(tpm.HashAlgo_SHA256)
	if err != nil {
		glog.Errorf("  Could not get PCRMap: %s", err)
		os.Exit(1)
	}
	vpcrs := &tpmpb.PCRs{Hash: tpmpb.HashAlgo_SHA256, Pcrs: pcrMap}

	serverPlatformAttestationParameter := &attest.PlatformParameters{}
	err = json.NewDecoder(bytes.NewReader(quoteResponse.PlatformAttestation)).Decode(serverPlatformAttestationParameter)
	if err != nil {
		glog.Errorf("Quote Failed: json decoding quote response: %v", err)
		os.Exit(1)
	}

	pub, err := attest.ParseAKPublic(attest.TPMVersion20, serverAttestationParameter.Public)
	if err != nil {
		glog.Errorf("Quote Failed ParseAKPublic: %v", err)
		os.Exit(1)
	}

	for _, quote := range serverPlatformAttestationParameter.Quotes {
		if err := pub.Verify(quote, serverPlatformAttestationParameter.PCRs, nonce); err != nil {
			glog.Errorf("Quote Failed Verify: %v", err)
			os.Exit(1)
		}
	}

	for _, p := range serverPlatformAttestationParameter.PCRs {
		glog.V(20).Infof("     PCR: %d, verified: %t value: %s", p.Index, p.QuoteVerified(), hex.EncodeToString((p.Digest)))
		if p.DigestAlg == crypto.SHA256 {
			v, ok := pcrMap[uint32(p.Index)]
			if ok {
				if hex.EncodeToString(v) != hex.EncodeToString(p.Digest) {
					glog.Errorf("Quote Failed Verify for index: %d", p.Index)
					os.Exit(1)
				}
			}
		}
	}

	glog.V(5).Infof("     quotes verified")
	el, err := attest.ParseEventLog(serverPlatformAttestationParameter.EventLog)
	if err != nil {
		glog.Errorf("Quote Parsing EventLog Failed: %v", err)
		os.Exit(1)
	}

	sb, err := attest.ParseSecurebootState(el.Events(attest.HashSHA1))
	if err != nil {
		glog.Errorf("Quote Parsing EventLog Failed: %v", err)
		os.Exit(1)
	}

	glog.V(5).Infof("     secureBoot State enabled %t", sb.Enabled)

	if _, err := el.Verify(serverPlatformAttestationParameter.PCRs); err != nil {
		glog.Errorf("Quote Verify Failed: %v", err)
		os.Exit(1)
	}
	glog.V(5).Infof("=============== end Quote/Verify ===============")

	glog.V(5).Infof("=============== start ImportBlob ===============")

	glog.V(5).Infof("     importSecret %s", *importBlobSecret)

	importBlob, err := server.CreateImportBlob(ekcert.PublicKey, []byte(*importBlobSecret), vpcrs)
	if err != nil {
		glog.Errorf("Unable to CreateImportBlob : %v", err)
		os.Exit(1)
	}
	sealedOutput, err := proto.Marshal(importBlob)
	if err != nil {
		glog.Errorf("Unable to marshall ImportBlob: ", err)
		os.Exit(1)
	}

	importBlobResponse, err := c.ImportBlob(ctx, &verifier.ImportBlobRequest{
		Uid:          *u,
		EncryptedKey: sealedOutput,
	})
	if err != nil {
		glog.Errorf("ImportBlob Failed,  Original Error is: %v", err)
		os.Exit(1)
	}
	glog.V(5).Infof("     Decrypted key %s", importBlobResponse.DecryptedKey)
	glog.V(5).Infof("=============== end ImportBlob ===============")

	glog.V(5).Infof("=============== start NewKey ===============")

	newKeyResponse, err := c.NewKey(ctx, &verifier.NewKeyRequest{
		Uid: *u,
		Kid: *kid,
	})
	if err != nil {
		glog.Errorf("newKey Failed,  Original Error is: %v", err)
		os.Exit(1)
	}

	glog.V(5).Infof("     newkey Public \n%s", newKeyResponse.Public)

	keyCertificationParameter := &attest.CertificationParameters{}
	err = json.NewDecoder(bytes.NewReader(newKeyResponse.KeyCertification)).Decode(keyCertificationParameter)
	if err != nil {
		glog.Errorf("Key Certification  %v", err)
		os.Exit(1)
	}

	err = keyCertificationParameter.Verify(attest.VerifyOpts{
		Public: akp.Public,
		Hash:   crypto.SHA256,
	})
	if err != nil {
		glog.Errorf("Key Verification error %v", err)
		os.Exit(1)
	}
	glog.V(5).Infof("     new key verified")
	glog.V(5).Infof("=============== end NewKey ===============")

	glog.V(5).Infof("=============== start Sign ===============")

	dataToSign := []byte("foo")
	signResponse, err := c.Sign(ctx, &verifier.SignRequest{
		Uid:  *u,
		Kid:  *kid,
		Data: dataToSign,
	})
	if err != nil {
		glog.Errorf("Sign Failed,  Original Error is: %v", err)
		os.Exit(1)
	}

	glog.V(5).Infof("     signature: %s", base64.StdEncoding.EncodeToString(signResponse.Signed))

	hh := sha256.New()
	hh.Write(dataToSign)
	hdigest := hh.Sum(nil)

	block, _ := pem.Decode(newKeyResponse.Public)
	if block == nil {
		glog.Errorf("failed to parse PEM block containing the key: %v", err)
		os.Exit(1)
	}

	rpub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		glog.Errorf("failed to parse ParsePKIXPublicKey: %v", err)
		os.Exit(1)
	}

	err = rsa.VerifyPKCS1v15(rpub.(*rsa.PublicKey), crypto.SHA256, hdigest, signResponse.Signed)
	if err != nil {
		glog.Errorf("Verification failed Failed,  Original Error is: %v", err)
		os.Exit(1)
	}
	glog.V(5).Infof("     signature verified")
	glog.V(5).Infof("=============== end Sign ===============")

}

func getPCRMap(algo tpm.HashAlgo) (map[uint32][]byte, []byte, error) {

	pcrMap := make(map[uint32][]byte)
	var hsh hash.Hash
	// https://github.com/tpm2-software/tpm2-tools/blob/83f6f8ac5de5a989d447d8791525eb6b6472e6ac/lib/tpm2_openssl.c#L206
	if algo == tpm.HashAlgo_SHA1 {
		hsh = sha1.New()
	}
	if algo == tpm.HashAlgo_SHA256 {
		hsh = sha256.New()
	}
	if algo == tpm.HashAlgo_SHA1 || algo == tpm.HashAlgo_SHA256 {
		for _, v := range strings.Split(*expectedPCRMapSHA256, ",") {
			entry := strings.Split(v, ":")
			if len(entry) == 2 {
				uv, err := strconv.ParseUint(entry[0], 10, 32)
				if err != nil {
					return nil, nil, fmt.Errorf(" PCR key:value is invalid in parsing %s", v)
				}
				hexEncodedPCR, err := hex.DecodeString(entry[1])
				if err != nil {
					return nil, nil, fmt.Errorf(" PCR key:value is invalid in encoding %s", v)
				}
				pcrMap[uint32(uv)] = hexEncodedPCR
				hsh.Write(hexEncodedPCR)
			} else {
				return nil, nil, fmt.Errorf(" PCR key:value is invalid %s", v)
			}
		}
	} else {
		return nil, nil, fmt.Errorf("Unknown Hash Algorithm for TPM PCRs %v", algo)
	}
	if len(pcrMap) == 0 {
		return nil, nil, fmt.Errorf(" PCRMap is null")
	}
	return pcrMap, hsh.Sum(nil), nil
}
