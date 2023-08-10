package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"

	"flag"
	"fmt"
	"io/ioutil"
	mrnd "math/rand"
	"net"
	"os"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/salrashid123/tpm_daemonset/verifier"

	"golang.org/x/net/context"

	"google.golang.org/grpc"

	"google.golang.org/grpc/status"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"cloud.google.com/go/compute/metadata"
)

var (
	grpcport  = flag.String("grpcport", "", "grpcport")
	caCertTLS = flag.String("caCertTLS", "certs/root.pem", "CA Certificate to trust")

	serverCert   = flag.String("servercert", "certs/server_crt.pem", "Server SSL Certificate")
	serverKey    = flag.String("serverkey", "certs/server_key.pem", "Server SSL PrivateKey")
	eventLogPath = flag.String("eventLogPath", "/sys/kernel/security/tpm0/binary_bios_measurements", "Path to the eventlog")
	tpmDevice    = flag.String("tpmDevice", "/dev/tpm0", "TPMPath")

	contextsPath    = flag.String("contextsPath", "/contexts", "Contexts Path")
	attestationKeys = make(map[string][]byte)

	handleNames = map[string][]tpm2.HandleType{
		"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    {tpm2.HandleTypeLoadedSession},
		"saved":     {tpm2.HandleTypeSavedSession},
		"transient": {tpm2.HandleTypeTransient},
	}
	ek          attest.EK
	letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
)

const ()

type server struct {
	mu sync.Mutex
}

type hserver struct {
	statusMap map[string]healthpb.HealthCheckResponse_ServingStatus
}

type contextKey string

func authUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	glog.V(40).Infof(">> inbound request")
	return handler(ctx, req)
}

func (s *hserver) Check(ctx context.Context, in *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	if in.Service == "" {
		return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVICE_UNKNOWN}, nil
	}
	glog.V(10).Infof("HealthCheck called for Service [%s]", in.Service)
	s.statusMap["attest.Attestor"] = healthpb.HealthCheckResponse_SERVING
	status, ok := s.statusMap[in.Service]
	if !ok {
		return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_UNKNOWN}, grpc.Errorf(codes.NotFound, "unknown service")
	}
	return &healthpb.HealthCheckResponse{Status: status}, nil
}

func (s *hserver) Watch(in *healthpb.HealthCheckRequest, srv healthpb.Health_WatchServer) error {
	return status.Error(codes.Unimplemented, "Watch is not implemented")
}

func (s *server) GetEK(ctx context.Context, in *verifier.GetEKRequest) (*verifier.GetEKResponse, error) {
	glog.V(2).Infof("======= GetEK ========")
	if ek.Public != nil {
		pubBytes, err := x509.MarshalPKIXPublicKey(ek.Public)
		if err != nil {
			glog.Errorf("ERROR:  could  marshall public key %v", err)
			return &verifier.GetEKResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:   could  marshall public key"))
		}

		if ek.Certificate != nil {
			return &verifier.GetEKResponse{
				EkPub:  pubBytes,
				EkCert: ek.Certificate.Raw,
			}, nil
		}
		return &verifier.GetEKResponse{
			EkPub: pubBytes,
		}, nil
	} else {
		glog.Errorf("ERROR:  could  EK not set")
		return &verifier.GetEKResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  could  not set"))
	}
}

func (s *server) GetAK(ctx context.Context, in *verifier.GetAKRequest) (*verifier.GetAKResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= GetAK ========")

	config := &attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		glog.Errorf("ERROR:  opening tpm %v", err)
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  could not get TPM"))
	}
	defer tpm.Close()

	var attestParams attest.AttestationParameters

	if _, err := os.Stat(fmt.Sprintf("%s/%s.ak", *contextsPath, in.Uid)); err == nil {
		akBytes, err := os.ReadFile(fmt.Sprintf("%s/%s.ak", *contextsPath, in.Uid))
		if err != nil {
			glog.Errorf("ERROR:  error reading ak file at path %v", err)
			return &verifier.GetAKResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:   error reading ak file at path"))
		}
		ak, err := tpm.LoadAK(akBytes)
		if err != nil {
			glog.Errorf("ERROR:  error loading ak AK %v", err)
			return &verifier.GetAKResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error loading ak"))
		}
		defer ak.Close(tpm)
		attestParams = ak.AttestationParameters()
	} else {
		akConfig := &attest.AKConfig{}
		ak, err := tpm.NewAK(akConfig)
		if err != nil {
			glog.Errorf("ERROR:  could not get AK %v", err)
			return &verifier.GetAKResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  could get AK"))
		}
		attestParams = ak.AttestationParameters()
		akBytes, err := ak.Marshal()
		if err != nil {
			glog.Errorf("ERROR:  could not marshall AK %v", err)
			return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ERROR:  could get AK"))
		}
		if err := os.WriteFile(fmt.Sprintf("%s/%s.ak", *contextsPath, in.Uid), akBytes, 0600); err != nil {
			glog.Errorf("ERROR:  could not write ak to file %v", err)
			return &verifier.GetAKResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  writing AK to file"))
		}
	}
	attestParametersBytes := new(bytes.Buffer)
	err = json.NewEncoder(attestParametersBytes).Encode(attestParams)
	if err != nil {
		glog.Errorf("ERROR:  encode attestation parameters AK %v", err)
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  could generate attestationParameters"))
	}
	return &verifier.GetAKResponse{
		Ak: attestParametersBytes.Bytes(),
	}, nil
}

func (s *server) Attest(ctx context.Context, in *verifier.AttestRequest) (*verifier.AttestResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= Attest ========")

	config := &attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		glog.Errorf("ERROR:  opening tpm %v", err)
		return &verifier.AttestResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  could not get TPM"))
	}
	defer tpm.Close()

	_, err = os.Stat(fmt.Sprintf("%s/%s.ak", *contextsPath, in.Uid))
	if err != nil {
		glog.Errorf("ERROR:  cannot Attest without Attestion Key; first run GetAK %v", err)
		return &verifier.AttestResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:   cannot Attest without Attestion Key; first run GetAK"))
	}

	akBytes, err := os.ReadFile(fmt.Sprintf("%s/%s.ak", *contextsPath, in.Uid))
	if err != nil {
		glog.Errorf("ERROR:  error reading ak file at path %v", err)
		return &verifier.AttestResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:   error reading ak file at path"))
	}
	ak, err := tpm.LoadAK(akBytes)
	if err != nil {
		glog.Errorf("ERROR:  error loading ak AK %v", err)
		return &verifier.AttestResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error loading ak"))
	}
	defer ak.Close(tpm)
	var encryptedCredentials attest.EncryptedCredential
	err = json.Unmarshal(in.EncryptedCredentials, &encryptedCredentials)
	if err != nil {
		glog.Errorf("ERROR:  error decoding encryptedCredentials %v", err)
		return &verifier.AttestResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error decoding encryptedCredentials"))
	}

	secret, err := ak.ActivateCredential(tpm, encryptedCredentials)
	if err != nil {
		glog.Errorf("ERROR:  error activating Credential  AK %v", err)
		return &verifier.AttestResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error activating Credentials"))
	}

	return &verifier.AttestResponse{
		Secret: secret,
	}, nil
}

func (s *server) Quote(ctx context.Context, in *verifier.QuoteRequest) (*verifier.QuoteResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= Quote ========")

	config := &attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		glog.Errorf("ERROR:  opening tpm %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  could not get TPM"))
	}
	defer tpm.Close()

	_, err = os.Stat(fmt.Sprintf("%s/%s.ak", *contextsPath, in.Uid))
	if err != nil {
		glog.Errorf("ERROR:  cannot Quote without Attestion Key; first run GetAK %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:   cannot Quote without Attestion Key; first run GetAK"))
	}

	akBytes, err := os.ReadFile(fmt.Sprintf("%s/%s.ak", *contextsPath, in.Uid))
	if err != nil {
		glog.Errorf("ERROR:  error reading ak file at path %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:   error reading ak file at path"))
	}
	ak, err := tpm.LoadAK(akBytes)
	if err != nil {
		glog.Errorf("ERROR:  error loading ak AK %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error loading ak"))
	}
	defer ak.Close(tpm)
	evtLog, err := os.ReadFile(*eventLogPath)
	if err != nil {
		glog.Errorf("     Error reading eventLog %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error reading eventLog: %v", err))
	}

	platformAttestation, err := tpm.AttestPlatform(ak, in.Nonce, &attest.PlatformAttestConfig{
		EventLog: evtLog,
	})
	if err != nil {
		glog.Errorf("ERROR: creating Attestation %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  creating Attestation "))
	}

	platformAttestationBytes := new(bytes.Buffer)
	err = json.NewEncoder(platformAttestationBytes).Encode(platformAttestation)
	if err != nil {
		glog.Errorf("ERROR: encoding platformAttestationBytes %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  encoding platformAttestationBytes "))
	}

	return &verifier.QuoteResponse{
		PlatformAttestation: platformAttestationBytes.Bytes(),
	}, nil
}

func (s *server) ImportBlob(ctx context.Context, in *verifier.ImportBlobRequest) (*verifier.ImportBlobResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= ImportBlob ========")

	blob := &pb.ImportBlob{}

	err := proto.Unmarshal(in.EncryptedKey, blob)
	if err != nil {
		glog.Errorf("ERROR:  unmarshalling encryptedBLob proto %v", err)
		return &verifier.ImportBlobResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  could not unmarshal encryptedBLob proto"))
	}

	rwc, err := tpm2.OpenTPM(*tpmDevice)
	if err != nil {
		glog.Errorf("ERROR:  error opening TPM %v", err)
		return &verifier.ImportBlobResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error opening TPM"))
	}
	defer rwc.Close()

	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		glog.Errorf("ERROR:  loading EndorsementKeyRSA %v", err)
		return &verifier.ImportBlobResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  loading EndorsementKeyRSA"))
	}
	defer ek.Close()

	decodedSecret, err := ek.Import(blob)
	if err != nil {
		glog.Errorf("ERROR:  error importing secret %v", err)
		return &verifier.ImportBlobResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error importing secret"))
	}

	return &verifier.ImportBlobResponse{
		DecryptedKey: decodedSecret,
	}, nil
}

func (s *server) ImportSigningKey(ctx context.Context, in *verifier.ImportSigningKeyRequest) (*verifier.ImportSigningKeyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= ImportSigningKey ========")

	glog.Errorf("ERROR:  Unimplemented")
	return &verifier.ImportSigningKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  ImportSigningBlob unimplemented"))
}

func (s *server) NewKey(ctx context.Context, in *verifier.NewKeyRequest) (*verifier.NewKeyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= NewKey ========")

	config := &attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		glog.Errorf("ERROR:  opening tpm %v", err)
		return &verifier.NewKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  could not get TPM"))
	}
	defer tpm.Close()

	_, err = os.Stat(fmt.Sprintf("%s/%s.ak", *contextsPath, in.Uid))
	if err != nil {
		glog.Errorf("ERROR:   cannot create NewKey without Attestion Key; first run GetAK %v", err)
		return &verifier.NewKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:   cannot create NewKey without Attestion Key; first run GetAK"))
	}

	akBytes, err := os.ReadFile(fmt.Sprintf("%s/%s.ak", *contextsPath, in.Uid))
	if err != nil {
		glog.Errorf("ERROR:  error reading ak file at path %v", err)
		return &verifier.NewKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:   error reading ak file at path"))
	}
	ak, err := tpm.LoadAK(akBytes)
	if err != nil {
		glog.Errorf("ERROR:  error loading ak AK %v", err)
		return &verifier.NewKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error loading ak"))
	}
	defer ak.Close(tpm)
	// todo: support other keytypes,sizes
	kConfig := &attest.KeyConfig{
		Algorithm: attest.RSA,
		Size:      2048,
	}
	nk, err := tpm.NewKey(ak, kConfig)
	if err != nil {
		glog.Errorf("ERROR:  error creating key  %v", err)
		return &verifier.NewKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR: creating key"))
	}

	nkBytes, err := nk.Marshal()
	if err != nil {
		glog.Errorf("ERROR:  could not marshall newkey %v", err)
		return &verifier.NewKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ERROR:  could marshall newkey"))
	}
	if err := os.WriteFile(fmt.Sprintf("%s/%s.%s", *contextsPath, in.Uid, in.Kid), nkBytes, 0600); err != nil {
		glog.Errorf("ERROR:  could not write ak to file %v", err)
		return &verifier.NewKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  writing AK to file"))
	}

	pubKey, ok := nk.Public().(*rsa.PublicKey)
	if !ok {
		glog.Errorf("Could not assert the public key to rsa public key")
		return &verifier.NewKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR: Could not assert the public key to rsa public key"))
	}

	pubkeybytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		glog.Errorf("Could not MarshalPKIXPublicKey rsa public key")
		return &verifier.NewKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR: Could not MarshalPKIXPublicKey rsa public key"))
	}
	pubkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkeybytes,
		},
	)

	keyCertificationBytes := new(bytes.Buffer)
	err = json.NewEncoder(keyCertificationBytes).Encode(nk.CertificationParameters())
	if err != nil {
		glog.Errorf("ERROR: encoding keyCertificationBytes %v", err)
		return &verifier.NewKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  encoding keyCertificationBytes "))
	}

	return &verifier.NewKeyResponse{
		Public:           []byte(pubkeyPem),
		KeyCertification: keyCertificationBytes.Bytes(),
	}, nil
}

func (s *server) Sign(ctx context.Context, in *verifier.SignRequest) (*verifier.SignResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= Sign ========")

	rwc, err := tpm2.OpenTPM(*tpmDevice)
	if err != nil {
		glog.Errorf("ERROR:  error opening TPM %v", err)
		return &verifier.SignResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error opening TPM"))
	}
	defer rwc.Close()

	config := &attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		glog.Errorf("ERROR:  opening tpm %v", err)
		return &verifier.SignResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  could not get TPM"))
	}
	defer tpm.Close()

	_, err = os.Stat(fmt.Sprintf("%s/%s.%s", *contextsPath, in.Uid, in.Kid))
	if err != nil {
		glog.Errorf("ERROR:  cannot Sign without signing key Key; first run GetAK then NewKey %v", err)
		return &verifier.SignResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:    cannot Sign without signing key Key; first run GetAK then NewKey "))
	}

	skBytes, err := os.ReadFile(fmt.Sprintf("%s/%s.%s", *contextsPath, in.Uid, in.Kid))
	if err != nil {
		glog.Errorf("ERROR:  error reading sigining key file at path %v", err)
		return &verifier.SignResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:   error reading signing file at path"))
	}

	var sig []byte

	sk, err := tpm.LoadKey(skBytes)
	if err != nil {
		glog.Errorf("ERROR:  error loading signing key %v", err)
		return &verifier.SignResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error loading signing key"))
	}
	defer sk.Close()

	pk, err := sk.Private(sk.Public())
	if err != nil {
		glog.Errorf("ERROR:  error loading privatekey %v", err)
		return &verifier.SignResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error loading signing privatekey"))
	}

	signer, ok := pk.(crypto.Signer)
	if !ok {
		glog.Errorf("ERROR:  error creating crypto.signer from privatekey %v", err)
		return &verifier.SignResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error creating crypto.signer from privatekey"))
	}

	h := sha256.New()
	h.Write(in.Data)
	digest := h.Sum(nil)

	sig, err = signer.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		glog.Errorf("ERROR:  error signing %v", err)
		return &verifier.SignResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error signing"))
	}

	return &verifier.SignResponse{
		Signed: sig,
	}, nil
}

func (s *server) GetGCEEKSigningKey(ctx context.Context, in *verifier.GetGCEEKSigningKeyRequest) (*verifier.GetGCEEKSigningKeyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= GetGCEEKSigningKey ========")

	if !metadata.OnGCE() {
		glog.Errorf("ERROR:  Not on GCE")
		return &verifier.GetGCEEKSigningKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  not on GCE"))
	}

	rwc, err := tpm2.OpenTPM(*tpmDevice)
	if err != nil {
		glog.Errorf("ERROR:  could not open tpm device: %v", err)
		return &verifier.GetGCEEKSigningKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  Error opening tpm device"))

	}
	defer func() {
		if err := rwc.Close(); err != nil {
			glog.Errorf("%v\ncan't close TPM %q: %v", *tpmDevice, err)
		}
	}()

	kk, err := client.EndorsementKeyFromNvIndex(rwc, client.GceAKTemplateNVIndexRSA)
	if err != nil {
		glog.Errorf("ERROR:  could not get EndorsementKeyFromNvIndex: %v", err)
		return &verifier.GetGCEEKSigningKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  not on GCE"))
	}
	defer kk.Close()
	pubKey := kk.PublicKey().(*rsa.PublicKey)
	akBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		glog.Errorf("ERROR:  could not MarshalPKIXPublicKey: %v", err)
		return &verifier.GetGCEEKSigningKeyResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:   could not MarshalPKIXPublicKey"))
	}
	akPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akBytes,
		},
	)
	glog.V(10).Infof("     Signing PEM \n%s", string(akPubPEM))

	return &verifier.GetGCEEKSigningKeyResponse{
		Public: akPubPEM,
	}, nil
}

func (s *server) SignGCEEK(ctx context.Context, in *verifier.SignGCEEKRequest) (*verifier.SignGCEEKResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= SignGCEEK ========")

	if !metadata.OnGCE() {
		glog.Errorf("ERROR:  Not on GCE")
		return &verifier.SignGCEEKResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  not on GCE"))
	}

	rwc, err := tpm2.OpenTPM(*tpmDevice)
	if err != nil {
		glog.Errorf("ERROR:  could not open tpm device: %v", err)
		return &verifier.SignGCEEKResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  Error opening tpm device"))

	}
	defer func() {
		if err := rwc.Close(); err != nil {
			glog.Errorf("%v\ncan't close TPM %q: %v", *tpmDevice, err)
		}
	}()

	kk, err := client.EndorsementKeyFromNvIndex(rwc, client.GceAKTemplateNVIndexRSA)
	if err != nil {
		glog.Errorf("ERROR:  could not get EndorsementKeyFromNvIndex: %v", err)
		return &verifier.SignGCEEKResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  Error reading EndorsementKeyFromNvIndex"))
	}
	defer kk.Close()

	r, err := kk.SignData(in.Data)
	if err != nil {
		glog.Errorf("ERROR:  error singing with go-tpm-tools: %v", err)
		return &verifier.SignGCEEKResponse{}, grpc.Errorf(codes.Internal, fmt.Sprintf("ERROR:  could not sign with EndorsementKeyFromNvIndex"))

	}

	return &verifier.SignGCEEKResponse{
		Signed: r,
	}, nil

}

func main() {

	flag.Parse()

	if *grpcport == "" {
		fmt.Fprintln(os.Stderr, "missing -grpcport flag (:50051)")
		flag.Usage()
		os.Exit(2)
	}

	var err error
	rwc, err := tpm2.OpenTPM(*tpmDevice)
	if err != nil {
		glog.Fatalf("can't open TPM %q: %v", tpmDevice, err)
	}

	totalHandles := 0
	for _, handleType := range handleNames["all"] {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			glog.Fatalf("getting handles: %v", err)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				glog.Fatalf("flushing handle 0x%x: %v", handle, err)
			}
			glog.V(10).Infof("Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}
	if err := rwc.Close(); err != nil {
		glog.Fatalf("can't close TPM %q: %v", tpmDevice, err)
	}
	glog.V(2).Info("Getting EKCert reset")

	config := &attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		glog.Fatalf("error opening TPM %v", err)
	}

	eks, err := tpm.EKs()
	if err != nil {
		glog.Fatalf("error getting EK %v", err)
	}

	for _, e := range eks {
		if e.Certificate != nil {
			glog.Infof("ECCert with available Issuer: %s", e.Certificate.Issuer)
		}
	}

	ek = eks[0]

	var tlsConfig *tls.Config
	ca, err := ioutil.ReadFile(*caCertTLS)
	if err != nil {
		glog.Fatalf("Faild to read CA Certificate file %s: %v", *caCertTLS, err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(ca)

	serverCerts, err := tls.LoadX509KeyPair(*serverCert, *serverKey)
	if err != nil {
		glog.Fatalf("Failed to read Server Certificate files %s  %s: %v", *serverCert, *serverKey, err)
	}

	tlsConfig = &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{serverCerts},
	}

	ce := credentials.NewTLS(tlsConfig)

	lis, err := net.Listen("tcp", *grpcport)
	if err != nil {
		glog.Fatalf("failed to listen: %v", err)
	}

	sopts := []grpc.ServerOption{grpc.MaxConcurrentStreams(10)}
	sopts = append(sopts, grpc.Creds(ce), grpc.UnaryInterceptor(authUnaryInterceptor))
	s := grpc.NewServer(sopts...)

	verifier.RegisterVerifierServer(s, &server{})
	healthpb.RegisterHealthServer(s, &hserver{
		statusMap: make(map[string]healthpb.HealthCheckResponse_ServingStatus),
	})

	glog.V(2).Infof("Starting gRPC server on port %v", *grpcport)
	mrnd.Seed(time.Now().UnixNano())
	s.Serve(lis)
}
