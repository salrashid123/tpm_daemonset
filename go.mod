module github.com/salrashid123/tpm_daemonset

go 1.21

require (
	cloud.google.com/go/compute/metadata v0.2.3
	github.com/golang/glog v1.1.1
	github.com/golang/protobuf v1.5.3
	github.com/google/go-attestation v0.5.0
	github.com/google/go-tpm v0.9.0
	github.com/google/go-tpm-tools v0.3.13-0.20230620182252-4639ecce2aba
	github.com/salrashid123/tpm_daemonset/verifier v0.0.0
	golang.org/x/net v0.10.0
	google.golang.org/grpc v1.55.0
)

require (
	cloud.google.com/go/compute v1.18.0 // indirect
	github.com/google/certificate-transparency-go v1.1.2 // indirect
	github.com/google/go-sev-guest v0.6.1 // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/pborman/uuid v1.2.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/crypto v0.0.0-20220525230936-793ad666bf5e // indirect
	golang.org/x/sys v0.9.0 // indirect
	golang.org/x/text v0.9.0 // indirect
	google.golang.org/genproto v0.0.0-20230306155012-7f2fa6fef1f4 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
)

replace github.com/salrashid123/tpm_daemonset/verifier => ./verifier
