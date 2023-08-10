module main

go 1.21

require (
	github.com/golang/glog v1.1.2
	github.com/google/go-attestation v0.5.0
	github.com/google/go-tpm v0.9.0
	github.com/google/go-tpm-tools v0.4.0
	github.com/google/uuid v1.3.0
	//github.com/salrashid123/tpm_daemonset/verifier v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.57.0
	google.golang.org/protobuf v1.31.0

)

require github.com/salrashid123/tpm_daemonset/verifier v0.0.0-20230810105258-9a27408cfaa3

require (
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/certificate-transparency-go v1.1.2 // indirect
	github.com/google/go-sev-guest v0.6.1 // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/pborman/uuid v1.2.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	golang.org/x/crypto v0.0.0-20220525230936-793ad666bf5e // indirect
	golang.org/x/net v0.9.0 // indirect
	golang.org/x/sys v0.9.0 // indirect
	golang.org/x/text v0.9.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230525234030-28d5490b6b19 // indirect
)

// replace github.com/salrashid123/tpm_daemonset/verifier => ../../verifier
