module main

go 1.22.0

toolchain go1.24.0

require (
	github.com/golang/glog v1.2.4
	github.com/google/go-attestation v0.5.1
	github.com/google/go-tpm v0.9.3
	github.com/google/go-tpm-tools v0.4.5
	github.com/google/uuid v1.6.0
	//github.com/salrashid123/tpm_daemonset/verifier v0.0.0
	google.golang.org/grpc v1.71.1
	google.golang.org/protobuf v1.36.6
)

require github.com/salrashid123/tpm_daemonset/verifier v0.0.0-20240725104710-35a8e15e8426

require (
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/certificate-transparency-go v1.1.2 // indirect
	github.com/google/gce-tcb-verifier v0.2.3-0.20240905212129-12f728a62786 // indirect
	github.com/google/go-configfs-tsm v0.3.3-0.20240919001351-b4b5b84fdcbc // indirect
	github.com/google/go-eventlog v0.0.2-0.20241003021507-01bb555f7cba // indirect
	github.com/google/go-sev-guest v0.12.1 // indirect
	github.com/google/go-tdx-guest v0.3.2-0.20241009005452-097ee70d0843 // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.32.0 // indirect
	golang.org/x/exp v0.0.0-20240531132922-fd00a4e0eefc // indirect
	golang.org/x/net v0.34.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250115164207-1a7da9e5054f // indirect
)

//replace github.com/salrashid123/tpm_daemonset/verifier => ../../verifier
