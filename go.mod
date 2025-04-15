module github.com/salrashid123/tpm_daemonset

go 1.23.0

toolchain go1.24.0

require (
	cloud.google.com/go/compute/metadata v0.6.0
	github.com/golang/glog v1.2.4
	github.com/golang/protobuf v1.5.4
	github.com/google/go-attestation v0.5.1
	github.com/google/go-tpm v0.9.3
	github.com/google/go-tpm-tools v0.4.5
	github.com/salrashid123/tpm_daemonset/verifier v0.0.0
	golang.org/x/net v0.39.0
	google.golang.org/grpc v1.71.1

)

require (
	github.com/google/certificate-transparency-go v1.1.2 // indirect
	github.com/google/go-configfs-tsm v0.3.3-0.20240919001351-b4b5b84fdcbc // indirect
	github.com/google/go-sev-guest v0.12.1 // indirect
	github.com/google/go-tdx-guest v0.3.2-0.20241009005452-097ee70d0843 // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/text v0.24.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250115164207-1a7da9e5054f // indirect
	google.golang.org/protobuf v1.36.6 // indirect
)

replace github.com/salrashid123/tpm_daemonset/verifier => ./verifier
