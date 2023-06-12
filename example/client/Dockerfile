FROM golang:1.19 as build

RUN apt-get update -y && apt-get install -y build-essential wget unzip curl git libtspi-dev

RUN curl -OL https://github.com/google/protobuf/releases/download/v3.19.0/protoc-3.19.0-linux-x86_64.zip && \
    unzip protoc-3.19.0-linux-x86_64.zip -d protoc3 && \
    mv protoc3/bin/* /usr/local/bin/ && \
    mv protoc3/include/* /usr/local/include/

WORKDIR /app
ADD . /app

RUN go mod download

# RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
# RUN go install github.com/golang/protobuf/protoc-gen-go@latest
# RUN protoc --go_out=. --go_opt=paths=source_relative --go-grpc_opt=require_unimplemented_servers=false --go-grpc_out=. --go-grpc_opt=paths=source_relative verifier/verifier.proto
RUN GOOS=linux GOARCH=amd64 go build -buildvcs=true -o /go/bin/grpc_verifier grpc_verifier.go 
RUN chown root:root /go/bin/grpc_verifier


# FROM gcr.io/distroless/base
# COPY --from=build /go/bin/grpc_verifier /grpc_verifier
# ENTRYPOINT ["/grpc_verifier", "--host=app-service:50051 --v=10 -alsologtostderr]
