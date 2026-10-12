# Loopback lab image for unpublished SONiC gNMI empty-UserAuth fail-open.
# Pin files are copied into the build context; no host home bind-mounts.
FROM golang:1.25-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        protobuf-compiler python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY pin/ /src/pin/
COPY lab/ /src/lab/
COPY check_extracts.py /src/check_extracts.py
RUN python3 /src/check_extracts.py

ENV GOPROXY=https://proxy.golang.org,direct
ENV PATH="/go/bin:${PATH}"
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.8 \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1

WORKDIR /src/lab
COPY certs/ /certs/
RUN protoc --go_out=. --go_opt=module=github.com/sonic-net/sonic-gnmi \
        --go-grpc_out=. --go-grpc_opt=module=github.com/sonic-net/sonic-gnmi \
        proto/probe.proto \
    && go mod tidy \
    && CGO_ENABLED=0 go build -tags gnmi_native_write,gnmi_translib_write \
        -o /usr/local/bin/labserver ./cmd/labserver

EXPOSE 18080 18081
CMD ["/usr/local/bin/labserver"]
