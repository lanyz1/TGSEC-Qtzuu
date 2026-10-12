module github.com/sonic-net/sonic-gnmi

go 1.25.0

require (
	github.com/golang/glog v1.2.4
	google.golang.org/grpc v1.75.1
	google.golang.org/protobuf v1.36.8
)

replace github.com/golang/glog => ./stubglog
