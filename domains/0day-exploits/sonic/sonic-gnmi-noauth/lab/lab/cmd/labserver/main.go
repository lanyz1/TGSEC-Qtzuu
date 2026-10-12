package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/sonic-net/sonic-gnmi/common_utils"
	gnmi "github.com/sonic-net/sonic-gnmi/gnmi_server"
	"github.com/sonic-net/sonic-gnmi/probe"
	"github.com/sonic-net/sonic-gnmi/telemetry"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

const witness = "SONIC-GNMI-NOAUTH-WITNESS"

func boolPtr(b bool) *bool { return &b }

func productionClientAuthCert() gnmi.AuthTypes {
	// setupFlags initial map, then --client_auth cert (gnmi-native.sh fail-closed default).
	a := gnmi.AuthTypes{"password": false, "cert": false, "jwt": false}
	if err := a.Set("cert"); err != nil {
		log.Fatal(err)
	}
	return a
}

func applyToR() *gnmi.Config {
	// Production ToR no-cert:
	// telemetry --noTLS --bind_address 127.0.0.1 --port 8080 --client_auth cert
	// no --ca_crt. Lab bind is 0.0.0.0 in-container; compose publishes 127.0.0.1:18080.
	empty := ""
	noTLS := true
	tel := &telemetry.TelemetryConfig{
		UserAuth:          productionClientAuthCert(),
		CaCert:            &empty,
		NoTLS:             &noTLS,
		Insecure:          boolPtr(false),
		AllowNoClientCert: boolPtr(false),
	}
	telemetry.ApplyCaCertCertUnset(tel)
	cfg := &gnmi.Config{
		EnableNativeWrite:   gnmi.ENABLE_NATIVE_WRITE,
		EnableTranslibWrite: gnmi.ENABLE_TRANSLIB_WRITE,
	}
	telemetry.CopyUserAuthIfTLS(tel, cfg)
	return cfg
}

func applyDPU() *gnmi.Config {
	// Production DPU no-cert:
	// telemetry --insecure --allow_no_client_auth --port 8080 --client_auth cert
	// --config_table_name GNMI_CLIENT_CERT, no --ca_crt.
	empty := ""
	noTLS := false
	tel := &telemetry.TelemetryConfig{
		UserAuth:          productionClientAuthCert(),
		CaCert:            &empty,
		NoTLS:             &noTLS,
		Insecure:          boolPtr(true),
		AllowNoClientCert: boolPtr(true),
	}
	telemetry.ApplyCaCertCertUnset(tel)
	cfg := &gnmi.Config{
		EnableNativeWrite:   gnmi.ENABLE_NATIVE_WRITE,
		EnableTranslibWrite: gnmi.ENABLE_TRANSLIB_WRITE,
		ConfigTableName:     "GNMI_CLIENT_CERT",
	}
	telemetry.CopyUserAuthIfTLS(tel, cfg)
	return cfg
}

func passwordClosedCfg() *gnmi.Config {
	return &gnmi.Config{
		UserAuth:            gnmi.AuthTypes{"password": true, "cert": false, "jwt": false},
		EnableNativeWrite:   gnmi.ENABLE_NATIVE_WRITE,
		EnableTranslibWrite: gnmi.ENABLE_TRANSLIB_WRITE,
	}
}

type probeSrv struct {
	probe.UnimplementedProbeServer
	cfg  *gnmi.Config
	mode string
}

func (s *probeSrv) Check(ctx context.Context, req *probe.CheckRequest) (*probe.CheckReply, error) {
	cfg := s.cfg
	if req.GetRequirePasswordAuth() {
		cfg = passwordClosedCfg()
	}
	ctx, err := gnmi.Authenticate(cfg, ctx, "gnoi", true)
	if err != nil {
		return nil, err
	}
	rc, _ := common_utils.GetContext(ctx)
	if cfg.UserAuth.Any() {
		return nil, status.Error(codes.PermissionDenied, "user_auth still enabled")
	}
	log.Printf("check mode=%s enable_native_write=%v auth_enabled=%v user_auth_any=%v",
		s.mode, gnmi.ENABLE_NATIVE_WRITE, rc.Auth.AuthEnabled, cfg.UserAuth.Any())
	return &probe.CheckReply{
		Witness:             witness,
		AuthEnabled:         rc.Auth.AuthEnabled,
		EnableNativeWrite:   gnmi.ENABLE_NATIVE_WRITE,
		EnableTranslibWrite: gnmi.ENABLE_TRANSLIB_WRITE,
		UserAuthAny:         cfg.UserAuth.Any(),
		Mode:                s.mode,
	}, nil
}

func serve(addr string, tlsCfg *tls.Config, cfg *gnmi.Config, mode string, errc chan error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		errc <- err
		return
	}
	var opts []grpc.ServerOption
	if tlsCfg != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsCfg)))
	}
	s := grpc.NewServer(opts...)
	probe.RegisterProbeServer(s, &probeSrv{cfg: cfg, mode: mode})
	log.Printf("listen mode=%s addr=%s tls=%v enable_native_write=%v user_auth_any=%v",
		mode, addr, tlsCfg != nil, gnmi.ENABLE_NATIVE_WRITE, cfg.UserAuth.Any())
	errc <- s.Serve(lis)
}

func main() {
	flag.Parse()
	if !gnmi.ENABLE_NATIVE_WRITE || !gnmi.ENABLE_TRANSLIB_WRITE {
		log.Fatalf("write flags off native=%v translib=%v", gnmi.ENABLE_NATIVE_WRITE, gnmi.ENABLE_TRANSLIB_WRITE)
	}
	fmt.Printf("enable_native_write=%v enable_translib_write=%v\n", gnmi.ENABLE_NATIVE_WRITE, gnmi.ENABLE_TRANSLIB_WRITE)

	torCfg := applyToR()
	dpuCfg := applyDPU()
	if torCfg.UserAuth.Any() || dpuCfg.UserAuth.Any() {
		log.Fatalf("expected empty UserAuth after setupFlags unset tor_any=%v dpu_any=%v", torCfg.UserAuth.Any(), dpuCfg.UserAuth.Any())
	}

	cert, err := tls.LoadX509KeyPair("/certs/server.crt", "/certs/server.key")
	if err != nil {
		log.Fatal(err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequestClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	errc := make(chan error, 2)
	go serve(":18080", nil, torCfg, "tor", errc)
	go serve(":18081", tlsCfg, dpuCfg, "dpu", errc)
	log.Printf("lab-ready tor=:18080 dpu=:18081 enable_native_write=true")
	log.Fatal(<-errc)
}
