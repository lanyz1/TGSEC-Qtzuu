package telemetry

import (
	log "github.com/golang/glog"
	gnmi "github.com/sonic-net/sonic-gnmi/gnmi_server"
)

type TelemetryConfig struct {
	UserAuth          gnmi.AuthTypes
	CaCert            *string
	NoTLS             *bool
	Insecure          *bool
	AllowNoClientCert *bool
}

// ApplyCaCertCertUnset is the setupFlags block that strips cert mode when ca_crt is empty.
func ApplyCaCertCertUnset(telemetryCfg *TelemetryConfig) {
	if *telemetryCfg.CaCert == "" && telemetryCfg.UserAuth.Enabled("cert") {
		telemetryCfg.UserAuth.Unset("cert")
		log.V(2).Info("client_auth mode cert requires ca_crt option. Disabling cert mode authentication.")
	}
}

// CopyUserAuthIfTLS models startGNMIServer copying cfg.UserAuth only inside the TLS branch.
func CopyUserAuthIfTLS(telemetryCfg *TelemetryConfig, cfg *gnmi.Config) {
	if telemetryCfg.NoTLS != nil && !*telemetryCfg.NoTLS {
		cfg.UserAuth = telemetryCfg.UserAuth
	}
}
