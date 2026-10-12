package gnmi

// Config is the subset of production gnmi.Config that authenticate() reads.
type Config struct {
	UserAuth            AuthTypes
	EnableTranslibWrite bool
	EnableNativeWrite   bool
	ConfigTableName     string
	EnableCrl           bool
}
