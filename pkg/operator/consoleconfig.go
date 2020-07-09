package operator

// partial copy of console CLI config

type ConsoleConfig struct {
	Customization `yaml:"customization"`
}

type Customization struct {
	Branding string `yaml:"branding"`
}
