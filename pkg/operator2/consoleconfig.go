package operator2

// partial copy of console CLI config

type ConsoleConfig struct {
	Customization `yaml:"customization"`
}

type Customization struct {
	Branding string `yaml:"branding"`
}
