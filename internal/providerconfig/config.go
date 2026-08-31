package providerconfig

import (
	"errors"
	"os"
	"strings"
)

const (
	DefaultHostname = "api.appsec.fortinet.com"

	HostnameDescription       = "The FortiAppSec Cloud API hostname."
	UsernameDescription       = "FortiAppSec Cloud username for compatibility authentication."
	PasswordDescription       = "FortiAppSec Cloud password for compatibility authentication."
	APITokenDescription       = "FortiAppSec Cloud API key secret."
	InsecureDescription       = "Disable TLS certificate verification. Use only for explicitly trusted development endpoints."
	CACertFileDescription     = "Path to a custom CA certificate bundle used to verify the API endpoint."
	TimeoutSecondsDescription = "Maximum duration in seconds for one API operation."

	EnvHostname = "FORTIAPPSECCLOUD_HOSTNAME"
	EnvAPIToken = "FORTIAPPSECCLOUD_API_TOKEN"
	EnvUsername = "FORTIAPPSECCLOUD_USERNAME"
	EnvPassword = "FORTIAPPSECCLOUD_PASSWORD"
)

// Value preserves whether a provider attribute was present in configuration.
type Value struct {
	Value string
	Set   bool
}

// Input contains provider configuration before environment resolution.
type Input struct {
	Hostname Value
	APIToken Value
	Username Value
	Password Value
}

// Config is the resolved provider configuration shared by SDKv2 and Framework.
type Config struct {
	Hostname string
	APIToken string
	Username string
	Password string
}

// ResolveOS resolves provider configuration using the process environment.
func ResolveOS(input Input) (Config, error) {
	return Resolve(input, os.Getenv)
}

// Resolve applies configured values, environment fallbacks, and authentication validation.
func Resolve(input Input, getenv func(string) string) (Config, error) {
	config := Config{
		Hostname: strings.TrimSpace(resolveValue(input.Hostname, getenv(EnvHostname))),
		APIToken: resolveValue(input.APIToken, getenv(EnvAPIToken)),
		Username: resolveValue(input.Username, getenv(EnvUsername)),
		Password: resolveValue(input.Password, getenv(EnvPassword)),
	}
	if config.Hostname == "" {
		config.Hostname = DefaultHostname
	}

	hasToken := strings.TrimSpace(config.APIToken) != ""
	hasUsername := strings.TrimSpace(config.Username) != ""
	hasPassword := config.Password != ""

	if hasToken && (hasUsername || hasPassword) {
		return Config{}, errors.New("configure either api_token or username and password, not both")
	}
	if hasUsername != hasPassword {
		return Config{}, errors.New("username and password must be configured together")
	}
	if !hasToken && !hasUsername {
		return Config{}, errors.New("configure api_token or username and password")
	}

	return config, nil
}

func resolveValue(configured Value, environment string) string {
	if configured.Set && strings.TrimSpace(configured.Value) != "" {
		return configured.Value
	}
	if strings.TrimSpace(environment) != "" {
		return environment
	}
	return ""
}
