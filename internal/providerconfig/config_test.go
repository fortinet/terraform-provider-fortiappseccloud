package providerconfig

import (
	"strings"
	"testing"
)

func TestResolve(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		input   Input
		env     map[string]string
		want    Config
		wantErr string
	}{
		"configured token": {
			input: Input{APIToken: Value{Set: true, Value: "token"}},
			want:  Config{Hostname: DefaultHostname, APIToken: "token"},
		},
		"environment token and hostname": {
			env:  map[string]string{EnvHostname: "api.example.test", EnvAPIToken: "env-token"},
			want: Config{Hostname: "api.example.test", APIToken: "env-token"},
		},
		"configured values override environment": {
			input: Input{
				Hostname: Value{Set: true, Value: "configured.example.test"},
				APIToken: Value{Set: true, Value: "configured-token"},
			},
			env:  map[string]string{EnvHostname: "env.example.test", EnvAPIToken: "env-token"},
			want: Config{Hostname: "configured.example.test", APIToken: "configured-token"},
		},
		"username password": {
			input: Input{
				Username: Value{Set: true, Value: "user"},
				Password: Value{Set: true, Value: " password with spaces "},
			},
			want: Config{Hostname: DefaultHostname, Username: "user", Password: " password with spaces "},
		},
		"missing credentials": {
			wantErr: "configure api_token or username and password",
		},
		"partial username password": {
			input:   Input{Username: Value{Set: true, Value: "user"}},
			wantErr: "username and password must be configured together",
		},
		"conflicting modes": {
			input: Input{
				APIToken: Value{Set: true, Value: "do-not-leak-token"},
				Username: Value{Set: true, Value: "user"},
				Password: Value{Set: true, Value: "do-not-leak-password"},
			},
			wantErr: "configure either api_token or username and password, not both",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			config, err := Resolve(test.input, func(key string) string { return test.env[key] })
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("Resolve() error = %v, want %q", err, test.wantErr)
				}
				for _, secret := range []string{"do-not-leak-token", "do-not-leak-password"} {
					if strings.Contains(err.Error(), secret) {
						t.Fatalf("Resolve() leaked %q: %v", secret, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve() error = %v", err)
			}
			if config != test.want {
				t.Fatalf("Resolve() = %#v, want %#v", config, test.want)
			}
		})
	}
}
