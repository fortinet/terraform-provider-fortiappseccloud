package waf

import "testing"

func TestLegacyConfigTokenClientIsCredentialFree(t *testing.T) {
	t.Setenv("FORTIWEB_CLOUD_SESSION", "")
	t.Setenv("FORTIWEB_CLOUD_SESSION_TIMESTAMP", "")

	for name, config := range map[string]Config{
		"missing hostname": {Token: "token"},
		"missing auth":     {HostName: "https://legacy.example.test"},
		"partial basic":    {HostName: "https://legacy.example.test", UserName: "user"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := config.CheckConfig(); err == nil {
				t.Fatal("CheckConfig() accepted invalid legacy configuration")
			}
		})
	}

	configured, err := (&Config{HostName: "https://legacy.example.test", Token: "unit-token"}).CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() error = %v", err)
	}
	client, ok := configured.(*WAFClient)
	if !ok || client.CloudClient == nil {
		t.Fatalf("CreateClient() = %T, want *WAFClient", configured)
	}
	if client.CloudClient.Host != "https://legacy.example.test" || client.CloudClient.Token != "Basic unit-token" || !client.CloudClient.Init {
		t.Fatalf("legacy token client = %#v", client.CloudClient)
	}
}

func TestLegacyResourceContracts(t *testing.T) {
	app := ResourceApp()
	if app.Create == nil || app.Read == nil || app.Update == nil || app.Delete == nil || app.Importer == nil {
		t.Fatal("legacy application resource is missing a lifecycle callback or importer")
	}
	for _, name := range []string{"app_name", "domain_name", "origin_server_ip", "ep_id"} {
		if app.Schema[name] == nil {
			t.Errorf("legacy application schema is missing %q", name)
		}
	}
	if !app.Schema["app_name"].Required || !app.Schema["domain_name"].Required || !app.Schema["origin_server_ip"].Required {
		t.Error("legacy application identity/bootstrap fields must remain required")
	}
	if !app.Schema["ep_id"].Computed {
		t.Error("legacy application ep_id must remain computed")
	}

	openAPI := ResourceOpenApiValidation()
	if openAPI.Create == nil || openAPI.Read == nil || openAPI.Update == nil || openAPI.Delete == nil || openAPI.Importer == nil {
		t.Fatal("legacy OpenAPI validation resource is missing a lifecycle callback or importer")
	}
	for _, name := range []string{"app_name", "action", "enable", "validation_files"} {
		if openAPI.Schema[name] == nil {
			t.Errorf("legacy OpenAPI validation schema is missing %q", name)
		}
	}
	if !openAPI.Schema["app_name"].Required || !openAPI.Schema["action"].Required {
		t.Error("legacy OpenAPI validation identity/action must remain required")
	}
	if value, ok := openAPI.Schema["enable"].Default.(bool); !ok || !value {
		t.Errorf("legacy OpenAPI validation enable default = %#v, want true", openAPI.Schema["enable"].Default)
	}
}

func TestLegacyPureHelpers(t *testing.T) {
	if BoolToInt(false) != 0 || BoolToInt(true) != 1 {
		t.Fatal("BoolToInt() does not preserve the legacy wire encoding")
	}
	if !IsIPAddress("192.0.2.1") || !IsIPAddress("2001:db8::1") || IsIPAddress("example.test") {
		t.Fatal("IsIPAddress() returned an unexpected classification")
	}
}
