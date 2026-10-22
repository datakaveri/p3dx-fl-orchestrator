package config

import "testing"

func TestParseDryRunVMs(t *testing.T) {
	got, err := ParseDryRunVMs(" user = 192.0.2.10 , data-provider=198.51.100.20 ")
	if err != nil || len(got) != 2 || got["user"] != "192.0.2.10" || got["data-provider"] != "198.51.100.20" {
		t.Fatalf("got %v, %v", got, err)
	}
	if got, err := ParseDryRunVMs("  "); err != nil || len(got) != 0 {
		t.Fatalf("empty: got %v, %v", got, err)
	}
	got, err = ParseDryRunVMs("user=192.0.2.10,vm:Client One=198.51.100.20,vm:client-2=198.51.100.30")
	if err != nil || len(got) != 3 || got["vm:Client One"] != "198.51.100.20" || got["vm:client-2"] != "198.51.100.30" {
		t.Fatalf("vm entries: got %v, %v", got, err)
	}
	for _, bad := range []string{"user", "user=", "=192.0.2.10", "admin=192.0.2.10", "user=192.0.2.10,", "user=a,,data-provider=b", "vm:=192.0.2.10", "vm: =192.0.2.10"} {
		if _, err := ParseDryRunVMs(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}
