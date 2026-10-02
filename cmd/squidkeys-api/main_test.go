package main

import "testing"

func TestValidateServeConfig(t *testing.T) {
	cases := []struct {
		name, host, policy, cert, key, bearer string
		wantErr                               bool
	}{
		{"legacy loopback", "127.0.0.1", "", "", "", "legacy", false},
		{"organization loopback", "localhost", "policy.json", "", "", "", false},
		{"ipv6 loopback", "::1", "", "", "", "", false},
		{"remote without policy", "0.0.0.0", "", "cert.pem", "key.pem", "", true},
		{"remote without TLS", "192.0.2.1", "policy.json", "", "", "", true},
		{"remote organization TLS", "0.0.0.0", "policy.json", "cert.pem", "key.pem", "", false},
		{"partial TLS", "127.0.0.1", "", "cert.pem", "", "", true},
		{"mixed bearer modes", "127.0.0.1", "policy.json", "", "", "legacy", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateServeConfig(tc.host, tc.policy, tc.cert, tc.key, tc.bearer)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}
