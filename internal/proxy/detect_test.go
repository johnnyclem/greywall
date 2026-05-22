package proxy

import "testing"

func TestSupportsFsEvents(t *testing.T) {
	cases := []struct {
		version string
		want    bool
	}{
		{"", true},         // unknown version: assume supported (dev / probe failed)
		{"dev", true},      // local dev build: bypass gate
		{"0.3.4", false},   // older than MinVersionFsEvents (0.5.0)
		{"0.4.4", false},   // current shipped greyproxy: still too old
		{"0.5.0", true},    // exact min
		{"0.5.1", true},    // newer patch
		{"0.6.0", true},    // newer minor
		{"1.0.0", true},    // newer major
		{"garbage", false}, // unparseable: treat as old (IsOlderVersion convention)
	}
	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			if got := SupportsFsEvents(tc.version); got != tc.want {
				t.Errorf("SupportsFsEvents(%q) = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}
