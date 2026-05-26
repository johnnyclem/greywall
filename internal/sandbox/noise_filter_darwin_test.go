//go:build darwin

package sandbox

import "testing"

func TestIsStartupNoise_Darwin(t *testing.T) {
	tests := []struct {
		name string
		ev   FsEvent
		want bool
	}{
		// Noise we want hidden.
		{"dyld root", FsEvent{Op: "open_read", Path: "/"}, true},
		{"cryptex root", FsEvent{Op: "open_read", Path: "/System/Volumes/Preboot/Cryptexes/OS"}, true},
		{"cryptex dyld", FsEvent{Op: "open_read", Path: "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld"}, true},
		{"locale", FsEvent{Op: "open_read", Path: "/usr/share/locale/UTF-8/LC_CTYPE"}, true},
		{"dtracehelper", FsEvent{Op: "open_write", Path: "/dev/dtracehelper"}, true},
		{"dev tty", FsEvent{Op: "open_write", Path: "/dev/tty"}, true},
		{"bin dir read", FsEvent{Op: "open_read", Path: "/bin"}, true},
		{"usr bin dir read", FsEvent{Op: "open_read", Path: "/usr/bin"}, true},

		// Signal we want kept.
		{"user file", FsEvent{Op: "open_read", Path: "/Users/peanut/GreyHaven/greywall/README.md"}, false},
		{"bin cat executable", FsEvent{Op: "open_read", Path: "/bin/cat"}, false},
		{"bin bash executable", FsEvent{Op: "open_read", Path: "/bin/bash"}, false},
		{"bin dir write", FsEvent{Op: "open_write", Path: "/bin"}, false},
		{"empty path", FsEvent{Op: "open_read", Path: ""}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsStartupNoise(tt.ev); got != tt.want {
				t.Errorf("IsStartupNoise(%+v) = %v, want %v", tt.ev, got, tt.want)
			}
		})
	}
}
