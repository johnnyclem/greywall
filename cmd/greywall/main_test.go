package main

import (
	"strings"
	"testing"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

func boolPtr(b bool) *bool { return &b }

func TestResolveRecordFs(t *testing.T) {
	cases := []struct {
		name      string
		flag      bool
		noFlag    bool
		watch     bool
		learning  bool
		cfg       *config.Config
		want      bool
		wantErrIs string
	}{
		{name: "default off", want: false},
		{name: "watch auto-enables", watch: true, want: true},
		{name: "watch + --no-record-fs opts out", watch: true, noFlag: true, want: false},
		{name: "learning alone does not auto-enable", learning: true, want: false},
		{name: "learning + --record-fs", learning: true, flag: true, want: true},
		{name: "watch + --record-fs (redundant but ok)", watch: true, flag: true, want: true},

		{
			name: "config enables under watch",
			cfg:  &config.Config{Observability: config.ObservabilityConfig{RecordFilesystem: boolPtr(true)}},
			watch: true, want: true,
		},
		{
			name: "explicit config false beats watch auto-enable",
			cfg:  &config.Config{Observability: config.ObservabilityConfig{RecordFilesystem: boolPtr(false)}},
			watch: true, want: false,
		},
		{
			name: "config enables under learning",
			cfg:  &config.Config{Observability: config.ObservabilityConfig{RecordFilesystem: boolPtr(true)}},
			learning: true, want: true,
		},

		{
			name: "--record-fs without watch or learning errors",
			flag: true, wantErrIs: "requires --watch or --learning",
		},
		{
			name: "config enables without watch or learning errors",
			cfg:  &config.Config{Observability: config.ObservabilityConfig{RecordFilesystem: boolPtr(true)}},
			wantErrIs: "requires --watch or --learning",
		},
		{
			name: "--record-fs and --no-record-fs mutually exclusive",
			flag: true, noFlag: true, wantErrIs: "mutually exclusive",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveRecordFs(tc.flag, tc.noFlag, tc.watch, tc.learning, tc.cfg)
			if tc.wantErrIs != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErrIs)
				}
				if !strings.Contains(err.Error(), tc.wantErrIs) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.wantErrIs)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("resolveRecordFs = %v, want %v", got, tc.want)
			}
		})
	}
}
