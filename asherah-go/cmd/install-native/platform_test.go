package main

import "testing"

func TestAssetNameForPlatform(t *testing.T) {
	tests := []struct {
		goos, goarch string
		musl         bool
		want         string
	}{
		{"linux", "amd64", false, "libasherah-x64.so"},
		{"linux", "arm64", false, "libasherah-arm64.so"},
		{"linux", "amd64", true, "libasherah-x64-musl.so"},
		{"linux", "arm64", true, "libasherah-arm64-musl.so"},
		{"darwin", "arm64", false, "libasherah-arm64.dylib"},
		{"windows", "amd64", false, "libasherah-x64.dll"},
	}
	for _, tt := range tests {
		got, err := assetNameForPlatform(tt.goos, tt.goarch, tt.musl)
		if err != nil {
			t.Errorf("assetNameForPlatform(%s, %s, %v) error: %v", tt.goos, tt.goarch, tt.musl, err)
			continue
		}
		if got != tt.want {
			t.Errorf("assetNameForPlatform(%s, %s, %v) = %q, want %q", tt.goos, tt.goarch, tt.musl, got, tt.want)
		}
	}
}

func TestAssetNameForPlatformRejectsMuslOffLinux(t *testing.T) {
	if _, err := assetNameForPlatform("darwin", "arm64", true); err == nil {
		t.Fatal("musl on darwin should be rejected")
	}
}

func TestResolveMusl(t *testing.T) {
	isMusl := func() bool { return true }
	isGnu := func() bool { return false }
	tests := []struct {
		goos, libc string
		detect     func() bool
		want       bool
	}{
		{"linux", "auto", isMusl, true},
		{"linux", "auto", isGnu, false},
		{"darwin", "auto", isMusl, false}, // detection only applies to linux
		{"linux", "gnu", isMusl, false},
		{"linux", "musl", isGnu, true},
	}
	for _, tt := range tests {
		got, err := resolveMusl(tt.goos, tt.libc, tt.detect)
		if err != nil {
			t.Errorf("resolveMusl(%s, %s) error: %v", tt.goos, tt.libc, err)
			continue
		}
		if got != tt.want {
			t.Errorf("resolveMusl(%s, %s) = %v, want %v", tt.goos, tt.libc, got, tt.want)
		}
	}
}

func TestResolveMuslRejectsBadInput(t *testing.T) {
	if _, err := resolveMusl("linux", "uclibc", func() bool { return false }); err == nil {
		t.Error("unknown --libc value should be rejected")
	}
	if _, err := resolveMusl("windows", "musl", func() bool { return false }); err == nil {
		t.Error("--libc=musl on windows should be rejected")
	}
}
