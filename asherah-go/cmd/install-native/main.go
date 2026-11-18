// install-native downloads the prebuilt Asherah native library for the current platform.
//
// Usage:
//
//	go run github.com/godaddy/asherah-ffi/asherah-go/cmd/install-native@latest
//	go run github.com/godaddy/asherah-ffi/asherah-go/cmd/install-native@latest --version v0.6.24
//	go run github.com/godaddy/asherah-ffi/asherah-go/cmd/install-native@latest --output /usr/local/lib
//
// On Linux it installs the musl build (libasherah-<arch>-musl.so) when the host uses musl libc,
// as Alpine does, and the glibc build otherwise. Pass --libc to choose explicitly, for example
// when building on glibc for an Alpine runtime image.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const defaultRepo = "godaddy/asherah-ffi"

func main() {
	version := flag.String("version", "", "Release version (e.g., v0.6.24). Defaults to latest.")
	output := flag.String("output", "", "Output directory. Defaults to user cache dir.")
	repo := flag.String("repo", defaultRepo, "GitHub repository (owner/name).")
	libc := flag.String("libc", "auto", "Linux C library to install for: auto, gnu or musl. auto detects the host.")
	flag.Parse()

	if *version == "" {
		v, err := fetchLatestVersion(*repo)
		if err != nil {
			fatalf("failed to determine latest version: %v", err)
		}
		*version = v
		fmt.Printf("Latest release: %s\n", *version)
	}

	musl, err := resolveMusl(runtime.GOOS, *libc, hostUsesMusl)
	if err != nil {
		fatalf("%v", err)
	}

	assetName, err := assetNameForPlatform(runtime.GOOS, runtime.GOARCH, musl)
	if err != nil {
		fatalf("%v", err)
	}

	destDir := *output
	if destDir == "" {
		// Default: current working directory. The loader searches cwd automatically.
		var err error
		destDir, err = os.Getwd()
		if err != nil {
			fatalf("unable to determine working directory: %v", err)
		}
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		fatalf("mkdir %s: %v", destDir, err)
	}

	localName := localLibraryName(runtime.GOOS)
	destFile := filepath.Join(destDir, localName)

	url := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", *repo, *version, assetName)
	checksumURL := fmt.Sprintf("https://github.com/%s/releases/download/%s/SHA256SUMS", *repo, *version)
	fmt.Printf("Downloading %s ...\n", url)

	if err := installAsset(url, checksumURL, assetName, destFile); err != nil {
		fatalf("%v", err)
	}

	fmt.Printf("\nInstalled: %s\n", destFile)
	cwd, _ := os.Getwd()
	if destDir != cwd {
		fmt.Printf("\nTo use, either set the environment variable:\n")
		fmt.Printf("  export ASHERAH_GO_NATIVE=%s\n", destDir)
		fmt.Printf("\nOr move the library to your project directory.\n")
	}
}

// resolveMusl turns the --libc flag into whether to install the musl build. Only Linux has a
// musl build, so --libc=musl is rejected elsewhere and auto is always glibc there.
func resolveMusl(goos, libc string, detect func() bool) (bool, error) {
	switch libc {
	case "auto":
		return goos == "linux" && detect(), nil
	case "gnu":
		return false, nil
	case "musl":
		if goos != "linux" {
			return false, fmt.Errorf("--libc=musl is only supported on linux, not %s", goos)
		}
		return true, nil
	default:
		return false, fmt.Errorf("invalid --libc %q: want auto, gnu or musl", libc)
	}
}

// muslLoaderGlob matches the musl dynamic loader, e.g. /lib/ld-musl-x86_64.so.1 or
// /lib/ld-musl-aarch64.so.1. glibc systems never ship it, so its presence identifies musl.
const muslLoaderGlob = "/lib/ld-musl-*.so.1"

func hostUsesMusl() bool {
	matches, err := filepath.Glob(muslLoaderGlob)
	return err == nil && len(matches) > 0
}

func assetNameForPlatform(goos, goarch string, musl bool) (string, error) {
	arch := ""
	switch goarch {
	case "amd64":
		arch = "x64"
	case "arm64":
		arch = "arm64"
	default:
		return "", fmt.Errorf("unsupported architecture: %s", goarch)
	}

	ext := ""
	switch goos {
	case "linux":
		ext = "so"
	case "darwin":
		ext = "dylib"
	case "windows":
		ext = "dll"
	default:
		return "", fmt.Errorf("unsupported OS: %s", goos)
	}

	if musl {
		if goos != "linux" {
			return "", fmt.Errorf("musl builds are only published for linux, not %s", goos)
		}
		return fmt.Sprintf("libasherah-%s-musl.%s", arch, ext), nil
	}
	return fmt.Sprintf("libasherah-%s.%s", arch, ext), nil
}

func localLibraryName(goos string) string {
	switch goos {
	case "windows":
		return "asherah_ffi.dll"
	case "darwin":
		return "libasherah_ffi.dylib"
	default:
		return "libasherah_ffi.so"
	}
}

func fetchLatestVersion(repo string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	// Use GITHUB_TOKEN if available for rate limiting
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}
	if release.TagName == "" {
		return "", fmt.Errorf("no tag_name in response")
	}
	return release.TagName, nil
}

// installAsset downloads url to a temporary path, verifies it against
// checksumURL, and only then moves it into place at destFile — a
// checksum mismatch never reaches destFile.
//
// Before this, downloadFile wrote straight to destFile (via its own
// internal atomic rename) and only *then* did verification run: the
// unverified library sat on the load path — which the loader searches
// automatically (cwd, the default install destination) with no hash or
// version check of its own — for the whole SHA256SUMS fetch/parse/hash
// window. A process that starts during that window loads an unverified
// file; an interrupt or hang during the fetch leaves one installed with
// no verdict at all. Downloading to a temp path first and renaming into
// place only after a non-fatal verification outcome means destFile is
// never written unless the download is either verified or the tool has
// explicitly decided (as it always has) to soft-skip verification for a
// release that predates SHA256SUMS.
func installAsset(url, checksumURL, assetName, destFile string) error {
	tmp := destFile + ".verify"
	if err := downloadFile(url, tmp); err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	verifyErr := verifyChecksum(checksumURL, assetName, tmp)
	if checksumIsFatal(verifyErr) {
		if rmErr := os.Remove(tmp); rmErr != nil {
			return fmt.Errorf("%w (additionally failed to remove unverified download %s: %v)", verifyErr, tmp, rmErr)
		}
		return verifyErr
	}
	if verifyErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: checksum verification skipped: %v\n", verifyErr)
	} else {
		fmt.Println("SHA256 checksum verified.")
	}

	if err := os.Rename(tmp, destFile); err != nil {
		return fmt.Errorf("finalize install: %w", err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(destFile, 0o755)
	}
	return nil
}

func downloadFile(url, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}

	tmp := dest + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}

	_, err = io.Copy(f, resp.Body)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}

	return os.Rename(tmp, dest)
}

func verifyChecksum(checksumURL, assetName, localFile string) error {
	resp, err := http.Get(checksumURL)
	if err != nil {
		return fmt.Errorf("fetch checksums: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("checksums not available (HTTP %d)", resp.StatusCode)
	}

	expectedHash, err := parseChecksumLines(resp.Body, assetName)
	if err != nil {
		return fmt.Errorf("read checksums: %w", err)
	}
	if expectedHash == "" {
		return fmt.Errorf("no checksum found for %s", assetName)
	}

	f, err := os.Open(localFile)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	actualHash := hex.EncodeToString(h.Sum(nil))

	if actualHash != expectedHash {
		// Removing localFile on a mismatch is installAsset's job, not
		// this function's: verifyChecksum only verifies, so its callers
		// (and tests) have one place that owns the file's lifecycle.
		return &checksumMismatchError{expected: expectedHash, actual: actualHash}
	}
	return nil
}

// checksumMismatchError distinguishes "the checksum was computed and it
// does not match" (must abort — the download is tampered or corrupted)
// from every other verifyChecksum error, such as the sums file being
// unavailable (soft-fail: warn and continue, matching this tool's
// long-standing behavior for older releases that predate SHA256SUMS).
type checksumMismatchError struct {
	expected, actual string
}

func (e *checksumMismatchError) Error() string {
	return fmt.Sprintf("checksum mismatch: expected %s, got %s", e.expected, e.actual)
}

// checksumIsFatal reports whether err represents a genuine checksum
// mismatch — the download was fetched, hashed, and the hash does not
// match, so it must never be installed — as opposed to every other
// verifyChecksum error (sums file unavailable, network failure, no
// matching entry), which main() treats as soft: warn and continue,
// matching this tool's long-standing behavior for releases that
// predate SHA256SUMS.
//
// This is the one decision this tool's checksum verification exists
// to make, so it is its own function rather than inline in main():
// callers can test the decision directly instead of only exercising
// the checksumMismatchError type declaration and the standard library.
func checksumIsFatal(err error) bool {
	var mismatch *checksumMismatchError
	return errors.As(err, &mismatch)
}

// parseChecksumLines scans a SHA256SUMS file body (format: "<hash>
// <filename>" per line) for the entry matching assetName. Extracted from
// verifyChecksum so the untrusted-input parsing — the release asset is
// fetched over HTTP and could be tampered with or corrupted — can be
// fuzzed without a network call.
//
// Takes an io.Reader rather than a []byte deliberately: SHA256SUMS is
// remote, untrusted input, and buffering the full response before
// parsing (e.g. via io.ReadAll) would let an arbitrarily large release
// asset exhaust memory before verification even starts. bufio.Scanner
// reads one line at a time (bounded by bufio.MaxScanTokenSize) and this
// returns as soon as a match is found, so memory use stays bounded
// regardless of the response size.
//
// Returns a non-nil error only if the scan itself failed (a network
// error mid-read, or a line exceeding bufio.MaxScanTokenSize) —
// distinct from a clean scan that simply never found a matching entry
// (hash == "", err == nil). Without this distinction, a truncated or
// corrupted SHA256SUMS response looked identical to "this release
// predates SHA256SUMS," both silently reaching the same soft-warn path
// in main(). They still share that soft-warn fate today — only a real
// checksumMismatchError hard-fails — but the two cases are now
// diagnosable instead of indistinguishable in the tool's output.
func parseChecksumLines(r io.Reader, assetName string) (hash string, err error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) == 2 && parts[1] == assetName {
			return parts[0], nil
		}
	}
	return "", scanner.Err()
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}
