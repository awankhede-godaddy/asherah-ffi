// Command musl-stack-repro exercises Setup, Encrypt and Decrypt from goroutines that are not on
// the main OS thread. On musl those threads get a 128 KiB stack, which the native library used to
// overflow (SIGSEGV in cgo execution). It uses the in-memory metastore and static KMS so it needs
// no AWS access.
package main

import (
	"fmt"
	"os"
	"runtime"
	"sync"

	asherah "github.com/godaddy/asherah-ffi/asherah-go"
)

func init() {
	// Keep the main goroutine on the main thread so every call below runs on another thread.
	runtime.LockOSThread()
}

func onOtherThread(f func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		errc <- f()
	}()
	return <-errc
}

func onOtherThread2(f func() ([]byte, error)) ([]byte, error) {
	type res struct {
		b   []byte
		err error
	}
	c := make(chan res, 1)
	go func() {
		runtime.LockOSThread()
		b, err := f()
		c <- res{b, err}
	}()
	r := <-c
	return r.b, r.err
}

func main() {
	key := "746869734973415374617469634d61737465724b6579466f7254657374696e67"
	caching := true
	cfg := asherah.Config{
		ServiceName:          "svc",
		ProductID:            "prod",
		Metastore:            "memory",
		KMS:                  "static",
		StaticMasterKeyHex:   &key,
		EnableSessionCaching: &caching,
	}
	if len(os.Args) > 1 && os.Args[1] == "aws" {
		// Builds real AWS SDK clients (the deep-stack path rdproxy hits in NewFactory) against
		// the real AWS endpoints with fake credentials, so requests go through TLS and the SDK but are
		// rejected as unauthenticated and nothing is read or written.
		region, table := "us-west-2", "asherah-stack-repro-nonexistent"
		cfg.Metastore, cfg.KMS, cfg.StaticMasterKeyHex = "dynamodb", "aws", nil
		cfg.PreferredRegion, cfg.DynamoDBRegion, cfg.DynamoDBTableName = &region, &region, &table
		cfg.RegionMap = map[string]string{region: "arn:aws:kms:us-west-2:111111111111:key/00000000-0000-0000-0000-000000000000"}
		if err := onOtherThread(func() error { return asherah.Setup(cfg) }); err != nil {
			fmt.Fprintln(os.Stderr, "setup:", err)
			os.Exit(1)
		}
		fmt.Println("setup ok (aws, non-main thread)")
		_, err := onOtherThread2(func() ([]byte, error) { return asherah.Encrypt("partition", []byte("x")) })
		fmt.Println("encrypt returned (aws, non-main thread), err set:", err != nil)
		return
	}
	if err := onOtherThread(func() error { return asherah.Setup(cfg) }); err != nil {
		fmt.Fprintln(os.Stderr, "setup:", err)
		os.Exit(1)
	}
	defer asherah.Shutdown()
	fmt.Println("setup ok (non-main thread)")

	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- onOtherThread(func() error {
				plain := fmt.Sprintf("secret-%d", i)
				drr, err := asherah.Encrypt("partition", []byte(plain))
				if err != nil {
					return fmt.Errorf("encrypt: %w", err)
				}
				got, err := asherah.Decrypt("partition", drr)
				if err != nil {
					return fmt.Errorf("decrypt: %w", err)
				}
				if string(got) != plain {
					return fmt.Errorf("round trip: got %q want %q", got, plain)
				}
				return nil
			})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	fmt.Println("encrypt/decrypt ok x32 (non-main threads)")
}
