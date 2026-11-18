# asherah-go

Go bindings for [Asherah](https://github.com/godaddy/asherah-ffi) envelope encryption with automatic key rotation, using [purego](https://github.com/ebitengine/purego) (no CGO required).

## Installation

### 1. Add the module

```bash
go get github.com/godaddy/asherah-ffi/asherah-go
```

### 2. Install the native library

The binding requires the prebuilt native library for your platform. Run this from your project directory:

```bash
go run github.com/godaddy/asherah-ffi/asherah-go/cmd/install-native@latest
```

This downloads the correct binary for your OS/architecture from [GitHub Releases](https://github.com/godaddy/asherah-ffi/releases), verifies the SHA256 checksum, and places it in the current working directory. The loader finds it automatically -- no environment variables needed.

Options:

```
--version v0.6.24      # Pin to a specific release (default: latest)
--output /custom/path  # Custom output directory
--repo owner/repo      # Custom GitHub repository
--libc auto|gnu|musl   # Linux C library (default: auto-detect; musl on Alpine)
```

Add the library to your `.gitignore`:

```
libasherah_ffi.*
asherah_ffi.dll
```

### Alternative: Build from source

```bash
git clone https://github.com/godaddy/asherah-ffi.git
cd asherah-ffi
cargo build --release -p asherah-ffi
export ASHERAH_GO_NATIVE=target/release
```

## Documentation

Task-oriented walkthroughs under [`docs/`](./docs/):

| Guide | When to read |
|---|---|
| [Getting started](./docs/getting-started.md) | `go get` through round-trip encrypt/decrypt. |
| [Framework integration](./docs/framework-integration.md) | `net/http`, Gin, Echo, chi, gRPC, AWS Lambda. |
| [AWS production setup](./docs/aws-production-setup.md) | KMS keys, DynamoDB, IAM policy, region routing. |
| [Testing](./docs/testing.md) | `testing` package patterns, httptest, Testcontainers, mocking via interfaces. |
| [Troubleshooting](./docs/troubleshooting.md) | Common errors with what to check first. |

## Quick Start

The simplest way to use Asherah is the global API. Call `Setup` once at startup and `Shutdown` on exit:

```go
package main

import (
    "fmt"
    "log"

    asherah "github.com/godaddy/asherah-ffi/asherah-go"
)

func main() {
    err := asherah.Setup(asherah.Config{
        ServiceName: "my-service",
        ProductID:   "my-product",
        Metastore:   "memory",  // testing only
        KMS:         "static", // testing only
    })
    if err != nil {
        log.Fatal(err)
    }
    defer asherah.Shutdown()

    ciphertext, err := asherah.EncryptString("partition-id", "sensitive data")
    if err != nil {
        log.Fatal(err)
    }

    plaintext, err := asherah.DecryptString("partition-id", ciphertext)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(plaintext) // "sensitive data"
}
```

The global API manages a session cache internally. Sessions are created on first use per partition and reused for subsequent calls. When session caching is disabled, sessions are created and closed per call.

## Factory/Session API

For direct control over session lifecycle, use `Factory` and `Session`:

```go
factory, err := asherah.NewFactory(asherah.Config{
    ServiceName: "my-service",
    ProductID:   "my-product",
    Metastore:   "memory",  // testing only
    KMS:         "static", // testing only
})
if err != nil {
    log.Fatal(err)
}
defer factory.Close()

session, err := factory.GetSession("partition-id")
if err != nil {
    log.Fatal(err)
}
defer session.Close()

ciphertext, err := session.Encrypt([]byte("sensitive data"))
if err != nil {
    log.Fatal(err)
}

plaintext, err := session.Decrypt(ciphertext)
if err != nil {
    log.Fatal(err)
}
```

### Canonical compatibility API

For code migrating from the canonical `appencryption` SDK, use `SessionFactory` and `CompatSession` which mirror the original API surface:

```go
sf := asherah.NewSessionFactory(
    &asherah.CanonicalConfig{
        Service: "my-service",
        Product: "my-product",
        Policy:  asherah.NewCryptoPolicy(),
    },
    &asherah.InMemoryMetastore{},
    asherah.NewStaticKMS("my-key"),
    nil, // AEAD (handled by native layer)
)
defer sf.Close()

session, err := sf.GetSession("partition-id")
if err != nil {
    log.Fatal(err)
}
defer session.Close()

drr, err := session.Encrypt(context.Background(), []byte("data"))
if err != nil {
    log.Fatal(err)
}

plaintext, err := session.Decrypt(context.Background(), *drr)
if err != nil {
    log.Fatal(err)
}
```

The `CompatSession` returns `*DataRowRecord` structs matching the canonical type, accepting `context.Context` parameters for API compatibility (the context is not used for cancellation).

The native `Factory` / `Session` API returns DataRowRecord JSON bytes
directly from `Session.Encrypt(data)`, so callers using that API do not need a
separate `json.Marshal` step. The compatibility API intentionally keeps the
canonical `Encrypt(ctx, data) -> *DataRowRecord` and `Decrypt(ctx, drr)`
contract and performs the JSON conversion internally.

## No Async API

Go's goroutine model makes a dedicated async API unnecessary. Goroutines are cheap and multiplexed onto OS threads by the Go runtime, so blocking sync calls are fine:

```go
// Just use goroutines
var wg sync.WaitGroup
for _, partition := range partitions {
    wg.Add(1)
    go func(p string) {
        defer wg.Done()
        ct, err := asherah.EncryptString(p, data)
        // ...
    }(partition)
}
wg.Wait()
```

## Input contract

**Partition ID** (`""`): rejected as a programming error with `error`
`"asherah-go: partition ID cannot be empty"` before any FFI call. No
row is ever written to the metastore under a degenerate partition ID.
(Go strings can't be `nil`, so there is no nil case for partition ID.)

**Plaintext** to encrypt:
- `nil []byte` and `[]byte{}` are interchangeable per Go convention.
  Both are **valid** plaintexts that round-trip through
  `Encrypt`/`Decrypt` to a zero-length slice.
- Empty `string` (`""`) is a **valid** plaintext: `EncryptString(...)`
  produces a real `DataRowRecord` envelope; `DecryptString(...)`
  returns exactly `""`.

**Ciphertext** to decrypt:
- `nil`, `[]byte{}`, or empty `string` on `Decrypt`/`DecryptString`
  returns an `error` (not valid `DataRowRecord` JSON).

**Do not short-circuit empty plaintext encryption in caller code** —
empty data is real data, encrypting it produces a genuine envelope, and
skipping encryption leaks the fact that the value was empty. See
[docs/input-contract.md](https://github.com/godaddy/asherah-ffi/blob/main/docs/input-contract.md)
for the full rationale.

## Migration from Canonical Go SDK

This replaces `github.com/godaddy/asherah/go/appencryption`. Key differences:

| | Canonical (`appencryption`) | This binding (`asherah-go`) |
|---|---|---|
| Implementation | Pure Go | Rust + purego FFI |
| CGO required | Yes (protectedmemory) or No (memguard) | No (purego) |
| Serialization | Protobuf | JSON |
| Memory protection | protectedmemory/memguard | Rust memguard (mlock + wipe) |
| Session model | `SessionFactory` | `Factory` / `Session` (+ compat layer) |
| Metastore format | Wire-compatible | Wire-compatible |

Migration steps:

1. Replace import `github.com/godaddy/asherah/go/appencryption` with `github.com/godaddy/asherah-ffi/asherah-go`
2. Install the native library via `install-native`
3. Either:
   - Use the new `Factory`/`Session` API directly, or
   - Use `SessionFactory`/`CompatSession` for a drop-in compatible API
4. Both read the same metastore tables -- no data migration required

Static KMS key configuration differs by API:

- Native config uses `StaticMasterKeyHex`, a 64-character hex string encoding
  32 bytes.
- The compatibility helper `NewStaticKMS("...")` accepts the legacy raw key
  string and converts it to hex before passing it to the native core.

## Performance

Benchmarked on Apple M4 Max, 64-byte payload, hot session cache:

| Operation | Latency |
|---|---|
| Encrypt | ~1,074 ns |
| Decrypt | ~973 ns |

## Supported Platforms

| OS | Architecture |
|---|---|
| Linux | x86_64, ARM64 |
| macOS | x86_64, ARM64 (Apple Silicon) |
| Windows | x86_64, ARM64 |

## Configuration

| Field | Type | Required | Description |
|---|---|---|---|
| `ServiceName` | `string` | Yes | Service identifier for key hierarchy |
| `ProductID` | `string` | Yes | Product identifier for key hierarchy |
| `Metastore` | `string` | Yes | `"rdbms"`, `"dynamodb"`, `"memory"` (testing) |
| `KMS` | `string` | No | `"static"` (default) or `"aws"` |
| `ConnectionString` | `*string` | No | RDBMS connection string |
| `ReplicaReadConsistency` | `*string` | No | DynamoDB read consistency |
| `DynamoDBEndpoint` | `*string` | No | Custom DynamoDB endpoint |
| `DynamoDBRegion` | `*string` | No | DynamoDB region — drives endpoint URL resolution and (when `DynamoDBSigningRegion` is unset) SigV4 signing |
| `DynamoDBSigningRegion` | `*string` | No | SigV4 signing region. When set distinct from `DynamoDBRegion`, the URL is built from `DynamoDBRegion` but SigV4 signs as `DynamoDBSigningRegion` |
| `DynamoDBTableName` | `*string` | No | DynamoDB table name |
| `RegionMap` | `map[string]string` | No | AWS KMS region-to-ARN map |
| `PreferredRegion` | `*string` | No | Preferred AWS KMS region |
| `AwsProfileName` | `*string` | No | AWS shared-credentials profile for KMS, DynamoDB, and Secrets Manager clients (native Rust SDK) |
| `EnableRegionSuffix` | `*bool` | No | Append region suffix to key IDs |
| `EnableSessionCaching` | `*bool` | No | Enable session caching (default: true) |
| `SessionCacheMaxSize` | `*int` | No | Max cached sessions (default: 1000) |
| `SessionCacheDuration` | `*int64` | No | Cache TTL in milliseconds |
| `ExpireAfter` | `*int64` | No | Key expiration in milliseconds |
| `CheckInterval` | `*int64` | No | Key check interval in milliseconds |
| `Verbose` | `*bool` | No | Enable verbose logging |
| `PoolMaxOpen` | `*int` | No | Max open DB connections (default: 0 = unlimited) |
| `PoolMaxIdle` | `*int` | No | Max idle connections to retain (default: 2) |
| `PoolMaxLifetime` | `*int64` | No | Max connection lifetime in seconds (default: 0 = unlimited) |
| `PoolMaxIdleTime` | `*int64` | No | Max idle time per connection in seconds (default: 0 = unlimited) |

For AWS KMS, DynamoDB, or Secrets Manager, when `AwsProfileName` is omitted the native Rust credential chain applies (including `AWS_PROFILE` and shared config under `~/.aws/`). Setting `AwsProfileName` selects a named profile explicitly.

You can also initialize from environment variables:

```go
err := asherah.SetupFromEnv()
// or
factory, err := asherah.NewFactoryFromEnv()
```

## Native Library Search Order

The loader searches for the native library in this order:

1. `ASHERAH_GO_NATIVE` environment variable (file or directory)
2. Current working directory (default `install-native` output)
3. `CARGO_TARGET_DIR` (for development builds)
4. Repo-relative `target/` directories (for development)
5. User cache directory (`~/.cache/asherah-go/` on Linux, `~/Library/Caches/asherah-go/` on macOS)
6. System library paths (via `dlopen`)

## API Reference

### Global API

| Function | Description |
|---|---|
| `Setup(cfg Config) error` | Initialize with a Config struct |
| `SetupFromEnv() error` | Initialize from environment variables |
| `Shutdown()` | Release all resources and cached sessions |
| `GetSetupStatus() bool` | Check if initialized |
| `Encrypt(partition, data)` | Encrypt `[]byte`, returns DRR JSON |
| `Decrypt(partition, drr)` | Decrypt DRR JSON to `[]byte` |
| `EncryptString(partition, data)` | String convenience wrapper |
| `DecryptString(partition, drr)` | String convenience wrapper |
| `SetEnvJSON(payload []byte) error` | Set env vars from JSON |
| `SetEnvMap(values map[string]*string)` | Set env vars from map |

### Factory

| Method | Description |
|---|---|
| `NewFactory(cfg Config) (*Factory, error)` | Create a factory from config |
| `NewFactoryFromEnv() (*Factory, error)` | Create a factory from env vars |
| `(*Factory).GetSession(partitionID)` | Create a session for a partition |
| `(*Factory).Close()` | Release the factory |

### Session

| Method | Description |
|---|---|
| `(*Session).Encrypt(plaintext)` | Encrypt `[]byte`, returns DRR JSON |
| `(*Session).EncryptString(plaintext)` | String convenience wrapper |
| `(*Session).Decrypt(drr)` | Decrypt DRR JSON to `[]byte` |
| `(*Session).DecryptString(drr)` | String convenience wrapper |
| `(*Session).Close()` | Release the session |

### Canonical Compatibility Layer

| Type/Function | Description |
|---|---|
| `NewSessionFactory(config, store, kms, ...)` | Create a canonical-compatible factory |
| `(*SessionFactory).GetSession(id)` | Get a canonical-compatible session |
| `(*SessionFactory).Close()` | Release the factory |
| `(*CompatSession).Encrypt(ctx, data)` | Encrypt, returns `*DataRowRecord` |
| `(*CompatSession).Decrypt(ctx, drr)` | Decrypt a `*DataRowRecord` |
| `(*CompatSession).Load(ctx, key, store)` | Load and decrypt from a store |
| `(*CompatSession).Store(ctx, data, store)` | Encrypt and store |
| `(*CompatSession).Close()` | Release the session |

## Observability hooks

### Log hook

Asherah ships first-class `log/slog` integration. The simplest way to forward
records is to hand it a `*slog.Logger` — the bridge attaches the Rust source
target as a `target` attribute on every record, so any handler routing on
attributes works out of the box:

```go
package main

import (
    "log/slog"
    "os"

    asherah "github.com/godaddy/asherah-ffi/asherah-go"
)

func main() {
    logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
        Level: slog.LevelInfo,
    }))
    if err := asherah.SetSlogLogger(logger); err != nil {
        panic(err)
    }
    defer asherah.ClearLogHook()
}
```

`SetSlogLogger` honours the underlying handler's `Enabled` check before
materialising each record, so out-of-band records below the configured level
are dropped without allocation. To forward to a `slog.Handler` directly (for
custom dispatchers), use `asherah.SetSlogHandler`.

The Rust `log` crate has a TRACE level that stdlib `slog` does not; Asherah
exports it as `asherah.LevelTrace` (one step below `slog.LevelDebug`) so you
can filter on it with the standard `slog.Leveler` interface.

For raw access pass a `LogHook` callback. `LogEvent.Level` is a `slog.Level`,
so direct comparison and dispatch works:

```go
asherah.SetLogHook(func(e asherah.LogEvent) {
    if e.Level >= slog.LevelWarn {
        slog.Default().LogAttrs(nil, e.Level, e.Message,
            slog.String("target", e.Target))
    }
})
defer asherah.ClearLogHook()
```

The hook may fire from any goroutine (including ones spawned by the
underlying Rust runtime). Implementations must be thread-safe and should not
block. Panics raised inside the hook are recovered and silently dropped —
propagating a panic across the FFI boundary is undefined behavior and would
abort the process.

### Metrics hook

Receive timing observations (`MetricEncrypt`, `MetricDecrypt`, `MetricStore`,
`MetricLoad`) and cache events (`MetricCacheHit`, `MetricCacheMiss`,
`MetricCacheStale`) via `asherah.SetMetricsHook`. Installing a hook implicitly
enables the global metrics gate; clearing it disables the gate.

```go
asherah.SetMetricsHook(func(e asherah.MetricsEvent) {
    switch e.Type {
    case asherah.MetricEncrypt, asherah.MetricDecrypt,
         asherah.MetricStore, asherah.MetricLoad:
        // Timing event: e.DurationNs is elapsed nanoseconds, e.Name is empty.
        statsd.Timing("asherah."+e.Type.String(), float64(e.DurationNs)/1e6)
    case asherah.MetricCacheHit, asherah.MetricCacheMiss, asherah.MetricCacheStale:
        // Cache event: e.Name is the cache identifier, e.DurationNs is 0.
        statsd.Increment("asherah." + e.Type.String() + "." + e.Name)
    }
})
defer asherah.ClearMetricsHook()
```

| Event type | `DurationNs` | `Name` |
|---|---|---|
| `MetricEncrypt` | elapsed ns | `""` |
| `MetricDecrypt` | elapsed ns | `""` |
| `MetricStore` | elapsed ns | `""` |
| `MetricLoad` | elapsed ns | `""` |
| `MetricCacheHit` | `0` | cache identifier |
| `MetricCacheMiss` | `0` | cache identifier |
| `MetricCacheStale` | `0` | cache identifier |

The same goroutine-safety caveats apply as for the log hook — implementations
must be thread-safe and non-blocking, and panics are recovered.

## License

Licensed under the Apache License, Version 2.0.
