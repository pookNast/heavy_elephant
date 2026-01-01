# Rust Crypto Documentation (Context7)

## SHA-1 One-shot API

```rust
use hex_literal::hex;
use sha1::{Sha1, Digest};

let result = Sha1::digest(b"hello world");
assert_eq!(result, hex!("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"));
```

## SHA-1 Incremental API

```rust
use hex_literal::hex;
use sha1::{Sha1, Digest};

let mut hasher = Sha1::new();
hasher.update(b"hello world");
let hash = hasher.finalize();

assert_eq!(hash, hex!("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"));

// Hex-encode hash using https://docs.rs/base16ct
let hex_hash = base16ct::lower::encode_string(&hash);
```

## HMAC Usage (for MAC verification)

```rust
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

let key = b"secret key";
let mut mac = HmacSha256::new_from_slice(key)
    .expect("HMAC can take key of any size");
mac.update(b"very secret data");
let result = mac.finalize();
let tag = result.into_bytes();
```

## HMAC-SHA1 Pattern (for PS5 tools)

```rust
use sha1::Sha1;
use hmac::{Hmac, Mac};

type HmacSha1 = Hmac<Sha1>;

let key = hex!("1EE22F6A189E7D99A28B9A96D3C4DBA2"); // Example MAC key
let mut mac = HmacSha1::new_from_slice(&key)
    .expect("HMAC can take key of any size");
mac.update(ciphertext);
let result = mac.finalize();
let computed_tag = result.into_bytes();

// Constant-time comparison
use subtle::ConstantTimeEq;
if computed_tag.ct_eq(&expected_tag).into() {
    // MAC verified, proceed with decryption
}
```

## Dynamic Hash Selection

```rust
use digest::DynDigest;

fn select_hasher(s: &str) -> Box<dyn DynDigest> {
    match s {
        "md5" => Box::new(md5::Md5::default()),
        "sha1" => Box::new(sha1::Sha1::default()),
        "sha256" => Box::new(sha2::Sha256::default()),
        _ => unimplemented!("unsupported digest: {}", s),
    }
}
```

---

# Clap CLI Documentation (Context7)

## Derive Macro Pattern

```rust
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "boot-decryptor")]
#[command(about = "Decrypt PS5 boot chain components")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Decrypt EMC IPL header
    EmcHeader {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Decrypt EAP KBL
    EapKbl {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, help = "Skip MAC verification")]
        skip_mac: bool,
    },
}
```

## Help Output Pattern

```console
$ boot-decryptor --help
Decrypt PS5 boot chain components

Usage: boot-decryptor <COMMAND>

Commands:
  emc-header  Decrypt EMC IPL header
  eap-kbl     Decrypt EAP KBL
  help        Print this message

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## Enum Arguments

```rust
#[derive(clap::ValueEnum, Clone)]
enum OutputFormat {
    Raw,
    Hex,
    Base64,
}

#[derive(Parser)]
struct Args {
    #[arg(value_enum, default_value_t = OutputFormat::Raw)]
    format: OutputFormat,
}
```
