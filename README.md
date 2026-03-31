# Santa - In-memory ELF Loader

Santa is an in-memory ELF loader that implements userland `execve` functionality. It can load and execute ELF binaries directly from memory without writing them to disk, making it useful for security research, sandboxing, and dynamic analysis.

## Features

- Load ELF binaries from files, stdin, or URLs
- Execute binaries entirely in memory (userland execve)
- Optional `web_request` feature flag for fetching binaries over HTTP/HTTPS (via `ureq`)
- Minimal dependencies for a small binary footprint
- Zero disk footprint execution

## Installation

### From GitHub

Clone the repository:

```bash
git clone https://github.com/carterburn/santa.git
cd santa
```

### Building from Source

#### Debug Build

For development and debugging:

```bash
cargo build
```

The debug binary will be located at `target/debug/santa`.

#### Release Build

For optimized performance:

```bash
cargo build --release
```

The release binary will be located at `target/release/santa`.

#### Building with Web Request Support

To enable fetching binaries from HTTP/HTTPS URLs, build with the `web_request` feature flag:

```bash
cargo build --release --features web_request
```

Without this feature, attempting to load a binary from a URL will return an error.

#### Install System-wide

To install santa to your system PATH:

```bash
cargo install --path .
```

Or install directly from GitHub:

```bash
cargo install --git https://github.com/carterburn/santa.git
```

To install with web request support, add the `--features` flag:

```bash
cargo install --path . --features web_request
# OR (from GitHub)...
cargo install --git https://github.com/carterburn/santa.git --features web_request
```

## Usage

```
santa <BINARY> [ARGS]...
```

- `<BINARY>` — Path to an ELF binary, `-` for stdin, or an HTTP/HTTPS URL (requires `web_request` feature)
- `[ARGS]...` — Arguments passed to the loaded binary

## Examples

### Load a local binary

```bash
santa /bin/ls -la /tmp
```

### Load from stdin

```bash
cat /bin/echo | santa - "Hello, World!"
```

### Fetch from URL

Requires building with `--features web_request`:

```bash
santa https://example.com/path/to/binary arg1 arg2
```

## Development

### Prerequisites

- Rust (2024 edition)
- Linux (for ELF support)

### Building for Development

```bash
# Debug build with logging
RUST_LOG=debug cargo build

# Run with logging
RUST_LOG=info cargo run -- /bin/echo "test"
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. This project also includes a clause on its use of a BSD-3-Clause project's code.

## Acknowledgments

- Inspired by userland exec research and in-memory loading techniques
- Inspired by [userland-execve-rust](https://github.com/io12/userland-execve-rust) by Benjamin Levy
- Inspired heavily by the python implementation of [ulexecve](https://github.com/anvilsecure/ulexecve/tree/main). Their implementation is heavily inspired by previous userland exec approachs (such as grugq's The Design and Implementation of Userland Exec and Phrack 62). The code is generally modeled after the python version but this implementation is original and written in Rust (except the assembly snippets where credit is given).
- Built with Rust's memory safety guarantees for secure execution
- Thanks to the ELF specification maintainers and reverse engineering community

---

**Disclaimer**: This tool is intended for educational and research purposes. Users are responsible for complying with applicable laws and regulations.
