# Santa - In-memory ELF Loader

Santa is an in-memory ELF loader that implements userland `execve` functionality. It can load and execute ELF binaries directly from memory without writing them to disk, making it useful for security research, sandboxing, and dynamic analysis.

## Features

- Load ELF binaries from files, stdin, or remote URLs
- Execute binaries entirely in memory (userland execve)
- Debug support with jump delays and stack inspection
- Cross-platform compatibility
- Zero disk footprint execution

## Installation

### From GitHub

Clone the repository:

```bash
git clone https://github.com/username/santa.git
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

#### Install System-wide

To install santa to your system PATH:

```bash
cargo install --path .
```

Or install directly from GitHub:

```bash
cargo install --git https://github.com/username/santa.git
```

## Usage

```
In-memory ELF loader (userland execve)

Usage: santa [OPTIONS] <BINARY> [ARGS]...

Arguments:
  <BINARY>   Binary to load (can be a filepath, "-" for stdin, or a URI with --fetch option)
  [ARGS]...  Arguments to the binary

Options:
  -d, --jump-delay <JUMP_DELAY>  Delay jump to loaded ELF for <JUMP_DELAY> seconds for debugging
  -j, --show-jumpbuf             Show jumpbuffer using objdump to a temporary file
  -s, --show-stack               Show stack contents after preparing
  -f, --fetch                    Treat binary as a URI to fetch a binary
  -h, --help                     Print help
```

## Examples

### Basic Usage

Execute a local ELF binary:

```bash
santa /bin/ls -la /tmp
```

### Load from stdin

Pipe a binary through stdin:

```bash
cat /bin/echo | santa - "Hello, World!"
```

### Fetch from URL

Download and execute a binary from a remote URL:

```bash
santa --fetch https://example.com/path/to/binary arg1 arg2
```

### Debug Mode

Execute with a 5-second delay for debugger attachment:

```bash
santa --jump-delay 5 /bin/ls -la
```

### Inspection Options

Show stack contents and jumpbuffer information:

```bash
santa --show-stack --show-jumpbuf /bin/echo "test"
```

### Combined Options

Fetch a remote binary with debugging enabled:

```bash
santa --fetch --jump-delay 3 --show-stack https://example.com/binary
```

## Development

### Prerequisites

- Rust 1.70+ (2021 edition)
- Linux/Unix-like system (for ELF support)

### Building for Development

```bash
# Debug build with full logging
RUST_LOG=debug cargo build

# Run tests
cargo test

# Run with logging
RUST_LOG=info cargo run -- /bin/echo "test"
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by userland exec research and in-memory loading techniques
- Built with Rust's memory safety guarantees for secure execution
- Thanks to the ELF specification maintainers and reverse engineering community

---

**Disclaimer**: This tool is intended for educational and research purposes. Users are responsible for complying with applicable laws and regulations.
