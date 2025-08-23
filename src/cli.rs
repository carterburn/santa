use std::{num::ParseIntError, time::Duration};

use clap::Parser;

#[derive(Parser)]
#[command(name = "santa")]
#[command(about = "In-memory ELF loader (userland execve)")]
pub struct Cli {
    /// Binary to load (can be a filepath, "-" for stdin, or a URI with --download option to fetch)
    pub binary: String,

    /// Arguments to the binary
    pub args: Vec<String>,

    #[arg(short = 'd', long, value_parser = parse_duration)]
    /// Delay jump to loaded ELF for <JUMP_DELAY> seconds for debugging
    pub jump_delay: Option<Duration>,

    #[arg(short = 'j', long)]
    /// Show jumpbuffer using objdump to a temporary file
    pub show_jumpbuf: bool,

    #[arg(short = 's', long)]
    /// Show stack contents after preparing
    pub show_stack: bool,

    #[arg(short, long)]
    /// Treat binary as a URI to fetch a binary
    pub fetch: bool,
}

fn parse_duration(arg: &str) -> Result<Duration, ParseIntError> {
    Ok(Duration::from_secs(arg.parse()?))
}
