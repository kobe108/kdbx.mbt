///|
/// Entry point of the `kdbx` command line tool.
///
/// The command line surface is deliberately thin: it owns argument parsing and
/// printing, while every decision lives in the `kdbx` package so that the same
/// behaviour can be unit-tested without spawning a process.
///
/// Current state: the container parser is implemented, so the next milestone
/// (see docs/DESIGN.md) is wiring file input and the `info` subcommand.
fn main {
  println(banner())
  println("")
  println("Usage: kdbx <command> [options] <database.kdbx>")
  println("")
  println("Commands (planned, see docs/DESIGN.md for the milestone plan):")
  println(
    "  info    show format revision, cipher, KDF parameters and entry counts",
  )
  println("  ls      list entries (group path, title, user name)")
  println("  show    print one entry by UUID or title")
  println("  audit   report weak, reused, stale and expired credentials")
  println("  export  write entries as CSV or JSON")
  println("")
  println("Implemented so far: KDBX 4.x outer header and variant dictionary.")
}

///|
/// One-line banner shared by the CLI and the README.
pub fn banner() -> String {
  @lib.banner()
}
