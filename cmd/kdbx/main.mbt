///|
/// Entry point of the `kdbx` command line tool.
///
/// The command line owns argument parsing, file I/O and printing. Parsing,
/// authentication and vault construction stay in the `kdbx` package.

///|
enum CliCommand {
  Help
  Invalid(String)
  Info(String)
  List(String)
  Show(String, String, Bool)
}

///|
fn parse_cli(args : Array[String]) -> CliCommand {
  let user_args = without_program_name(args)
  if user_args.length() == 0 {
    return Help
  }
  let command = user_args[0]
  if command == "help" || command == "--help" || command == "-h" {
    return Help
  }
  if command != "info" && command != "ls" && command != "show" {
    return Invalid("unknown command '" + command + "'")
  }
  let positional : Array[String] = []
  let mut reveal = false
  let mut index = 1
  while index < user_args.length() {
    let arg = user_args[index]
    if arg == "--reveal" {
      reveal = true
    } else if arg == "--help" || arg == "-h" {
      return Help
    } else if arg.has_prefix("-") {
      return Invalid("unknown option '" + arg + "'")
    } else {
      positional.push(arg)
    }
    index = index + 1
  }
  if command == "info" {
    if positional.length() != 1 {
      Invalid("info expects exactly one database path")
    } else {
      Info(positional[0])
    }
  } else if command == "ls" {
    if positional.length() != 1 {
      Invalid("ls expects exactly one database path")
    } else {
      List(positional[0])
    }
  } else if positional.length() != 2 {
    Invalid("show expects a database path and an entry title or UUID")
  } else {
    Show(positional[0], positional[1], reveal)
  }
}

///|
/// Native executables receive their own path as argv[0], while the Wasm and JS
/// launchers may omit it. Recognising the first command makes both layouts
/// expose the same user-facing syntax.
fn without_program_name(args : Array[String]) -> Array[String] {
  if args.length() == 0 {
    return []
  }
  let first = args[0]
  let first_is_command = first == "info" ||
    first == "ls" ||
    first == "show" ||
    first == "help" ||
    first == "--help" ||
    first == "-h"
  let start = if first_is_command { 0 } else { 1 }
  let out : Array[String] = []
  let mut index = start
  while index < args.length() {
    out.push(args[index])
    index = index + 1
  }
  out
}

///|
fn print_usage() -> Unit {
  println(@lib.banner())
  println("")
  println("Usage: kdbx <command> <database.kdbx> [arguments]")
  println("")
  println("Commands:")
  println("  info <file>              show format, cipher, KDF and counts")
  println(
    "  ls <file>                list group path, title, user name and UUID",
  )
  println("  show <file> <entry>      show one entry by exact title or UUID")
  println("")
  println("Options:")
  println("  --reveal                 show protected field values in `show`")
  println("  -h, --help               show this help")
  println("")
  println("The database password is read from the KDBX_PASSWORD environment")
  println(
    "variable, so it does not appear in shell history or process arguments.",
  )
}

///|
fn load_database(path : String, password : String) -> @lib.OpenedDatabase? {
  let data = @fs.read_file_to_bytes(path) catch {
    _ => {
      println("kdbx: cannot read database: " + path)
      return None
    }
  }
  let key = @lib.MasterKey::new().with_password(password)
  let database = @lib.read_database(data, key) catch {
    error => {
      println("kdbx: cannot open database: " + error.message())
      return None
    }
  }
  Some(database)
}

///|
fn open_or_exit(path : String) -> @lib.OpenedDatabase? {
  match @env.get_env_var("KDBX_PASSWORD") {
    Some(password) => load_database(path, password)
    None => {
      println("kdbx: KDBX_PASSWORD is not set")
      None
    }
  }
}

///|
fn print_info(path : String, database : @lib.OpenedDatabase) -> Unit {
  let header = database.outer_header()
  let verification = database.verification()
  let kdf = database.kdf_parameters()
  println("File: " + path)
  println("Revision: " + verification.revision())
  println("Cipher: " + verification.cipher().to_text())
  println("Compression: " + verification.compression().to_text())
  println("KDF: " + @lib.kdf_name(kdf))
  println("KDF parameters:")
  for item in kdf.entries() {
    let (name, value) = item
    println("  " + name + "=" + value.to_text())
  }
  println("Generator: " + database.vault().generator())
  println("Groups: " + database.vault().group_count().to_string())
  println("Entries: " + database.vault().entry_count().to_string())
  println(
    "Attachments: " + database.inner_header().binaries().length().to_string(),
  )
  println("Header bytes: " + header.byte_length().to_string())
}

///|
fn print_list(database : @lib.OpenedDatabase) -> Unit {
  let entries = database.vault().entries()
  if entries.length() == 0 {
    println("No entries.")
    return
  }
  println("GROUP\tTITLE\tUSERNAME\tUUID")
  for item in entries {
    let (path, entry) = item
    let title = entry.field("Title").unwrap_or("")
    let user = entry.field("UserName").unwrap_or("")
    println(path + "\t" + title + "\t" + user + "\t" + entry.uuid())
  }
}

///|
fn print_entry(path : String, entry : @lib.VaultEntry, reveal : Bool) -> Unit {
  println("Group: " + path)
  println("UUID: " + entry.uuid())
  for field in entry.fields() {
    let value = if field.is_protected() && !reveal {
      "<redacted; use --reveal>"
    } else {
      field.value()
    }
    println(field.key() + ": " + value)
  }
}

///|
fn main {
  match parse_cli(@env.args()) {
    Help => print_usage()
    Invalid(message) => {
      println("kdbx: " + message)
      println("kdbx: run 'kdbx --help' for usage")
      @sys.exit(2)
    }
    Info(path) =>
      match open_or_exit(path) {
        Some(database) => print_info(path, database)
        None => @sys.exit(1)
      }
    List(path) =>
      match open_or_exit(path) {
        Some(database) => print_list(database)
        None => @sys.exit(1)
      }
    Show(path, query, reveal) =>
      match open_or_exit(path) {
        Some(database) =>
          match database.vault().find_entry(query) {
            Some(item) => {
              let (group_path, entry) = item
              print_entry(group_path, entry, reveal)
            }
            None => {
              println("kdbx: no entry matches title or UUID: " + query)
              @sys.exit(1)
            }
          }
        None => @sys.exit(1)
      }
  }
}

///|
/// One-line banner shared by the CLI and the README.
pub fn banner() -> String {
  @lib.banner()
}
