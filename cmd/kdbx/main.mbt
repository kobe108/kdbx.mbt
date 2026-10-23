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
  Audit(String, AuditFormat, Int, Bool)
  Export(String, ExportFormat, Bool, String)
}

///|
enum AuditFormat {
  Markdown
  Json
}

///|
enum ExportFormat {
  Csv
  Json
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
  if command != "info" &&
    command != "ls" &&
    command != "show" &&
    command != "audit" &&
    command != "export" {
    return Invalid("unknown command '" + command + "'")
  }
  let positional : Array[String] = []
  let mut reveal = false
  let mut audit_format = Markdown
  let mut stale_days = 180
  let mut fail_on_findings = false
  let mut export_format = Csv
  let mut output_path = ""
  let mut index = 1
  while index < user_args.length() {
    let arg = user_args[index]
    if arg == "--reveal" && (command == "show" || command == "export") {
      reveal = true
      index = index + 1
    } else if arg == "--format" && command == "audit" {
      if index + 1 >= user_args.length() {
        return Invalid("--format expects markdown or json")
      }
      let value = user_args[index + 1]
      if value == "markdown" {
        audit_format = Markdown
      } else if value == "json" {
        audit_format = Json
      } else {
        return Invalid("unknown audit format '" + value + "'")
      }
      index = index + 2
    } else if arg == "--format" && command == "export" {
      if index + 1 >= user_args.length() {
        return Invalid("--format expects csv or json")
      }
      let value = user_args[index + 1]
      if value == "csv" {
        export_format = Csv
      } else if value == "json" {
        export_format = Json
      } else {
        return Invalid("unknown export format '" + value + "'")
      }
      index = index + 2
    } else if arg == "--output" && command == "export" {
      if index + 1 >= user_args.length() {
        return Invalid("--output expects a file path")
      }
      output_path = user_args[index + 1]
      index = index + 2
    } else if arg == "--stale-days" && command == "audit" {
      if index + 1 >= user_args.length() {
        return Invalid("--stale-days expects a positive integer")
      }
      match parse_positive_int(user_args[index + 1]) {
        Some(value) => stale_days = value
        None => return Invalid("--stale-days expects a positive integer")
      }
      index = index + 2
    } else if arg == "--fail-on-findings" && command == "audit" {
      fail_on_findings = true
      index = index + 1
    } else if arg == "--help" || arg == "-h" {
      return Help
    } else if arg.has_prefix("-") {
      return Invalid("unknown option '" + arg + "'")
    } else {
      positional.push(arg)
      index = index + 1
    }
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
  } else if command == "audit" {
    if positional.length() != 1 {
      Invalid("audit expects exactly one database path")
    } else {
      Audit(positional[0], audit_format, stale_days, fail_on_findings)
    }
  } else if command == "export" {
    if positional.length() != 1 {
      Invalid("export expects exactly one database path")
    } else {
      Export(positional[0], export_format, reveal, output_path)
    }
  } else if positional.length() != 2 {
    Invalid("show expects a database path and an entry title or UUID")
  } else {
    Show(positional[0], positional[1], reveal)
  }
}

///|
fn parse_positive_int(text : String) -> Int? {
  if text == "" {
    return None
  }
  let mut value = 0
  for index = 0; index < text.length(); index = index + 1 {
    let digit = text[index].to_int() - 48
    if digit < 0 || digit > 9 {
      return None
    }
    value = value * 10 + digit
  }
  if value > 0 {
    Some(value)
  } else {
    None
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
    first == "audit" ||
    first == "export" ||
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
  println(
    "  audit <file>             report weak, reused, stale or expired entries",
  )
  println("  export <file>            export all entries as CSV or JSON")
  println("")
  println("Options:")
  println(
    "  --reveal                 reveal protected values in `show` / `export`",
  )
  println("  --format <markdown|json> audit output format (default: markdown)")
  println("  --stale-days <days>      stale threshold for audit (default: 180)")
  println("  --fail-on-findings       audit exits 1 when findings exist")
  println("  --format <csv|json>      export output format (default: csv)")
  println("  --output <path>          write export to a file instead of stdout")
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
fn print_audit(
  database : @lib.OpenedDatabase,
  format : AuditFormat,
  stale_days : Int,
) -> Bool {
  let now_day = (@env.now() / 86400000UL).reinterpret_as_int64()
  let report = @lib.audit_vault(database.vault(), now_day, stale_days)
  let text = match format {
    Markdown => report.render_markdown()
    Json => report.render_json()
  }
  print_text(text)
  report.has_findings()
}

///|
fn write_export(
  database : @lib.OpenedDatabase,
  format : ExportFormat,
  reveal : Bool,
  output_path : String,
) -> Bool {
  let text = match format {
    Csv => @lib.export_csv(database.vault(), reveal)
    Json => @lib.export_json(database.vault(), reveal)
  }
  if output_path == "" {
    print_text(text)
    true
  } else {
    @fs.write_string_to_file(output_path, text) catch {
      _ => {
        println("kdbx: cannot write export: " + output_path)
        return false
      }
    }
    true
  }
}

///|
fn print_text(text : String) -> Unit {
  if text.has_suffix("\n") {
    println(text[:text.length() - 1].to_owned())
  } else {
    println(text)
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
    Audit(path, format, stale_days, fail_on_findings) =>
      match open_or_exit(path) {
        Some(database) =>
          if print_audit(database, format, stale_days) && fail_on_findings {
            @sys.exit(1)
          }
        None => @sys.exit(1)
      }
    Export(path, format, reveal, output_path) =>
      match open_or_exit(path) {
        Some(database) =>
          if !write_export(database, format, reveal, output_path) {
            @sys.exit(1)
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
