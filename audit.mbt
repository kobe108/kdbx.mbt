///|
/// Deterministic password-vault audit rules and report rendering.
///
/// Auditing is kept outside the file parser: the rules consume the readable
/// vault model, never the encrypted bytes, and never include password values in
/// reports. `now_day` is supplied by the caller so tests do not depend on the
/// machine clock.

///|
/// One finding attached to a vault entry.
pub enum AuditIssue {
  WeakPassword(String)
  ReusedPassword(Int)
  Expired(String)
  Stale(Int)
}

///|
/// Stable machine-readable issue identifier used by JSON output and CI gates.
pub fn AuditIssue::code(self : AuditIssue) -> String {
  match self {
    WeakPassword(_) => "weak-password"
    ReusedPassword(_) => "reused-password"
    Expired(_) => "expired"
    Stale(_) => "stale"
  }
}

///|
/// Human-readable explanation that never contains the password itself.
pub fn AuditIssue::message(self : AuditIssue) -> String {
  match self {
    WeakPassword(reasons) => reasons
    ReusedPassword(count) =>
      "password is shared by " + count.to_string() + " entries"
    Expired(date) => "entry expired on " + date
    Stale(days) => "last modified " + days.to_string() + " days ago"
  }
}

///|
/// Findings for one entry, with its location and non-secret identifying fields.
pub struct AuditEntry {
  path : String
  uuid : String
  title : String
  issues : Array[AuditIssue]
}

///|
pub fn AuditEntry::path(self : AuditEntry) -> String {
  self.path
}

///|
pub fn AuditEntry::uuid(self : AuditEntry) -> String {
  self.uuid
}

///|
pub fn AuditEntry::title(self : AuditEntry) -> String {
  self.title
}

///|
pub fn AuditEntry::issues(self : AuditEntry) -> Array[AuditIssue] {
  self.issues.copy()
}

///|
/// Complete audit result in document order.
pub struct AuditReport {
  entries_scanned : Int
  stale_days : Int
  findings : Array[AuditEntry]
}

///|
pub fn AuditReport::entries_scanned(self : AuditReport) -> Int {
  self.entries_scanned
}

///|
pub fn AuditReport::stale_days(self : AuditReport) -> Int {
  self.stale_days
}

///|
pub fn AuditReport::findings(self : AuditReport) -> Array[AuditEntry] {
  self.findings.copy()
}

///|
/// Total number of issues across all entries.
pub fn AuditReport::issue_count(self : AuditReport) -> Int {
  let mut total = 0
  for finding in self.findings {
    total = total + finding.issues.length()
  }
  total
}

///|
/// Number of issues with the given stable code.
pub fn AuditReport::count(self : AuditReport, code : String) -> Int {
  let mut total = 0
  for finding in self.findings {
    for issue in finding.issues {
      if issue.code() == code {
        total = total + 1
      }
    }
  }
  total
}

///|
pub fn AuditReport::has_findings(self : AuditReport) -> Bool {
  self.findings.length() > 0
}

///|
/// Audits a vault against four independent rules: weak, reused, expired and
/// stale passwords. `now_day` is days since the Unix epoch.
pub fn audit_vault(
  vault : Vault,
  now_day : Int64,
  stale_days : Int,
) -> AuditReport {
  let threshold = if stale_days < 1 { 180 } else { stale_days }
  let entries = vault.entries()
  let findings : Array[AuditEntry] = []
  let mut index = 0
  while index < entries.length() {
    let (path, entry) = entries[index]
    let title = entry.field("Title").unwrap_or("")
    let user_name = entry.field("UserName").unwrap_or("")
    let password = entry.field("Password").unwrap_or("")
    let issues : Array[AuditIssue] = []
    let weak_reasons = weak_password_reasons(password, title, user_name)
    if weak_reasons.length() > 0 {
      issues.push(WeakPassword(join_strings(weak_reasons, "; ")))
    }
    if password != "" {
      let reused = password_reuse_count(entries, password)
      if reused > 1 {
        issues.push(ReusedPassword(reused))
      }
    }
    if entry.expires() {
      match entry.expiry_time() {
        Some(text) =>
          match parse_iso_date_days(text) {
            Some(expiry_day) =>
              if expiry_day <= now_day {
                issues.push(Expired(date_prefix(text)))
              }
            None => ()
          }
        None => ()
      }
    }
    match entry.last_modified() {
      Some(text) =>
        match parse_iso_date_days(text) {
          Some(modified_day) =>
            if now_day - modified_day > threshold.to_int64() {
              issues.push(Stale((now_day - modified_day).to_int()))
            }
          None => ()
        }
      None => ()
    }
    if issues.length() > 0 {
      findings.push({ path, uuid: entry.uuid(), title, issues, })
    }
    index = index + 1
  }
  { entries_scanned: entries.length(), stale_days: threshold, findings, }
}

///|
/// Renders a Markdown report suitable for a pull request or weekly review.
pub fn AuditReport::render_markdown(self : AuditReport) -> String {
  let out = StringBuilder()
  out.write_string("# KDBX audit report\n\n")
  out.write_string(
    "- Entries scanned: " + self.entries_scanned.to_string() + "\n",
  )
  out.write_string(
    "- Entries with findings: " + self.findings.length().to_string() + "\n",
  )
  out.write_string("- Total issues: " + self.issue_count().to_string() + "\n")
  out.write_string(
    "- Stale threshold: " + self.stale_days.to_string() + " days\n\n",
  )
  if self.findings.length() == 0 {
    out.write_string("No findings.\n")
    return out.to_string()
  }
  out.write_string("| Group | Title | UUID | Issues |\n")
  out.write_string("| --- | --- | --- | --- |\n")
  for finding in self.findings {
    let messages : Array[String] = []
    for issue in finding.issues {
      messages.push(issue.code() + ": " + issue.message())
    }
    out.write_string(
      "| " +
      markdown_cell(finding.path) +
      " | " +
      markdown_cell(finding.title) +
      " | " +
      markdown_cell(finding.uuid) +
      " | " +
      markdown_cell(join_strings(messages, "<br>")) +
      " |\n",
    )
  }
  out.to_string()
}

///|
/// Renders the same result as deterministic JSON for automation and CI gates.
pub fn AuditReport::render_json(self : AuditReport) -> String {
  let out = StringBuilder()
  out.write_string("{\n")
  out.write_string(
    "  \"entries_scanned\": " + self.entries_scanned.to_string() + ",\n",
  )
  out.write_string(
    "  \"entries_with_findings\": " + self.findings.length().to_string() + ",\n",
  )
  out.write_string(
    "  \"issue_count\": " + self.issue_count().to_string() + ",\n",
  )
  out.write_string("  \"stale_days\": " + self.stale_days.to_string() + ",\n")
  out.write_string("  \"findings\": [")
  if self.findings.length() > 0 {
    out.write_string("\n")
  }
  let mut index = 0
  while index < self.findings.length() {
    let finding = self.findings[index]
    out.write_string("    {\n")
    out.write_string(
      "      \"group\": \"" + json_escape(finding.path) + "\",\n",
    )
    out.write_string(
      "      \"title\": \"" + json_escape(finding.title) + "\",\n",
    )
    out.write_string("      \"uuid\": \"" + json_escape(finding.uuid) + "\",\n")
    out.write_string("      \"issues\": [\n")
    let mut issue_index = 0
    while issue_index < finding.issues.length() {
      let issue = finding.issues[issue_index]
      out.write_string(
        "        {\"code\": \"" +
        json_escape(issue.code()) +
        "\", \"message\": \"" +
        json_escape(issue.message()) +
        "\"}",
      )
      if issue_index + 1 < finding.issues.length() {
        out.write_string(",")
      }
      out.write_string("\n")
      issue_index = issue_index + 1
    }
    out.write_string("      ]\n")
    out.write_string("    }")
    if index + 1 < self.findings.length() {
      out.write_string(",")
    }
    out.write_string("\n")
    index = index + 1
  }
  out.write_string("  ]\n")
  out.write_string("}\n")
  out.to_string()
}

///|
fn password_reuse_count(
  entries : Array[(String, VaultEntry)],
  password : String,
) -> Int {
  let mut count = 0
  for item in entries {
    let entry = item.1
    if entry.field("Password").unwrap_or("") == password {
      count = count + 1
    }
  }
  count
}

///|
fn weak_password_reasons(
  password : String,
  title : String,
  user_name : String,
) -> Array[String] {
  let reasons : Array[String] = []
  if password == "" {
    reasons.push("password is empty")
    return reasons
  }
  if password.length() < 12 {
    reasons.push("shorter than 12 characters")
  }
  if character_class_count(password) < 3 {
    reasons.push("uses fewer than 3 character classes")
  }
  let lower = password.to_lower()
  if lower == "password" ||
    lower == "password1" ||
    lower == "123456" ||
    lower == "12345678" ||
    lower == "qwerty" ||
    lower == "letmein" ||
    lower == "admin" ||
    lower == "welcome" {
    reasons.push("matches a common password")
  }
  if title != "" && lower == title.to_lower() {
    reasons.push("matches the entry title")
  }
  if user_name != "" && lower == user_name.to_lower() {
    reasons.push("matches the user name")
  }
  if password.length() > 1 && all_same_character(password) {
    reasons.push("uses one repeated character")
  }
  reasons
}

///|
fn character_class_count(password : String) -> Int {
  let mut lower = false
  let mut upper = false
  let mut digit = false
  let mut symbol = false
  for i = 0; i < password.length(); i = i + 1 {
    let code = password[i].to_int()
    if code >= 97 && code <= 122 {
      lower = true
    } else if code >= 65 && code <= 90 {
      upper = true
    } else if code >= 48 && code <= 57 {
      digit = true
    } else {
      symbol = true
    }
  }
  lower.to_int() + upper.to_int() + digit.to_int() + symbol.to_int()
}

///|
fn all_same_character(password : String) -> Bool {
  let first = password[0]
  let mut index = 1
  while index < password.length() {
    if password[index] != first {
      return false
    }
    index = index + 1
  }
  true
}

///|
fn join_strings(items : Array[String], separator : String) -> String {
  let out = StringBuilder()
  for index = 0; index < items.length(); index = index + 1 {
    if index > 0 {
      out.write_string(separator)
    }
    out.write_string(items[index])
  }
  out.to_string()
}

///|
fn markdown_cell(text : String) -> String {
  text
  .replace_all(old="\\", new="\\\\")
  .replace_all(old="|", new="\\|")
  .replace_all(old="\r", new=" ")
  .replace_all(old="\n", new=" ")
}

///|
fn json_escape(text : String) -> String {
  text
  .replace_all(old="\\", new="\\\\")
  .replace_all(old="\"", new="\\\"")
  .replace_all(old="\r", new="\\r")
  .replace_all(old="\n", new="\\n")
  .replace_all(old="\t", new="\\t")
}

///|
fn date_prefix(text : String) -> String {
  if text.length() >= 10 {
    text[:10].to_owned()
  } else {
    text
  }
}

///|
/// Parses the leading `YYYY-MM-DD` part of a KeePass ISO-8601 timestamp.
pub fn parse_iso_date_days(text : String) -> Int64? {
  if text.length() < 10 || text[4] != '-' || text[7] != '-' {
    return None
  }
  let year = match parse_digits(text, 0, 4) {
    Some(value) => value
    None => return None
  }
  let month = match parse_digits(text, 5, 2) {
    Some(value) => value
    None => return None
  }
  let day = match parse_digits(text, 8, 2) {
    Some(value) => value
    None => return None
  }
  if month < 1 || month > 12 || day < 1 || day > days_in_month(year, month) {
    return None
  }
  Some(days_from_civil(year, month, day))
}

///|
fn parse_digits(text : String, start : Int, count : Int) -> Int? {
  if start < 0 || start + count > text.length() {
    return None
  }
  let mut value = 0
  for index = start; index < start + count; index = index + 1 {
    let digit = text[index].to_int() - 48
    if digit < 0 || digit > 9 {
      return None
    }
    value = value * 10 + digit
  }
  Some(value)
}

///|
fn days_in_month(year : Int, month : Int) -> Int {
  if month == 2 {
    if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
      29
    } else {
      28
    }
  } else if month == 4 || month == 6 || month == 9 || month == 11 {
    30
  } else {
    31
  }
}

///|
/// Converts a proleptic Gregorian date to days since 1970-01-01.
fn days_from_civil(year : Int, month : Int, day : Int) -> Int64 {
  let adjusted_year = if month <= 2 { year - 1 } else { year }
  let era = adjusted_year / 400
  let year_of_era = adjusted_year - era * 400
  let shifted_month = if month > 2 { month - 3 } else { month + 9 }
  let day_of_year = (153 * shifted_month + 2) / 5 + day - 1
  let day_of_era = year_of_era * 365 +
    year_of_era / 4 -
    year_of_era / 100 +
    day_of_year
  (era * 146097 + day_of_era - 719468).to_int64()
}
