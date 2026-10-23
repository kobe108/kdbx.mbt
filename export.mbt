///|
/// Deterministic CSV and JSON export for readable vault entries.
///
/// Exports preserve the group path, UUID and every entry field. Password and
/// protected values are redacted unless the caller explicitly opts in.

///|
/// Exports all entries as CSV. The column order is the first-seen field order,
/// so repeated runs over the same vault are byte-for-byte stable.
pub fn export_csv(vault : Vault, include_secrets : Bool) -> String {
  let entries = vault.entries()
  let columns : Array[String] = []
  for item in entries {
    let entry = item.1
    for field in entry.fields() {
      if !array_contains(columns, field.key()) {
        columns.push(field.key())
      }
    }
  }
  let out = StringBuilder()
  out.write_string(csv_cell("Group"))
  out.write_string(",")
  out.write_string(csv_cell("UUID"))
  for column in columns {
    out.write_string(",")
    out.write_string(csv_cell(column))
  }
  out.write_string("\n")
  for item in entries {
    let (path, entry) = item
    out.write_string(csv_cell(path))
    out.write_string(",")
    out.write_string(csv_cell(entry.uuid()))
    for column in columns {
      out.write_string(",")
      let value = match entry.field(column) {
        Some(value) => export_value(column, value, entry, include_secrets)
        None => ""
      }
      out.write_string(csv_cell(value))
    }
    out.write_string("\n")
  }
  out.to_string()
}

///|
/// Exports the same entries as JSON, preserving field order and protection
/// markers. Secret values are replaced before serialization when disabled.
pub fn export_json(vault : Vault, include_secrets : Bool) -> String {
  let entries = vault.entries()
  let out = StringBuilder()
  out.write_string("{\n")
  out.write_string(
    "  \"generator\": \"" + escape_json_string(vault.generator()) + "\",\n",
  )
  out.write_string("  \"entry_count\": " + entries.length().to_string() + ",\n")
  out.write_string("  \"entries\": [")
  if entries.length() > 0 {
    out.write_string("\n")
  }
  let mut index = 0
  while index < entries.length() {
    let (path, entry) = entries[index]
    out.write_string("    {\n")
    out.write_string("      \"group\": \"" + escape_json_string(path) + "\",\n")
    out.write_string(
      "      \"uuid\": \"" + escape_json_string(entry.uuid()) + "\",\n",
    )
    out.write_string("      \"fields\": [")
    let fields = entry.fields()
    if fields.length() > 0 {
      out.write_string("\n")
    }
    let mut field_index = 0
    while field_index < fields.length() {
      let field = fields[field_index]
      out.write_string(
        "        {\"key\": \"" + escape_json_string(field.key()) + "\", ",
      )
      out.write_string("\"value\": \"")
      out.write_string(
        escape_json_string(
          redacted_value(field.key(), field.value(), field, include_secrets),
        ),
      )
      out.write_string("\", \"protected\": ")
      out.write_string(field.is_protected().to_string())
      out.write_string("}")
      if field_index + 1 < fields.length() {
        out.write_string(",")
      }
      out.write_string("\n")
      field_index = field_index + 1
    }
    out.write_string("      ]\n")
    out.write_string("    }")
    if index + 1 < entries.length() {
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
fn export_value(
  key : String,
  value : String,
  entry : VaultEntry,
  include_secrets : Bool,
) -> String {
  let mut is_protected = false
  for field in entry.fields() {
    if field.key() == key && field.is_protected() {
      is_protected = true
    }
  }
  if (key == "Password" || is_protected) && !include_secrets {
    "<redacted>"
  } else {
    value
  }
}

///|
fn redacted_value(
  key : String,
  value : String,
  field : VaultField,
  include_secrets : Bool,
) -> String {
  if (key == "Password" || field.is_protected()) && !include_secrets {
    "<redacted>"
  } else {
    value
  }
}

///|
fn array_contains(items : Array[String], wanted : String) -> Bool {
  for item in items {
    if item == wanted {
      return true
    }
  }
  false
}

///|
fn csv_cell(text : String) -> String {
  if text.contains(",") ||
    text.contains("\"") ||
    text.contains("\r") ||
    text.contains("\n") {
    "\"" + text.replace_all(old="\"", new="\"\"") + "\""
  } else {
    text
  }
}

///|
fn escape_json_string(text : String) -> String {
  text
  .replace_all(old="\\", new="\\\\")
  .replace_all(old="\"", new="\\\"")
  .replace_all(old="\r", new="\\r")
  .replace_all(old="\n", new="\\n")
  .replace_all(old="\t", new="\\t")
}
