///|
/// The database model: what a KDBX payload means once the XML is parsed.
///
/// Only the parts needed to read a vault are modelled — groups, entries, string
/// fields and their protection flag — rather than the whole KeePass schema.

///|
/// One string field of an entry.
pub struct VaultField {
  key : String
  value : String
  /// True when the value was protected by the inner random stream. The flag is
  /// preserved after decryption so reports can redact sensitive fields.
  is_encrypted : Bool
}

///|
pub fn VaultField::key(self : VaultField) -> String {
  self.key
}

///|
pub fn VaultField::value(self : VaultField) -> String {
  self.value
}

///|
pub fn VaultField::is_protected(self : VaultField) -> Bool {
  self.is_encrypted
}

///|
pub struct VaultEntry {
  uuid : String
  fields : Array[VaultField]
}

///|
pub fn VaultEntry::uuid(self : VaultEntry) -> String {
  self.uuid
}

///|
pub fn VaultEntry::fields(self : VaultEntry) -> Array[VaultField] {
  self.fields.copy()
}

///|
/// Looks up a field by key, for example "Title" or "UserName".
pub fn VaultEntry::field(self : VaultEntry, key : String) -> String? {
  let mut found : String? = None
  let mut i = 0
  while i < self.fields.length() && found is None {
    if self.fields[i].key == key {
      found = Some(self.fields[i].value)
    }
    i = i + 1
  }
  found
}

///|
pub struct VaultGroup {
  name : String
  uuid : String
  groups : Array[VaultGroup]
  entries : Array[VaultEntry]
}

///|
pub fn VaultGroup::name(self : VaultGroup) -> String {
  self.name
}

///|
pub fn VaultGroup::uuid(self : VaultGroup) -> String {
  self.uuid
}

///|
pub fn VaultGroup::groups(self : VaultGroup) -> Array[VaultGroup] {
  self.groups.copy()
}

///|
pub fn VaultGroup::entries(self : VaultGroup) -> Array[VaultEntry] {
  self.entries.copy()
}

///|
pub struct Vault {
  groups : Array[VaultGroup]
  generator : String
}

///|
pub fn Vault::groups(self : Vault) -> Array[VaultGroup] {
  self.groups.copy()
}

///|
/// Name of the program that wrote the file, as recorded in `<Meta>`.
pub fn Vault::generator(self : Vault) -> String {
  self.generator
}

///|
/// Builds the model from the XML document of a payload.
pub fn parse_vault(xml : String) -> Vault raise KdbxError {
  let root = parse_xml(xml)
  if root.name() != "KeePassFile" {
    raise Malformed(
      "payload root element is <" + root.name() + ">, expected <KeePassFile>",
    )
  }
  let generator = match root.child("Meta") {
    Some(meta) => meta.child_text("Generator")
    None => ""
  }
  let groups : Array[VaultGroup] = []
  match root.child("Root") {
    Some(root_element) =>
      for element in root_element.children_named("Group") {
        groups.push(parse_group(element))
      }
    None => raise Malformed("payload has no <Root> element")
  }
  { groups, generator, }
}

///|
/// Number of entries in the whole vault, including nested groups.
pub fn Vault::entry_count(self : Vault) -> Int {
  let mut total = 0
  for group in self.groups {
    total = total + count_entries(group)
  }
  total
}

///|
/// Number of groups in the whole vault, including nested groups.
pub fn Vault::group_count(self : Vault) -> Int {
  let mut total = 0
  for group in self.groups {
    total = total + count_groups(group)
  }
  total
}

///|
fn count_groups(group : VaultGroup) -> Int {
  let mut total = 1
  for child in group.groups {
    total = total + count_groups(child)
  }
  total
}

///|
fn count_entries(group : VaultGroup) -> Int {
  let mut total = group.entries.length()
  for child in group.groups {
    total = total + count_entries(child)
  }
  total
}

///|
/// Every entry in the vault, depth first, with the path of the group it lives in.
pub fn Vault::entries(self : Vault) -> Array[(String, VaultEntry)] {
  let out : Array[(String, VaultEntry)] = []
  for group in self.groups {
    collect_entries(group, "", out)
  }
  out
}

///|
/// Finds one entry by exact UUID or exact title, returning its group path.
///
/// UUIDs are the unambiguous lookup key. Titles are accepted as a convenience,
/// and the first document-order match wins when titles are duplicated.
pub fn Vault::find_entry(self : Vault, query : String) -> (String, VaultEntry)? {
  let all = self.entries()
  let mut found : (String, VaultEntry)? = None
  let mut index = 0
  while index < all.length() && found is None {
    let (path, entry) = all[index]
    let title_matches = match entry.field("Title") {
      Some(title) => title == query
      None => false
    }
    if entry.uuid() == query || title_matches {
      found = Some((path, entry))
    }
    index = index + 1
  }
  found
}

///|
fn collect_entries(
  group : VaultGroup,
  prefix : String,
  out : Array[(String, VaultEntry)],
) -> Unit {
  let path = if prefix == "" { group.name } else { prefix + "/" + group.name }
  for entry in group.entries {
    out.push((path, entry))
  }
  for child in group.groups {
    collect_entries(child, path, out)
  }
}

///|
fn parse_group(element : XmlElement) -> VaultGroup {
  let groups : Array[VaultGroup] = []
  for child in element.children_named("Group") {
    groups.push(parse_group(child))
  }
  let entries : Array[VaultEntry] = []
  for child in element.children_named("Entry") {
    entries.push(parse_entry(child))
  }
  {
    name: element.child_text("Name"),
    uuid: element.child_text("UUID"),
    groups,
    entries,
  }
}

///|
fn parse_entry(element : XmlElement) -> VaultEntry {
  let fields : Array[VaultField] = []
  for child in element.children_named("String") {
    let is_encrypted = match child.child("Value") {
      Some(value) =>
        match value.attribute("Protected") {
          Some(flag) => flag == "True"
          None => false
        }
      None => false
    }
    fields.push({
      key: child.child_text("Key"),
      value: child.child_text("Value"),
      is_encrypted,
    })
  }
  { uuid: element.child_text("UUID"), fields, }
}
