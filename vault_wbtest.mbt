///|
/// The document model: groups, entries, fields and their protection flag.
test "the vault model reflects the document" {
  let vault = parse_vault(sample_document())
  assert_eq(vault.generator(), "KeePass")
  assert_eq(vault.groups().length(), 2)
  assert_eq(vault.entry_count(), 2)
  let groups = vault.groups()
  assert_eq(groups[0].name(), "Internet")
  assert_eq(groups[0].uuid(), "group-1")
  assert_eq(groups[0].entries().length(), 1)
  assert_eq(groups[0].groups().length(), 1)
  assert_eq(groups[0].groups()[0].name(), "Nested")
  let entry = groups[0].entries()[0]
  assert_eq(entry.uuid(), "entry-1")
  assert_eq(entry.field("Title"), Some("Example & Co AB"))
  assert_eq(entry.field("UserName"), None)
  // A protected value is reported as such rather than silently treated as
  // plain text: decrypting it needs the inner random stream (F10b).
  let fields = entry.fields()
  assert_eq(fields.length(), 2)
  assert_true(!fields[0].is_protected())
  assert_true(fields[1].is_protected())
  assert_eq(fields[1].value(), "c2VjcmV0")
  // Entries can be listed with the path of the group they live in.
  let listed = vault.entries()
  assert_eq(listed.length(), 2)
  assert_eq(listed[0].0, "Internet")
  assert_eq(listed[1].0, "Internet/Nested")
  assert_eq(listed[1].1.field("Title"), Some("Inner"))
}

///|
/// A payload that is not a KeePass document, or has no root, is refused rather
/// than producing an empty vault that looks like success.
test "documents that are not vaults are refused" {
  try parse_vault("<NotAVault/>") catch {
    Malformed(message) => assert_true(message.contains("KeePassFile"))
    e => fail("expected a root error, got: " + e.message())
  } noraise {
    _ => fail("expected a non-vault document to be refused")
  }
  try parse_vault("<KeePassFile><Meta/></KeePassFile>") catch {
    Malformed(message) => assert_true(message.contains("Root"))
    e => fail("expected a missing-root error, got: " + e.message())
  } noraise {
    _ => fail("expected a document without <Root> to be refused")
  }
}
