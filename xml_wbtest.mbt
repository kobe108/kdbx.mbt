///|
/// A small but complete KeePass document: a nested group tree, two entries, one
/// protected value and two entities.
fn sample_document() -> String {
  "<?xml version='1.0' encoding='utf-8'?>\n<KeePassFile>\n  <Meta>\n    <Generator>KeePass</Generator>\n  </Meta>\n  <Root>\n    <Group>\n      <UUID>group-1</UUID>\n      <Name>Internet</Name>\n      <Entry>\n        <UUID>entry-1</UUID>\n        <String>\n          <Key>Title</Key>\n          <Value>Example &amp; Co &#65;&#x42;</Value>\n        </String>\n        <String>\n          <Key>Password</Key>\n          <Value Protected='True'>c2VjcmV0</Value>\n        </String>\n      </Entry>\n      <Group>\n        <UUID>group-2</UUID>\n        <Name>Nested</Name>\n        <Entry>\n          <UUID>entry-2</UUID>\n          <String><Key>Title</Key><Value>Inner</Value></String>\n        </Entry>\n      </Group>\n    </Group>\n    <Group>\n      <UUID>group-3</UUID>\n      <Name>Bank</Name>\n    </Group>\n  </Root>\n</KeePassFile>\n"
}

///|
/// The reader handles the subset KeePass writes: prologue, comments, nesting,
/// attributes and entities, including numeric character references.
test "xml elements, attributes and entities" {
  let root = parse_xml(sample_document())
  assert_eq(root.name(), "KeePassFile")
  // `child_text` reads direct character data only: <Meta> holds an element, so
  // its own text is whitespace and trims to nothing.
  assert_eq(root.child_text("Meta"), "")
  let meta = root.child("Meta").unwrap()
  assert_eq(meta.child_text("Generator"), "KeePass")
  let root_element = root.child("Root").unwrap()
  let groups = root_element.children_named("Group")
  assert_eq(groups.length(), 2)
  let entry = groups[0].child("Entry").unwrap()
  let strings = entry.children_named("String")
  assert_eq(strings.length(), 2)
  // Entities, including the numeric forms, are decoded in text nodes.
  assert_eq(strings[0].child_text("Value"), "Example & Co AB")
  // Attribute values are decoded too, and quoting style does not matter.
  let value = strings[1].child("Value").unwrap()
  assert_eq(value.attribute("Protected"), Some("True"))
  assert_eq(value.text().trim().to_owned(), "c2VjcmV0")
  // Comments and the prologue are skipped, not treated as content.
  let with_comment = parse_xml("<!-- leading --><a><!-- inner --><b/></a>")
  assert_eq(with_comment.children().length(), 1)
  assert_eq(with_comment.children()[0].name(), "b")
}

///|
/// Malformed documents must be refused: a reader that guesses produces
/// plausible nonsense, which is the worst outcome for a security tool.
test "malformed xml is refused" {
  try parse_xml("<a><b></a>") catch {
    Malformed(message) => assert_true(message.contains("closes"))
    e => fail("expected a mismatch error, got: " + e.message())
  } noraise {
    _ => fail("expected mismatched tags to be refused")
  }
  try parse_xml("<a>") catch {
    Malformed(message) => assert_true(message.contains("never closed"))
    e => fail("expected an unclosed error, got: " + e.message())
  } noraise {
    _ => fail("expected an unclosed element to be refused")
  }
  try parse_xml("<a>&bogus;</a>") catch {
    Malformed(message) => assert_true(message.contains("unknown entity"))
    e => fail("expected an entity error, got: " + e.message())
  } noraise {
    _ => fail("expected an unknown entity to be refused")
  }
  try parse_xml("<a/>trailing") catch {
    Malformed(message) => assert_true(message.contains("trailing"))
    e => fail("expected a trailing-content error, got: " + e.message())
  } noraise {
    _ => fail("expected trailing content to be refused")
  }
  try parse_xml("<a b=c/>") catch {
    Malformed(message) => assert_true(message.contains("quoted"))
    e => fail("expected a quoting error, got: " + e.message())
  } noraise {
    _ => fail("expected an unquoted attribute to be refused")
  }
}
