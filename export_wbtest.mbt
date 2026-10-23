///|
fn export_fixture() -> Vault raise KdbxError {
  parse_vault(
    "<KeePassFile><Meta><Generator>export test</Generator></Meta><Root><Group><Name>Root</Name>" +
    "<Entry><UUID>one</UUID><String><Key>Title</Key><Value>Mail, primary</Value></String><String><Key>UserName</Key><Value>alice</Value></String><String><Key>Password</Key><Value>hunter2</Value></String><String><Key>PIN</Key><Value Protected='True'>c2VjcmV0</Value></String></Entry>" +
    "<Entry><UUID>two</UUID><String><Key>Title</Key><Value>Bank</Value></String><String><Key>Password</Key><Value>other-secret</Value></String><String><Key>URL</Key><Value>https://example.com</Value></String></Entry>" +
    "</Group></Root></KeePassFile>",
  )
}

///|
test "CSV export includes every field and redacts secrets by default" {
  let vault = export_fixture()
  let csv = export_csv(vault, false)
  assert_true(csv.has_prefix("Group,UUID,Title,UserName,Password,PIN,URL\n"))
  assert_true(csv.contains("\"Mail, primary\""))
  assert_true(csv.contains("<redacted>"))
  assert_true(!csv.contains("hunter2"))
  assert_true(!csv.contains("c2VjcmV0"))
  let revealed = export_csv(vault, true)
  assert_true(revealed.contains("hunter2"))
}

///|
test "JSON export preserves fields and masks secrets by default" {
  let vault = export_fixture()
  let json = export_json(vault, false)
  assert_true(json.contains("\"entry_count\": 2"))
  assert_true(json.contains("\"key\": \"PIN\""))
  assert_true(json.contains("\"protected\": true"))
  assert_true(json.contains("\"value\": \"<redacted>\""))
  assert_true(!json.contains("hunter2"))
  assert_true(!json.contains("c2VjcmV0"))
  let revealed = export_json(vault, true)
  assert_true(revealed.contains("hunter2"))
}
