///|
fn audit_fixture() -> Vault raise KdbxError {
  let xml = "<KeePassFile><Meta><Generator>audit test</Generator></Meta><Root><Group><Name>Root</Name>" +
    "<Entry><UUID>good</UUID><Times><LastModificationTime>2026-10-01T00:00:00Z</LastModificationTime><ExpiryTime>2030-01-01T00:00:00Z</ExpiryTime><Expires>False</Expires></Times><String><Key>Title</Key><Value>Good</Value></String><String><Key>UserName</Key><Value>alice</Value></String><String><Key>Password</Key><Value>Correct-Horse-2026!</Value></String></Entry>" +
    "<Entry><UUID>weak</UUID><Times><LastModificationTime>2026-10-01T00:00:00Z</LastModificationTime><Expires>False</Expires></Times><String><Key>Title</Key><Value>Weak</Value></String><String><Key>UserName</Key><Value>bob</Value></String><String><Key>Password</Key><Value>qwerty</Value></String></Entry>" +
    "<Entry><UUID>reuse-a</UUID><Times><LastModificationTime>2026-10-01T00:00:00Z</LastModificationTime><Expires>False</Expires></Times><String><Key>Title</Key><Value>Reuse A</Value></String><String><Key>Password</Key><Value>Shared-Strong-2026!</Value></String></Entry>" +
    "<Entry><UUID>reuse-b</UUID><Times><LastModificationTime>2026-10-01T00:00:00Z</LastModificationTime><Expires>False</Expires></Times><String><Key>Title</Key><Value>Reuse B</Value></String><String><Key>Password</Key><Value>Shared-Strong-2026!</Value></String></Entry>" +
    "<Entry><UUID>expired</UUID><Times><LastModificationTime>2026-10-01T00:00:00Z</LastModificationTime><ExpiryTime>2020-01-01T00:00:00Z</ExpiryTime><Expires>True</Expires></Times><String><Key>Title</Key><Value>Expired</Value></String><String><Key>Password</Key><Value>Expired-Unique-2026!</Value></String></Entry>" +
    "<Entry><UUID>stale</UUID><Times><LastModificationTime>2020-01-01T00:00:00Z</LastModificationTime><Expires>False</Expires></Times><String><Key>Title</Key><Value>Stale</Value></String><String><Key>Password</Key><Value>Stale-Unique-2026!</Value></String></Entry>" +
    "</Group></Root></KeePassFile>"
  parse_vault(xml)
}

///|
test "audit reports weak, reused, expired and stale passwords" {
  let now = parse_iso_date_days("2026-10-23T12:00:00Z").unwrap()
  let report = audit_vault(audit_fixture(), now, 180)
  assert_eq(report.entries_scanned(), 6)
  assert_eq(report.findings().length(), 5)
  assert_eq(report.issue_count(), 5)
  assert_eq(report.count("weak-password"), 1)
  assert_eq(report.count("reused-password"), 2)
  assert_eq(report.count("expired"), 1)
  assert_eq(report.count("stale"), 1)
  let markdown = report.render_markdown()
  assert_true(markdown.contains("weak-password"))
  assert_true(markdown.contains("matches a common password"))
  assert_true(
    markdown.contains("reused-password: password is shared by 2 entries"),
  )
  assert_true(markdown.contains("expired on 2020-01-01"))
  assert_true(markdown.contains("stale"))
  assert_true(!markdown.contains("qwerty"))
  assert_true(!markdown.contains("Shared-Strong-2026!"))
  let json = report.render_json()
  assert_true(json.contains("\"code\": \"reused-password\""))
  assert_true(json.contains("\"entries_scanned\": 6"))
  assert_true(!json.contains("qwerty"))
}

///|
test "audit returns no findings for a strong current vault" {
  let xml = "<KeePassFile><Meta/><Root><Group><Name>Root</Name><Entry><UUID>ok</UUID><Times><LastModificationTime>2026-10-01T00:00:00Z</LastModificationTime><Expires>False</Expires></Times><String><Key>Title</Key><Value>Mail</Value></String><String><Key>UserName</Key><Value>alice</Value></String><String><Key>Password</Key><Value>Strong-Unique-2026!</Value></String></Entry></Group></Root></KeePassFile>"
  let now = parse_iso_date_days("2026-10-23").unwrap()
  let report = audit_vault(parse_vault(xml), now, 180)
  assert_true(!report.has_findings())
  assert_eq(report.issue_count(), 0)
  assert_true(report.render_markdown().contains("No findings."))
}

///|
test "date parsing validates calendar dates" {
  assert_eq(parse_iso_date_days("1970-01-01T00:00:00Z"), Some(0))
  assert_eq(parse_iso_date_days("2000-02-29"), Some(11016))
  assert_eq(parse_iso_date_days("2026-02-29"), None)
  assert_eq(parse_iso_date_days("not-a-date"), None)
}
