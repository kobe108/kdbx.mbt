///|
test "cli parses commands and reveal flag" {
  match parse_cli(["info", "vault.kdbx"]) {
    Info(path) => assert_eq(path, "vault.kdbx")
    _ => fail("expected info command")
  }
  match parse_cli(["show", "vault.kdbx", "mail", "--reveal"]) {
    Show(path, query, reveal) => {
      assert_eq(path, "vault.kdbx")
      assert_eq(query, "mail")
      assert_true(reveal)
    }
    _ => fail("expected show command")
  }
  match parse_cli(["ls"]) {
    Invalid(message) => assert_true(message.contains("exactly one"))
    _ => fail("expected invalid ls command")
  }
  match parse_cli(["C:\\tools\\kdbx.exe", "info", "vault.kdbx"]) {
    Info(path) => assert_eq(path, "vault.kdbx")
    _ => fail("expected embedded program name to be ignored")
  }
  match
    parse_cli([
      "audit", "vault.kdbx", "--format", "json", "--stale-days", "90", "--fail-on-findings",
    ]) {
    Audit(path, Json, stale_days, fail_on_findings) => {
      assert_eq(path, "vault.kdbx")
      assert_eq(stale_days, 90)
      assert_true(fail_on_findings)
    }
    _ => fail("expected audit command")
  }
  match parse_cli(["audit", "vault.kdbx", "--stale-days", "0"]) {
    Invalid(message) => assert_true(message.contains("positive"))
    _ => fail("expected invalid stale threshold")
  }
  match
    parse_cli([
      "export", "vault.kdbx", "--format", "json", "--output", "vault.json", "--reveal",
    ]) {
    Export(path, Json, reveal, output) => {
      assert_eq(path, "vault.kdbx")
      assert_true(reveal)
      assert_eq(output, "vault.json")
    }
    _ => fail("expected export command")
  }
}
