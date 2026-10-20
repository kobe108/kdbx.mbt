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
}
