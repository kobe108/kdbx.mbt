// kdbx.mbt — MoonBit toolkit for KeePass KDBX databases.
// See docs/DESIGN.md for the scope and the milestone plan.
// See docs/SETUP.md for the environment and identity setup.
//
// To add a dependency, run this command in your terminal (requires `git`):
//   moon add moonbitlang/x
// or declare it manually:
// import {
//   "moonbitlang/x@0.5.5",
// }

name = "kobe108/kdbx"

version = "0.1.0"

readme = "README.md"

// Repository and module share a single identity: kobe108.

repository = "https://github.com/kobe108/kdbx.mbt"

license = "Apache-2.0"

keywords = [ "keepass", "kdbx", "password-manager", "security", "audit" ]

preferred_target = "native"

description = "Read, inspect and audit KeePass KDBX databases with MoonBit: a pure container layer with no third-party crypto required."

import {
  "moonbitlang/x@0.5.5",
}
