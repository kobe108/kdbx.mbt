# Project Agents.md Guide

This is a [MoonBit](https://docs.moonbitlang.com) project.

## Project structure

- The library package is at the repository root (`moon.pkg` in the root directory).
- The command line tool lives in `cmd/kdbx` and only parses arguments and prints.
- `docs/DESIGN.md` is the source of truth for scope, milestones and the
  specification references used by the code.

## Coding conventions

- MoonBit code is organised in blocks separated by `///|`; block order is
  irrelevant, so refactors can be done block by block.
- Every public item carries a doc comment that says why it exists, not only what
  it does.
- Parsing code proves the input length before reading (`ByteReader::need`) and
  fails with a narrow `KdbxError` variant instead of panicking.
- Constants taken from the KDBX specification keep the byte sequence they have
  in the specification, in a comment next to their definition.

## Tooling

- `moon fmt` formats the code; `moon check` type checks.
- `moon test` runs the test suite; `moon test --update` refreshes snapshots.
- `moon info` updates the generated `.mbti` interface; review the diff of the
  `.mbti` file to see whether a refactor changed the public API.
- `moon coverage analyze > uncovered.log` lists code that tests do not reach.
