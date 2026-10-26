# SecretHive — working agreement for agents and humans

## Rules

- **English everywhere**: identifiers, comments, commit messages, docs.
- **No value in a log, an output line, an argument, an audit payload or a test fixture.** A value lives in a
  `SecretValue` and leaves it only through `Reveal()`. `NoValueLeavesTests` lists the files that may call it and the
  one file that may touch the console; changing that list is a decision, not a fix for a failing test.
- **Tests use generated values only**, spelt `generated-…`, so a leak shows up as that word in the output.
- **Nothing organisation-specific in this repo**: no hostnames, stack names, paths or secret names from a real
  host. Examples use the stack `shop`.
- **No vendor or product names** of other secret managers or password managers. One exception (owner,
  2026-10-21): the read endpoint that answers the 1Password Connect API (`OnePasswordConnectEndpoints.cs`), named
  as such in its code and docs because a tool can only be pointed at it by that name.
- **A refusal happens before the first write.** Everything that can fail a render is checked for every target
  first; a half-rendered directory is the failure this tool exists to prevent.
- **Nothing temporary inside a target directory**, ever. Applications read every file in it at startup.
- **Commit messages** in the imperative, one change per commit, no trailers, no `Co-Authored-By`.
- **Stage explicit paths.** Never `git add -A` or `git add .`.

## Toolchain

- .NET 10 SDK (see `global.json`), nullable and implicit usings on, warnings are errors.
- xUnit v3 on Microsoft.Testing.Platform; `dotnet test` from the root.
- The Linux-only tests (`UnixHostFilesTests`) need root. Run them in the SDK container before claiming anything
  about ownership, modes or atomicity; on Windows they are skipped, and a skipped test proves nothing.

## Layout

```
src/SecretHive.Domain/          the rules of the model: names, fields, limits. No references.
src/SecretHive.Application/     use cases and ports. References Domain only.
src/SecretHive.Infrastructure/  adapters: the key ring (envelope encryption), later persistence.
src/SecretHive.Cli/   the secrethive command: Hosting (profile, manifest), Bundles (sealed copy),
                      Rendering (files on a host), Commands
tests/                unit tests; a fake host for the rules, the real filesystem for the Linux behaviour
tests/browser/        the pages in headless Chrome over the DevTools protocol, no npm: `node tests/browser/smoke.mjs
                      <base url> <token file>`; CI runs it against the image and fails on any CSP report
```
