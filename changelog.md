# Release Notes

Each release has its own `## vX.Y.Z` section. The release workflow copies the section matching the pushed tag to the top of the GitHub release page (`scripts/release_notes.sh`), so add the section before running `tag.sh` (`xx publish`). To see the page before releasing: `xx "release notes preview" vX.Y.Z`.

A release is the Rust `ssenc` binary (`ssenc-darwin-arm64`, `ssenc-linux-x64`, `ssenc-linux-arm64`) and `SHA256SUMS.txt`. The TypeScript and Bash implementations are used from the repository.

## v0.1.0

First release of the Rust `ssenc` binary.

- **`ssenc encrypt` / `decrypt` / `rekey` / `inspect`**: format `ssenc1`, see [examples/SUMMARY.md](https://github.com/stopsopa/encrypt/blob/main/examples/SUMMARY.md) and [SPEC.md](https://github.com/stopsopa/encrypt/blob/main/SPEC.md).
- **`ssenc --update [tag|--check]`**: the binary replaces itself with the latest (or the given) release. The download is verified against `SHA256SUMS.txt` and executed before anything is replaced; after any failure the installed file is what it was. `SSENC_RELEASES` (URL or local directory) replaces the place releases are taken from, `SSENC_CONFIRM=false` skips the question.
- **`ssenc --version`**: prints `ssenc rust <tag>`, the tag of the release (`ssenc rust dev` for a local build).
