// Gives the binary the version it reports in "ssenc --version" and compares in "ssenc --update".
//
// The version comes only from the env var SSENC_VERSION: the release workflow
// (.github/workflows/test.yml, job build-matrix) sets it to the pushed tag, e.g. v1.2.3.
// Every other build is "dev", and a "dev" binary refuses to --update.
//
// The version of Cargo.toml is not used for it on purpose: it would have to be bumped by hand
// and kept equal to the tag. (ssenc::VERSION of the library is still the crate version.)
fn main() {
    println!("cargo:rerun-if-env-changed=SSENC_VERSION");

    let version = match std::env::var("SSENC_VERSION") {
        Ok(val) if !val.trim().is_empty() => val.trim().to_string(),
        _ => "dev".to_string(),
    };

    println!("cargo:rustc-env=SSENC_BUILD_VERSION={version}");
}
