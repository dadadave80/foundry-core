use std::{env, path::PathBuf, process::Command};

const XCODE_HINT: &str = "the touch-id feature requires the Xcode command line tools";

/// Oldest Swift toolchain the shim is known to link with, kept honest by the
/// oldest-supported leg of the `touch-id-link` CI job. Swift 5.9
/// ships with Xcode / Command Line Tools 15.0.
const MIN_SWIFT: (u32, u32) = (5, 9);

fn main() {
    println!("cargo::rerun-if-changed=src/touch_id/shim.swift");
    println!("cargo::rerun-if-env-changed=SDKROOT");
    println!("cargo::rerun-if-env-changed=DEVELOPER_DIR");
    println!("cargo::rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");

    if env::var_os("CARGO_FEATURE_TOUCH_ID").is_none()
        || env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos")
    {
        return;
    }

    check_swift_version();

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    // Apple Silicon, plus Intel Macs whose T2 chip provides a Secure Enclave.
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "aarch64" => "arm64".to_string(),
        arch => arch.to_string(),
    };
    // Honor the standard deployment-target override, like the `cc` crate does.
    // CryptoKit's Secure Enclave and HKDF APIs need macOS 11; swiftc rejects
    // older values with clear availability errors.
    let deployment = env::var("MACOSX_DEPLOYMENT_TARGET").unwrap_or_else(|_| "11".to_string());

    let object = out_dir.join("foundry_se.o");
    run(Command::new("swiftc")
        .args(["-emit-object", "-parse-as-library", "-O"])
        .args(["-target", &format!("{arch}-apple-macos{deployment}")])
        .arg("src/touch_id/shim.swift")
        .arg("-o")
        .arg(&object));
    run(Command::new("ar").arg("crs").arg(out_dir.join("libfoundry_se.a")).arg(&object));

    println!("cargo::rustc-link-search=native={}", out_dir.display());
    println!("cargo::rustc-link-lib=static=foundry_se");
    // The Swift objects autolink their frameworks and runtime via LC_LINKER_OPTION;
    // the linker only needs search paths for the Swift runtime libraries.
    println!("cargo::rustc-link-search=native=/usr/lib/swift");
    let sdk = run_stdout(Command::new("xcrun").args(["--sdk", "macosx", "--show-sdk-path"]));
    let sdk = sdk.trim();
    println!("cargo::rustc-link-search=native={sdk}/usr/lib/swift");
    // Cargo reruns the script when a watched path disappears, self-healing after
    // Xcode updates that remove the versioned SDK directory.
    println!("cargo::rerun-if-changed={sdk}");
    // The toolchain resource dir holds the static libswiftCompatibility* archives
    // force-loaded when the deployment target predates the host Swift runtime.
    let info = run_stdout(Command::new("swiftc").arg("-print-target-info"));
    let info: serde_json::Value =
        serde_json::from_str(&info).expect("unparsable `swiftc -print-target-info` output");
    let path = info["paths"]["runtimeResourcePath"].as_str().expect(
        "`swiftc -print-target-info` reported no paths.runtimeResourcePath; \
         cannot locate the Swift compatibility archives",
    );
    println!("cargo::rustc-link-search=native={path}/macosx");
}

/// Rejects toolchains older than [`MIN_SWIFT`] before compiling anything,
/// turning an opaque failure inside Apple `ld` into an actionable error.
/// Gated on `swiftc` rather than `xcodebuild` because Command Line Tools-only
/// installs have no `xcodebuild`, and both toolchain flavors print
/// "Swift version X.Y".
fn check_swift_version() {
    let out = run_stdout(Command::new("swiftc").arg("--version"));
    let ver =
        out.split("Swift version ").nth(1).and_then(|s| s.split_whitespace().next()).unwrap_or("");
    assert!(
        !ver.is_empty(),
        "could not parse `swiftc --version` output ({}); {XCODE_HINT}",
        out.trim()
    );
    let mut parts = ver.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    let found = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    assert!(
        found >= MIN_SWIFT,
        "the touch-id feature requires Swift {}.{} or newer (Xcode/Command Line Tools \
         15.0 or newer); found Swift {ver}. Update Xcode, select a newer install \
         with `sudo xcode-select -s`, or build without `--features touch-id`",
        MIN_SWIFT.0,
        MIN_SWIFT.1,
    );
}

fn run(cmd: &mut Command) {
    let status =
        cmd.status().unwrap_or_else(|e| panic!("failed to spawn {cmd:?}: {e}; {XCODE_HINT}"));
    assert!(status.success(), "{cmd:?} failed with {status}");
}

fn run_stdout(cmd: &mut Command) -> String {
    let output =
        cmd.output().unwrap_or_else(|e| panic!("failed to spawn {cmd:?}: {e}; {XCODE_HINT}"));
    assert!(output.status.success(), "{cmd:?} failed with {}", output.status);
    String::from_utf8(output.stdout).unwrap_or_else(|e| panic!("{cmd:?} output not UTF-8: {e}"))
}
