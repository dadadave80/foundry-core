use std::{env, path::PathBuf, process::Command};

const XCODE_HINT: &str = "the touch-id feature requires the Xcode command line tools";

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
