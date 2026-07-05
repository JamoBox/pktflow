fn main() {
    // Windows CI has the Npcap SDK (import lib) but no runtime DLL.
    // Delay-loading keeps the binary loadable so subcommands that never
    // call libpcap (--help, snapshots) still run. Link args from the
    // capture crate's build script do not propagate to downstream
    // binaries, so this is repeated here.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-lib=delayimp");
    }
}
