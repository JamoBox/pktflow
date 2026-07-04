fn main() {
    // Windows: delay-load wpcap.dll so binaries (and CI test runners on
    // machines with only the Npcap SDK, no runtime) can start without the
    // DLL present. The DLL is resolved on the first pcap call instead.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-lib=delayimp");
    }
}
