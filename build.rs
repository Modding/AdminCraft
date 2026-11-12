// Puts the AdminCraft icon into the Windows executable. When no resource compiler is available
// the program is built without it (and only the window icon, set at run time, shows the logo).
fn main() {
    println!("cargo:rerun-if-changed=assets/admincraft.rc");
    println!("cargo:rerun-if-changed=assets/admincraft.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        if let Err(e) = embed_resource::compile("assets/admincraft.rc", embed_resource::NONE).manifest_optional() {
            println!("cargo:warning=program icon not embedded: {e}");
        }
    }
}
