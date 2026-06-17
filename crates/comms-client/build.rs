fn main() {
    // Emit Slint element debug-info so the headless UI test harness
    // (i-slint-backend-testing) can introspect elements by id / accessible-label / type and
    // synth-click them (the hit-target/interaction suite). Also powers accessibility tooling.
    println!("cargo:rerun-if-env-changed=SLINT_EMIT_DEBUG_INFO");
    std::env::set_var("SLINT_EMIT_DEBUG_INFO", "1");
    slint_build::compile("ui/app.slint").expect("compile ui/app.slint");
}
