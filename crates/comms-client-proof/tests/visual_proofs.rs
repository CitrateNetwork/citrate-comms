//! Visual proof harness (PoC) — render the real client UI headless via
//! `MinimalSoftwareWindow::take_snapshot()` and lock against committed golden PNGs.
//! Mirrors `citrate-boeing-shell`'s `*_proof` pattern.
//!
//! Regenerate goldens (then eyeball each against the design before committing):
//!   COMMS_REGEN_GOLDENS=1 cargo test -p comms-client-proof --test visual_proofs

use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Once;

use comms_client_proof::{
    AgentsProofWindow, AuditProofWindow, CommsProofWindow, CrmProofWindow, ForumProofWindow,
    MembersProofWindow, ProjectsProofWindow, ProofRoot, SecurityProofWindow, SettingsProofWindow,
};
use image::RgbaImage;
use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
use slint::platform::{Platform, PlatformError, WindowAdapter};
use slint::{ComponentHandle, PhysicalSize, Rgba8Pixel, SharedPixelBuffer};

const REGEN_ENV: &str = "COMMS_REGEN_GOLDENS";

thread_local! {
    static WINDOW: Rc<MinimalSoftwareWindow> =
        MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
}

struct TestPlatform;
impl Platform for TestPlatform {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
        Ok(WINDOW.with(|w| w.clone()))
    }
}

fn init_test_platform() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        slint::platform::set_platform(Box::new(TestPlatform)).expect("set test platform");
    });
}

fn goldens_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("goldens")
}

fn to_rgba(snap: &SharedPixelBuffer<Rgba8Pixel>) -> RgbaImage {
    let mut bytes = snap.as_bytes().to_vec();
    for px in bytes.chunks_exact_mut(4) {
        px[3] = 255; // opaque (the renderer leaves alpha; goldens are opaque)
    }
    RgbaImage::from_raw(snap.width(), snap.height(), bytes).expect("snapshot fits RgbaImage")
}

fn compare_or_save(label: &str, image: &RgbaImage) {
    let path = goldens_dir().join(format!("{label}.png"));
    let regen = std::env::var(REGEN_ENV).is_ok();
    if regen || !path.exists() {
        std::fs::create_dir_all(path.parent().unwrap()).expect("mkdir goldens");
        image.save(&path).expect("save golden");
        return;
    }
    let golden = image::open(&path).expect("open golden").to_rgba8();
    assert_eq!(image.dimensions(), golden.dimensions(), "{label}: dimension mismatch");
    let diffs = image.pixels().zip(golden.pixels()).filter(|(a, b)| a != b).count();
    assert_eq!(diffs, 0, "{label}: {diffs} pixel diffs (regen with {REGEN_ENV}=1 if intended)");
}

#[derive(Clone, Copy)]
struct Size {
    w: u32,
    h: u32,
}
const SIZES: [Size; 3] = [Size { w: 1280, h: 800 }, Size { w: 1440, h: 900 }, Size { w: 1920, h: 1080 }];

/// Render any proof window (they all expose `set_proof_width/height`) to an RgbaImage.
macro_rules! render_window {
    ($Win:ty, $size:expr) => {{
        let app = <$Win>::new().expect("proof window ::new");
        app.set_proof_width($size.w as f32);
        app.set_proof_height($size.h as f32);
        WINDOW.with(|w| w.set_size(PhysicalSize::new($size.w, $size.h)));
        to_rgba(&app.window().take_snapshot().expect("take_snapshot"))
    }};
}

/// Render the real screens (with their design-time fixtures) headless across the
/// responsiveness matrix → committed golden PNGs. ALL renders live in ONE test function:
/// the software platform hosts one window lifecycle per process, so separate
/// window-creating test fns would conflict (mirrors citrate-boeing-shell's single-lock).
#[test]
fn screen_goldens_across_sizes() {
    init_test_platform();
    for size in SIZES {
        let kit = render_window!(ProofRoot, size);
        // Sanity: non-blank.
        let first = kit.pixels().next().copied();
        assert!(kit.pixels().any(|p| Some(*p) != first), "render must not be flat");
        compare_or_save(&format!("kit_{}x{}", size.w, size.h), &kit);

        compare_or_save(&format!("comms_{}x{}", size.w, size.h), &render_window!(CommsProofWindow, size));
        compare_or_save(&format!("crm_{}x{}", size.w, size.h), &render_window!(CrmProofWindow, size));
        compare_or_save(&format!("settings_{}x{}", size.w, size.h), &render_window!(SettingsProofWindow, size));
        compare_or_save(&format!("projects_{}x{}", size.w, size.h), &render_window!(ProjectsProofWindow, size));
        compare_or_save(&format!("members_{}x{}", size.w, size.h), &render_window!(MembersProofWindow, size));
        compare_or_save(&format!("agents_{}x{}", size.w, size.h), &render_window!(AgentsProofWindow, size));
        compare_or_save(&format!("audit_{}x{}", size.w, size.h), &render_window!(AuditProofWindow, size));
        compare_or_save(&format!("security_{}x{}", size.w, size.h), &render_window!(SecurityProofWindow, size));
        compare_or_save(&format!("forum_{}x{}", size.w, size.h), &render_window!(ForumProofWindow, size));
    }

    // Full-content proofs: a tall window reveals everything the scroll now reaches, so a
    // golden documents that no card is lost (the "unreachable settings cards" regression).
    compare_or_save("settings_full_1440x1700", &render_window!(SettingsProofWindow, Size { w: 1440, h: 1700 }));
    compare_or_save("crm_full_1440x1500", &render_window!(CrmProofWindow, Size { w: 1440, h: 1500 }));

    // Narrow comms — the message rows must not overlap / clash when the thread column is
    // squeezed (the reported "sections crash into each other at different sizes" bug).
    compare_or_save("comms_narrow_1100x720", &render_window!(CommsProofWindow, Size { w: 1100, h: 720 }));
    compare_or_save("comms_narrow_980x680", &render_window!(CommsProofWindow, Size { w: 980, h: 680 }));

    // Full shell (title bar + rail + routed screen) — proves the header-relative layout
    // (the "content crashes past the header" report). force-shell renders the signed-in
    // shell without the live relay.
    let app_size = Size { w: 1440, h: 900 };
    compare_or_save("app_settings_1440x900", &render_app(comms_client_proof::AppWindow::new().expect("app"), "settings", app_size));
    compare_or_save("app_crm_1440x900", &render_app(comms_client_proof::AppWindow::new().expect("app"), "crm", app_size));
}

/// Render the full AppWindow at a route via force-shell (no live relay).
fn render_app(app: comms_client_proof::AppWindow, route: &str, size: Size) -> RgbaImage {
    use slint::ComponentHandle;
    app.set_force_shell(true);
    app.set_route(route.into());
    WINDOW.with(|w| w.set_size(PhysicalSize::new(size.w, size.h)));
    to_rgba(&app.window().take_snapshot().expect("app take_snapshot"))
}
