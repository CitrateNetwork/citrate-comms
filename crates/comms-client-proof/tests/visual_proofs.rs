//! Visual proof harness (PoC) — render the real client UI headless via
//! `MinimalSoftwareWindow::take_snapshot()` and lock against committed golden PNGs.
//! Mirrors `citrate-boeing-shell`'s `*_proof` pattern.
//!
//! Regenerate goldens (then eyeball each against the design before committing):
//!   COMMS_REGEN_GOLDENS=1 cargo test -p comms-client-proof --test visual_proofs

use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Once;

use comms_client_proof::ProofRoot;
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

fn render(size: Size) -> RgbaImage {
    init_test_platform();
    let app = ProofRoot::new().expect("ProofRoot::new");
    app.set_proof_width(size.w as f32);
    app.set_proof_height(size.h as f32);
    WINDOW.with(|w| w.set_size(PhysicalSize::new(size.w, size.h)));
    let snap = app.window().take_snapshot().expect("take_snapshot");
    to_rgba(&snap)
}

/// Pipeline proof: rendering the real brand UI headless across the responsiveness matrix
/// yields non-trivial images, each locked against a committed golden PNG. (One test
/// function — the software platform hosts one window lifecycle per process; per-screen
/// scaling is the COMMS-S5 rollout, mirroring citrate-boeing-shell's `*_proof` crates.)
#[test]
fn proof_root_goldens_across_sizes() {
    for (i, size) in SIZES.iter().enumerate() {
        let img = render(*size);
        assert_eq!(img.dimensions(), (size.w, size.h), "rendered at the requested size");
        if i == 0 {
            // Non-blank: the brand paper background + content produce real variation.
            let first = img.pixels().next().copied();
            assert!(img.pixels().any(|p| Some(*p) != first), "render must not be a flat color");
        }
        compare_or_save(&format!("proof_root_{}x{}", size.w, size.h), &img);
    }
}
