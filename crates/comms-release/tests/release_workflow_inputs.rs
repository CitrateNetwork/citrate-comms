//! Pins for `.github/workflows/release.yml`:
//!
//! 1. no `run:` line interpolates a `workflow_dispatch` input with `${{ ... }}` (the input
//!    reaches the shell through `env:` only);
//! 2. the "resolve tag" step accepts only a `vX.Y.Z[-suffix]` tag before it writes the tag
//!    to `$GITHUB_OUTPUT` (later `run:` lines and the release name interpolate that output,
//!    and a newline in it would add forged step outputs);
//! 3. every `uses:` is pinned to a full commit SHA.
//!
//! Each scanner has a negative control on a synthetic workflow, so a scanner that
//! cannot fail is caught too. The resolve-tag script is executed with bash, with
//! `GITHUB_OUTPUT` pointed at a temp file; nothing else on the host is written.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn release_yml() -> String {
    std::fs::read_to_string(repo_root().join(".github/workflows/release.yml"))
        .expect("read .github/workflows/release.yml")
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Every line that belongs to a `run:` value, as (1-based line number, text).
fn run_lines(src: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let t = line.trim_start().trim_start_matches("- ");
        if let Some(rest) = t.strip_prefix("run:") {
            let key_indent = indent(line);
            let rest = rest.trim();
            if rest.starts_with('|') || rest.starts_with('>') {
                i += 1;
                while i < lines.len() && (lines[i].trim().is_empty() || indent(lines[i]) > key_indent) {
                    out.push((i + 1, lines[i].to_string()));
                    i += 1;
                }
                continue;
            }
            out.push((i + 1, line.to_string()));
        }
        i += 1;
    }
    out
}

/// `run:` lines that interpolate a dispatch input directly into the shell.
fn input_interpolations(src: &str) -> Vec<String> {
    run_lines(src)
        .into_iter()
        .filter(|(_, l)| {
            l.split("${{").skip(1).any(|expr| {
                let expr = expr.split("}}").next().unwrap_or("");
                expr.contains("github.event.inputs") || expr.contains("inputs.")
            })
        })
        .map(|(n, l)| format!("{n}: {}", l.trim()))
        .collect()
}

/// `uses:` references that are not pinned to a 40-hex commit SHA (local `./` actions excepted).
fn unpinned_uses(src: &str) -> Vec<String> {
    src.lines()
        .enumerate()
        .filter_map(|(n, line)| {
            let t = line.trim_start().trim_start_matches("- ").trim_start();
            let r = t.strip_prefix("uses:")?.trim();
            let r = r.split_whitespace().next().unwrap_or("");
            if r.starts_with("./") {
                return None;
            }
            let pinned = r
                .rsplit_once('@')
                .map(|(_, v)| v.len() == 40 && v.chars().all(|c| c.is_ascii_hexdigit()))
                .unwrap_or(false);
            (!pinned).then(|| format!("{}: {r}", n + 1))
        })
        .collect()
}

/// The shell body of the step named `name` (the lines of its `run: |` block, dedented).
fn step_script(src: &str, name: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.trim_start().trim_start_matches("- ").trim() == format!("name: {name}"))
        .unwrap_or_else(|| panic!("no step named {name:?} in release.yml"));
    let step_indent = indent(lines[start]);
    let mut i = start + 1;
    while i < lines.len() {
        let l = lines[i];
        if !l.trim().is_empty() && indent(l) <= step_indent && l.trim_start().starts_with("- ") {
            break;
        }
        if l.trim_start().starts_with("run:") {
            let key_indent = indent(l);
            let mut body = Vec::new();
            i += 1;
            while i < lines.len() && (lines[i].trim().is_empty() || indent(lines[i]) > key_indent) {
                body.push(lines[i]);
                i += 1;
            }
            let pad = body.iter().filter(|b| !b.trim().is_empty()).map(|b| indent(b)).min().unwrap_or(0);
            return body.iter().map(|b| if b.len() >= pad { &b[pad..] } else { "" }).collect::<Vec<_>>().join("\n");
        }
        i += 1;
    }
    panic!("step {name:?} has no run: block");
}

/// Run the resolve-tag script with the given dispatch input; returns (exit ok, GITHUB_OUTPUT contents).
fn resolve_tag(script: &str, tag_input: &str) -> (bool, String) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = tmp.path().join("github_output");
    std::fs::write(&out, "").unwrap();
    let status = Command::new("bash")
        .arg("-e")
        .arg("-c")
        .arg(script)
        .current_dir(repo_root())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", tmp.path())
        .env("TAG_INPUT", tag_input)
        .env("GITHUB_REF", "refs/heads/main")
        .env("GITHUB_OUTPUT", &out)
        .status()
        .expect("run bash");
    (status.success(), std::fs::read_to_string(&out).unwrap_or_default())
}

#[test]
fn no_run_line_interpolates_a_dispatch_input() {
    let bad = input_interpolations(&release_yml());
    assert!(bad.is_empty(), "dispatch input interpolated into a shell line:\n{}", bad.join("\n"));
}

#[test]
fn input_scanner_negative_control() {
    let wf = "jobs:\n  r:\n    steps:\n      - name: a\n        run: |\n          echo ok\n          TAG=${{ github.event.inputs.tag }}\n      - run: echo ${{ inputs.tag }}\n      - name: b\n        env:\n          T: ${{ github.event.inputs.tag }}\n        run: echo \"$T\"\n";
    let bad = input_interpolations(wf);
    assert_eq!(bad.len(), 2, "scanner must flag both run-line interpolations and not the env: one: {bad:?}");
}

#[test]
fn every_action_is_pinned_to_a_commit_sha() {
    let bad = unpinned_uses(&release_yml());
    assert!(bad.is_empty(), "actions not pinned to a commit SHA:\n{}", bad.join("\n"));
}

#[test]
fn pin_scanner_negative_control() {
    let wf = "steps:\n  - uses: actions/checkout@v4\n  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4\n  - uses: ./local\n  - name: x\n    uses: softprops/action-gh-release@v2\n";
    assert_eq!(unpinned_uses(wf).len(), 2);
}

#[test]
fn resolve_tag_accepts_version_tags() {
    let script = step_script(&release_yml(), "resolve tag");
    for tag in ["v0.1.0", "v1.2.3-rc.1", "v10.20.30-beta"] {
        let (ok, out) = resolve_tag(&script, tag);
        assert!(ok, "a version tag {tag:?} must be accepted");
        assert!(out.lines().any(|l| l == format!("tag={tag}")), "tag output for {tag:?}: {out:?}");
    }
}

#[test]
fn resolve_tag_refuses_a_tag_that_is_not_a_version_before_writing_outputs() {
    let script = step_script(&release_yml(), "resolve tag");
    for tag in [
        "v1.0.0\ngated_sha256=00",
        "v1.0.0$(id)",
        "v1.0.0;true",
        "v1.0.0 x",
        "main",
        "1.0.0",
    ] {
        let (ok, out) = resolve_tag(&script, tag);
        assert!(!ok, "a non-version tag {tag:?} must fail the step");
        assert!(
            !out.lines().any(|l| l.starts_with("tag=") || l.starts_with("gated_sha256=")),
            "nothing may be written to GITHUB_OUTPUT for {tag:?}: {out:?}"
        );
    }
}
