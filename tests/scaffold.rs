#[test]
fn package_name_matches_repository() {
    assert_eq!(env!("CARGO_PKG_NAME"), "proton-mail-mac-mcp");
}
