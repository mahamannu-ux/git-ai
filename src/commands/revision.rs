/// Normalize a user-typed lowercase `head` revision to the current worktree's
/// `HEAD`. Suffixes are preserved; branch names such as `header` are not.
pub(crate) fn normalize_head_rev(rev: &str) -> String {
    if rev
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("head"))
    {
        let suffix = &rev[4..];
        if suffix.is_empty()
            || suffix.starts_with('~')
            || suffix.starts_with('^')
            || suffix.starts_with('@')
        {
            return format!("HEAD{suffix}");
        }
    }
    rev.to_string()
}
