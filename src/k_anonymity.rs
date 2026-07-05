//! k anonymity.

use alloc::vec::Vec;

// K-Anonymity
// ---------------------------------------------------------------------------

/// k-匿名性チェック: 各等価クラスのレコード数がk以上か
#[must_use]
pub fn check_k_anonymity(groups: &[usize], k: usize) -> bool {
    groups.iter().all(|&count| count >= k)
}

/// 等価クラスサイズの計算 (quasi-identifier hash → count)
#[must_use]
pub fn compute_equivalence_classes(quasi_ids: &[u64]) -> Vec<usize> {
    let mut sorted = quasi_ids.to_vec();
    sorted.sort_unstable();
    let mut classes = Vec::new();
    if sorted.is_empty() {
        return classes;
    }
    let mut count = 1usize;
    for i in 1..sorted.len() {
        if sorted[i] == sorted[i - 1] {
            count += 1;
        } else {
            classes.push(count);
            count = 1;
        }
    }
    classes.push(count);
    classes
}
