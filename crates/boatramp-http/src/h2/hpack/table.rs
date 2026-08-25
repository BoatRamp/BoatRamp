//! HPACK index address space (RFC 7541 §2.3, §4): the fixed static table
//! (Appendix A) plus the connection's dynamic table. Index 1..=61 addresses the
//! static table; index 62.. addresses the dynamic table, most-recently-inserted
//! first. Entry "size" is `name.len() + value.len() + 32` (§4.1).

use std::collections::VecDeque;

/// The RFC 7541 Appendix A static table, 1-indexed (entry `i` is `STATIC[i - 1]`).
/// Header names are already lowercase, as HTTP/2 requires (§8.1.2).
pub(super) const STATIC: [(&[u8], &[u8]); 61] = [
    (b":authority", b""),
    (b":method", b"GET"),
    (b":method", b"POST"),
    (b":path", b"/"),
    (b":path", b"/index.html"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"200"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"304"),
    (b":status", b"400"),
    (b":status", b"404"),
    (b":status", b"500"),
    (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"),
    (b"accept-language", b""),
    (b"accept-ranges", b""),
    (b"accept", b""),
    (b"access-control-allow-origin", b""),
    (b"age", b""),
    (b"allow", b""),
    (b"authorization", b""),
    (b"cache-control", b""),
    (b"content-disposition", b""),
    (b"content-encoding", b""),
    (b"content-language", b""),
    (b"content-length", b""),
    (b"content-location", b""),
    (b"content-range", b""),
    (b"content-type", b""),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"expect", b""),
    (b"expires", b""),
    (b"from", b""),
    (b"host", b""),
    (b"if-match", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"if-range", b""),
    (b"if-unmodified-since", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"max-forwards", b""),
    (b"proxy-authenticate", b""),
    (b"proxy-authorization", b""),
    (b"range", b""),
    (b"referer", b""),
    (b"refresh", b""),
    (b"retry-after", b""),
    (b"server", b""),
    (b"set-cookie", b""),
    (b"strict-transport-security", b""),
    (b"transfer-encoding", b""),
    (b"user-agent", b""),
    (b"vary", b""),
    (b"via", b""),
    (b"www-authenticate", b""),
];

/// Per-entry overhead added to `name.len() + value.len()` when accounting the
/// dynamic table's size (RFC 7541 §4.1).
const ENTRY_OVERHEAD: usize = 32;

/// The connection's dynamic table: a FIFO of recently-referenced `(name, value)`
/// entries bounded by a maximum octet size the decoder tracks across requests.
pub(super) struct DynamicTable {
    /// Newest at the front, oldest at the back — so dynamic index 62 (the first
    /// dynamic slot) is `entries[0]`.
    entries: VecDeque<(Vec<u8>, Vec<u8>)>,
    /// Current total size (sum of per-entry sizes).
    size: usize,
    /// The current maximum size, capped by the last accepted size update (§6.3),
    /// which itself may not exceed `hard_max` (`SETTINGS_HEADER_TABLE_SIZE`).
    max: usize,
    /// The protocol ceiling on `max` — our advertised `SETTINGS_HEADER_TABLE_SIZE`.
    hard_max: usize,
}

impl DynamicTable {
    pub(super) fn new(hard_max: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            size: 0,
            max: hard_max,
            hard_max,
        }
    }

    /// Look up a header by its HPACK index (1-based over static ∪ dynamic).
    /// `None` if the index is 0 or past the end of the dynamic table.
    pub(super) fn get(&self, index: usize) -> Option<(&[u8], &[u8])> {
        if index == 0 {
            return None;
        }
        if index <= STATIC.len() {
            let (n, v) = STATIC[index - 1];
            return Some((n, v));
        }
        self.entries
            .get(index - STATIC.len() - 1)
            .map(|(n, v)| (n.as_slice(), v.as_slice()))
    }

    /// Insert a new entry at the front, evicting oldest entries until it fits.
    /// An entry larger than `max` on its own evicts the whole table and is not
    /// stored (RFC 7541 §4.4) — legal, not an error.
    pub(super) fn insert(&mut self, name: &[u8], value: &[u8]) {
        let entry_size = name.len() + value.len() + ENTRY_OVERHEAD;
        while self.size + entry_size > self.max {
            match self.entries.pop_back() {
                Some((n, v)) => self.size -= n.len() + v.len() + ENTRY_OVERHEAD,
                None => break, // table empty; entry doesn't fit → not stored
            }
        }
        if entry_size <= self.max {
            self.entries.push_front((name.to_vec(), value.to_vec()));
            self.size += entry_size;
        }
    }

    /// Apply a dynamic-table size update (§6.3). The new size must not exceed the
    /// advertised `SETTINGS_HEADER_TABLE_SIZE`; the caller rejects over-limit
    /// updates before calling. Shrinking evicts oldest entries to fit.
    pub(super) fn set_max(&mut self, new_max: usize) -> bool {
        if new_max > self.hard_max {
            return false;
        }
        self.max = new_max;
        while self.size > self.max {
            match self.entries.pop_back() {
                Some((n, v)) => self.size -= n.len() + v.len() + ENTRY_OVERHEAD,
                None => break,
            }
        }
        true
    }
}
