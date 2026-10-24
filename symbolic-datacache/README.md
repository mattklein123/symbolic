# Symbolic Data Cache

A separate, portable raw data-symbol cache. It does not change crash SymCache, demangle names,
infer symbol sizes or allocation types, or perform nearest-preceding address lookup.

The default `builder` feature enables `DataCacheBuilder::from_macho` and `serialize`. Disable
default features for a reader without Mach-O dependencies. The `symbolic` facade exposes this
crate through its opt-in `datacache` feature.

## Borrowed Reader

```rust
use symbolic_datacache::{DataCache, ParseError, ReadLimits};

fn raw_name(bytes: &[u8], address: u64) -> Result<Option<&str>, ParseError> {
    let cache = DataCache::parse(bytes, ReadLimits::default())?;
    Ok(cache.lookup_exact(address).next().map(|symbol| symbol.name))
}
```

`parse` validates the whole uncompressed file once. `lookup_exact` binary-searches full-width
image-relative addresses, then returns every raw alias at that address in `O(log N + K)` work.
Zero and offsets above 4 GiB are valid. An interior or preceding address is not a match. Returned
names and section views borrow the immutable backing bytes; no strings, address map, or per-hit
vectors are allocated. Unaligned input is supported through explicit endian-aware byte reads.

Callers own the mapping/byte view and may retain it across conversions. A mapping must remain
alive and immutable while borrowed results exist. Download/decompress to a bounded local file,
validate before atomic installation, and reuse the uncompressed mapping. Compressed Zstd bytes
are not directly searchable. Source identity, authorization, cache eviction, and freshness are
caller responsibilities; a payload checksum is not an authorization or freshness guarantee.

## Builder Budgets

The builder requires a non-nil original Mach-O UUID and a supported object kind. The caller
supplies SHA-256 of the original slice. Names/addresses come from bounded section-aware extraction;
no second image-base subtraction or crash-PC adjustment occurs. Raw-entry and name-work budgets
include filtered entries. Names are bounded before scanning/UTF-8 decoding, not after allocation.

Defaults are 2,000,000 raw entries, 1,000,000 accepted records, 4,096 aliases per address before
duplicate removal, 16 KiB per name, 64 MiB examined name bytes, 32 MiB interned strings, 64 MiB
uncompressed file bytes, and 256 MiB accounted storage. Accepted-record counters retain exact
duplicates; searchable tables coalesce only identical address/section/name triples.

Storage accounting conservatively charges every reserved record-vector generation (covering
reallocation overlap), intern references, section references, the output, and a 64-KiB allowance
for at most 255 extraction sections plus sorting/header scratch. It excludes caller-owned source
bytes, allocator metadata, and RSS. This allowance means very small memory budgets can yield a
header-only memory-limit result even for an empty source. Budgets below the 256-byte terminal
header are invalid configuration. Reader limits are independent and must also accept any raised
writer limits. Allocation failure is terminal where recoverable; header allocation and output
I/O failures are typed build errors. Discard failed output destinations rather than publishing.

Complete empty, incomplete, and unsupported are distinct. Incomplete/unsupported files contain
no searchable tables or strings. Budget/source failures cannot silently hide conflicting aliases
inside an apparently complete prefix. Terminal reason and raw counters remain inspectable.

## Format Version 1

All integers are little-endian, without Rust layout/pointer dependence. Tables are eight-byte
aligned with zero padding; reserved fields are zero. No trailing bytes are permitted. UUID bytes
retain Mach-O order, not Windows GUID order. Architecture uses `symbolic_common::Arch`'s current
documented numeric discriminants. Unknown versions/enums are rejected, not guessed or salvaged.

| Header Byte Offset | Field |
| --- | --- |
| 0 | `SYMDATA` and NUL, 8 bytes |
| 8, 12 | Version `u32 = 1`, header size `u32 = 256` |
| 16 | Exact total file size `u64` |
| 24, 40 | UUID `[u8; 16]`, preferred load address `u64` |
| 48, 52 | Architecture `u32`, object kind `u32` (debug 1, executable 2, library 3) |
| 56, 60 | State `u32` (complete 0, incomplete 1, unsupported 2), reason `u32` |
| 64, 96 | Source-slice SHA-256, then SHA-256 of every byte after the header |
| 128, 144, 160, 176 | Four `(offset: u64, count: u64)` descriptors: addresses, records, sections, strings |
| 192, 200, 208 | Declared raw entries, inspected raw entries, accepted raw records: three `u64` counters |
| 216 | Forty reserved zero bytes |

Reason values are none 0, unsupported architecture 1, source error 2, raw-symbol limit 3,
record limit 4, alias limit 5, name-length limit 6, examined-name-bytes limit 7, string-pool
limit 8, file-size limit 9, and builder-memory limit 10. Complete requires none; unsupported
requires unsupported architecture; incomplete requires another nonzero reason.

The regions immediately follow in descriptor order (with alignment padding):

| Region | Entry Layout |
| --- | --- |
| Addresses, 16 bytes | `address: u64, first_record: u32, record_count: u32` |
| Records, 16 bytes | `section_row: u32, name_offset: u32, name_length: u32, reserved: u32` |
| Sections, 40 bytes | `address: u64, size: u64, ordinal: u32, flags: u32, segment_offset: u32, segment_length: u32, name_offset: u32, name_length: u32` |
| Strings, byte count | Interned UTF-8, lexicographically ordered at construction, no terminators |

Addresses are strictly increasing; each points to a contiguous, nonempty alias group. Within a
group, records sort by original section ordinal then raw name. Sections sort by their original
one-based ordinals, at most 255. String references are byte offsets relative to the pool, not
file offsets. Every record's address belongs to its section's checked half-open range. Sections
do not define individual symbol extents. The reader validates ordering, references, UTF-8
boundaries, all arithmetic, resource limits, completeness/counters, and checksum once.

Empty files contain only the 256-byte header with four `(256, 0)` descriptors and the empty-payload
SHA-256. Complete empty files have no accepted records; terminal files can retain accepted-raw
counts without exposing partial tables. The hand-specified golden fixture is
`tests/fixtures/v1.hex`; tests independently pin its field offsets, digest, and writer bytes.

## Verification

Run `cargo nextest run -p symbolic-datacache` and repeat with `--no-default-features` for reader
isolation. `cargo bench -p symbolic-datacache --bench datacache -- --noplot` measures build,
serialization, validation, fresh map/validation, warm hit/miss/alias lookup, and a linear-scan
reference at 100, 10,000, and 100,000 addresses. It prints serialized bytes and conservative
builder accounting. A fresh reader does not imply an OS-cold filesystem cache. Benchmark numbers
are local evidence, not correctness thresholds; deterministic tests bound binary-search comparisons.
