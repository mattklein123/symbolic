# Symbolic Data Cache

A separate, portable exact-address cache for raw section symbols and validated runtime metadata.
It does not change crash SymCache, demangle names, infer symbol sizes or allocation-instance types,
or perform nearest-preceding address lookup. Every record carries section or explicit selector-pool
provenance and a `RecordKind`; class data, class objects, metaclasses, ABI fields, Swift descriptors,
exact function/method context, selectors, and constant objects remain distinct.

The builder recovers rooted Objective-C and Swift metadata and strictly decoded constant objects
from little-endian 64-bit Mach-O images. Supported chained-pointer formats are 1, 2, 6, 9 and 12;
unsupported encodings skip metadata rather than treating encoded words as raw addresses. Imported
runtime-class identities require zero addends. Undefined synthetic method symbols are excluded.
An optional `AddressSpace` supplies matching shared-cache bytes and unanimous exact runtime symbols
only during ingestion. Recovered names are serialized into the index; lookup never needs that
context or a JSON metadata artifact. The original slice's UUID, digest and coordinates are retained.

Method lists support absolute entries, signed field-relative implementation offsets, unsigned
optimized selector-base offsets, and bounded tagged lists of lists. Class and instance methods
retain their distinct `+`/`-` identity. Constant integers require the exact runtime class and `q`/`Q`
encoding; constant dictionaries require their exact class and bounded readable key/value arrays.
Mixed-layout `__cfstring_CFN` sections are examined at pointer alignment, validating the complete
32-byte string object rather than truncating the section or accepting partial tails.

Supported shared-cache selector hashes are version 0. Only exact, pointer-aligned table members
inside this image's declared `__OBJC_RO` pool are emitted, matching pointer-valued heap-census
addresses without indexing unaligned strings or their interiors. Table occupancy is checked before
emission. Slot traversal is bounded by the smaller of 4,194,304 and the next power of two of the
configured raw-entry budget. Emitted names/records still consume the ordinary shared budgets.

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
image-relative addresses, then returns every typed alias at that address in `O(log N + K)` work.
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
include filtered entries. Raw, imported and recovered names share an examined-byte budget.
Names are bounded before scanning/UTF-8 decoding, not after allocation.

Defaults are 2,000,000 raw entries, 1,000,000 accepted records, 4,096 aliases per address before
duplicate removal, 16 KiB per name, 64 MiB examined name bytes, 32 MiB interned strings, 64 MiB
uncompressed file bytes, and 256 MiB accounted storage. Accepted-record counters retain exact
duplicates; searchable tables coalesce only identical address/section/name/kind tuples. Raw counters
exclude derived metadata records.

Storage accounting conservatively charges every reserved record-vector generation (covering
reallocation overlap), intern references, section references, the output, and a 64-KiB allowance
for at most 255 extraction sections and one selector pool plus sorting/header scratch. It excludes
caller-owned source bytes, allocator metadata, and RSS. This allowance means very small memory budgets can yield a
header-only memory-limit result even for an empty source. Budgets below the 256-byte terminal
header are invalid configuration. Reader limits are independent and must also accept any raised
writer limits. Allocation failure is terminal where recoverable; header allocation and output
I/O failures are typed build errors. Discard failed output destinations rather than publishing.

Complete empty, incomplete, and unsupported are distinct. Incomplete/unsupported files contain
no searchable tables or strings. Budget/source failures cannot silently hide conflicting aliases
inside an apparently complete prefix. Terminal reason and raw counters remain inspectable.

## Format Versions 1 and 2

Raw data-only indexes retain the version-1 encoding. An index containing typed records uses version
2 with the same header and table widths. Version 1 requires the record's final word to be zero;
version 2 stores `RecordKind` there. Readers accept both and reject unknown kinds. The portable
format version is independent of any caller's storage-key namespace.

All integers are little-endian, without Rust layout/pointer dependence. Tables are eight-byte
aligned with zero padding; reserved fields are zero. No trailing bytes are permitted. UUID bytes
retain Mach-O order, not Windows GUID order. Architecture uses `symbolic_common::Arch`'s current
documented numeric discriminants. Unknown versions/enums are rejected, not guessed or salvaged.

| Header Byte Offset | Field |
| --- | --- |
| 0 | `SYMDATA` and NUL, 8 bytes |
| 8, 12 | Version `u32 = 1` or `2`, header size `u32 = 256` |
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
| Records, 16 bytes | `section_row: u32, name_offset: u32, name_length: u32, kind: u32` |
| Sections, 40 bytes | `address: u64, size: u64, ordinal: u32, flags: u32, segment_offset: u32, segment_length: u32, name_offset: u32, name_length: u32` |
| Strings, byte count | Interned UTF-8, lexicographically ordered at construction, no terminators |

Addresses are strictly increasing; each points to a contiguous, nonempty alias group. Within a
group, records sort by original section ordinal, name, then kind. Sections sort by their original
one-based ordinals, at most 255, plus an optional version-2 row with reserved ordinal zero for the
declared selector pool. That row uses segment `__OBJC_RO`, name `__selectors`, and flags zero; only
aligned `Selector` records may reference it. It is not a fabricated Mach-O section. String references
are byte offsets relative to the string pool, not file offsets. Every record's address belongs to its
provenance row's checked half-open range. Sections
do not define individual symbol extents. The reader validates ordering, references, UTF-8
boundaries, all arithmetic, resource limits, completeness/counters, and checksum once.

Empty files contain only the 256-byte header with four `(256, 0)` descriptors and the empty-payload
SHA-256. Complete empty files have no accepted records; terminal files can retain accepted-raw
counts without exposing partial tables. The hand-specified golden fixture is
`tests/fixtures/v1.hex`; tests independently pin its field offsets, digest, and writer bytes.

Kind codes are symbol 0; class data 1; class object 2; metaclass data 3; metaclass object 4;
their respective fields 5 through 8; function 9; constant string 10; constant-string field 11;
ivar list 12; ivar entry 13; protocol list 14; protocol 15; protocol field 16; Swift type descriptor
17; Swift type-descriptor field 18; method implementation 19; method-entry field 20; selector 21;
constant integer 22; integer field 23; constant dictionary 24; dictionary field 25.
These describe the addressed artifact, not heap-instance
types. Callers must preserve genuine alias conflicts rather than choosing an attractive name.

## Verification

Run `cargo nextest run -p symbolic-datacache` and repeat with `--no-default-features` for reader
isolation. `cargo bench -p symbolic-datacache --bench datacache -- --noplot` measures build,
serialization, validation, fresh map/validation, warm hit/miss/alias lookup, and a linear-scan
reference at 100, 10,000, and 100,000 addresses. It prints serialized bytes and conservative
builder accounting. A fresh reader does not imply an OS-cold filesystem cache. Benchmark numbers
are local evidence, not correctness thresholds; deterministic tests bound binary-search comparisons.
