//! Exercise packed pointer words independently of Mach-O traversal. Numeric format IDs and bit
//! positions mirror fixup-chains.h, so fixtures distinguish absolute, relative, and authenticated
//! encodings even when they resolve to the same unslid address.

use super::{Fixups, Pointer};
use crate::format::{write_u32, write_u64};

#[test]
fn chained_formats_preserve_exact_rebases_and_authentication_layouts() {
    let base = 0x1_0000_0000;
    // Formats 1/2 use absolute unauthenticated targets; 6/9/12 use image-relative targets.
    // ARM64E auth bit 63 switches all ARM64E variants to a low-32-bit image-relative target.
    for (format, word, expected) in [
        (2, base + 0x1234, base + 0x1234),
        (6, 0x1234, base + 0x1234),
        (1, base + 0x1234, base + 0x1234),
        (9, 0x1234, base + 0x1234),
        (12, 0x1234, base + 0x1234),
        (1, (1 << 63) | 0x1234, base + 0x1234),
        (9, (1 << 63) | 0x1234, base + 0x1234),
        (12, (1 << 63) | 0x1234, base + 0x1234),
    ] {
        let (pointer, next) = Fixups::decode(word, format, base, &[], 4096).unwrap();
        let Pointer::Address(address) = pointer else {
            panic!("expected rebase")
        };
        assert_eq!((address, next), (expected, 0));
    }
}

#[test]
fn chained_import_identity_requires_zero_addends_in_both_locations() {
    let name = b"___CFConstantStringClassReference\0";
    for import_format in [1, 2, 3] {
        for pointer_format in [1, 2, 6, 9, 12] {
            let arm64e = matches!(pointer_format, 1 | 9 | 12);
            for pointer_addend in [0, 1] {
                for import_addend in [0, 1] {
                    if import_format == 1 && import_addend != 0 {
                        continue;
                    }
                    // Header offsets +8/+12 select import and string tables. One import starts
                    // at +28; reserve the widest 16-byte format before the name pool at +44.
                    let mut blob = vec![0; 44];
                    write_u32(&mut blob, 8, 28);
                    write_u32(&mut blob, 12, 44);
                    write_u32(&mut blob, 16, 1);
                    write_u32(&mut blob, 20, import_format);
                    if import_format == 2 {
                        write_u32(&mut blob, 32, import_addend);
                    }
                    if import_format == 3 {
                        write_u64(&mut blob, 36, import_addend as u64);
                    }
                    blob.extend_from_slice(name);
                    // Ordinal zero selects that import. Bind and inline-addend bit positions
                    // differ between ARM64E and PTR_64; table and pointer addends are independent.
                    let word = (1 << if arm64e { 62 } else { 63 })
                        | (pointer_addend << if arm64e { 32 } else { 24 });
                    let (pointer, next) =
                        Fixups::decode(word, pointer_format, 0, &blob, 4096).unwrap();
                    let Pointer::Import {
                        name: actual,
                        exact,
                    } = pointer
                    else {
                        panic!("expected import")
                    };
                    assert_eq!(actual.as_bytes(), &name[..name.len() - 1]);
                    assert_eq!(exact, pointer_addend == 0 && import_addend == 0);
                    assert_eq!(next, 0);
                }
            }
        }
    }
}
