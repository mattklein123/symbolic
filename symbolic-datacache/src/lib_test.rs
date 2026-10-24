use crate::{DataCache, ParseError, ReadLimits};

pub(crate) fn golden() -> Vec<u8> {
    let hex: String = include_str!("../tests/fixtures/v1.hex")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .flat_map(str::split_whitespace)
        .collect();
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

pub(crate) fn repair(bytes: &mut [u8]) {
    let digest = crate::format::digest(&bytes[256..]);
    bytes[96..128].copy_from_slice(&digest);
}

pub(crate) fn set32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn set64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn independent_cache(addresses: &[u64], aliases: usize) -> Vec<u8> {
    let count = addresses.len() * aliases;
    let records = 256 + addresses.len() * 16;
    let sections = records + count * 16;
    let pool = sections + 40;
    let mut strings = String::from("__DATA__data");
    for alias in 0..aliases {
        strings.push('_');
        strings.push(char::from(b'a' + alias as u8));
    }
    let mut bytes = golden();
    bytes.resize(pool + strings.len(), 0);
    bytes[256..].fill(0);
    let size = bytes.len() as u64;
    set64(&mut bytes, 16, size);
    for (index, (offset, count)) in [
        (256, addresses.len()),
        (records, count),
        (sections, 1),
        (pool, strings.len()),
    ]
    .into_iter()
    .enumerate()
    {
        set64(&mut bytes, 128 + index * 16, offset as u64);
        set64(&mut bytes, 136 + index * 16, count as u64);
    }
    for offset in [192, 200, 208] {
        set64(&mut bytes, offset, count as u64);
    }
    for (index, address) in addresses.iter().enumerate() {
        set64(&mut bytes, 256 + index * 16, *address);
        set32(&mut bytes, 264 + index * 16, (index * aliases) as u32);
        set32(&mut bytes, 268 + index * 16, aliases as u32);
        for alias in 0..aliases {
            let row = records + (index * aliases + alias) * 16;
            set32(&mut bytes, row + 4, (12 + alias * 2) as u32);
            set32(&mut bytes, row + 8, 2);
        }
    }
    set64(&mut bytes, sections + 8, u64::MAX);
    set32(&mut bytes, sections + 16, 1);
    set32(&mut bytes, sections + 28, 6);
    set32(&mut bytes, sections + 32, 6);
    set32(&mut bytes, sections + 36, 6);
    bytes[pool..].copy_from_slice(strings.as_bytes());
    repair(&mut bytes);
    bytes
}

#[test]
fn rejects_short_and_wrong_magic_files() {
    assert_eq!(
        DataCache::parse(&[], ReadLimits::default()).unwrap_err(),
        ParseError::Header
    );
    assert_eq!(
        DataCache::parse(&[0; 256], ReadLimits::default()).unwrap_err(),
        ParseError::Header
    );
}

#[cfg(feature = "builder")]
#[test]
fn builds_existing_redistributable_dsym() {
    use symbolic_common::ByteView;
    use symbolic_debuginfo::macho::MachObject;
    use symbolic_testutils::fixture;

    use crate::{BuildLimits, DataCacheBuilder, State};

    let bytes = ByteView::open(fixture("macos/crash.dSYM/Contents/Resources/DWARF/crash")).unwrap();
    let object = MachObject::parse(&bytes).unwrap();
    let built = DataCacheBuilder::from_macho(
        &object,
        crate::format::digest(&bytes),
        BuildLimits::default(),
    )
    .unwrap();
    let cache = DataCache::parse(built.as_bytes(), ReadLimits::default()).unwrap();
    assert_eq!(cache.state(), State::Complete);
    for record in object.data_symbols().unwrap() {
        let record = record.unwrap();
        assert!(cache
            .lookup_exact(record.address)
            .any(|candidate| candidate.name == record.name
                && candidate.section.macho_ordinal == u32::from(record.section.index)));
    }
}
