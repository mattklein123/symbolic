//! Describe constant CF/NS string objects only after proving their runtime class identity.
//!
//! A 32-byte object in a known constant-string section is not sufficient evidence by itself: its isa
//! must name an approved class, either through an exact chained import or unambiguous cache aliases.
//! Strict encoding/length checks keep arbitrary bytes out of labels; character storage is not itself
//! labeled as an object, and the quoted display is distinct from a runtime type association.

use super::fixups::Pointer;
use super::Image;
use crate::{Reason, RecordKind};

/// Exact linker/runtime spellings, not a substring test for anything containing "ConstantString".
fn constant_class(name: &str) -> bool {
    matches!(
        name,
        "__NSConstantStringClassReference"
            | "___CFConstantStringClassReference"
            | "_OBJC_CLASS_$_NSConstantString"
            | "_OBJC_CLASS_$_NSCFConstantString"
            | "_OBJC_CLASS_$___NSCFConstantString"
    )
}

impl Image<'_, '_> {
    /// The 64-bit constant-string ABI is four words: isa, flags, character pointer, and unit count.
    /// Decode from section roots rather than searching for flags or readable text elsewhere.
    pub(super) fn constant_strings(&mut self) -> Result<(), Reason> {
        let roots = self
            .roots(&["__cfstring"], 32)
            .into_iter()
            .map(|(start, count)| (start, count, 32))
            .chain(
                self.roots(&["__cfstring_CFN"], 8)
                    .into_iter()
                    .map(|(start, count)| (start, count, 8)),
            );
        for (start, count, stride) in roots {
            for index in 0..count {
                self.step()?;
                let address = start + index * stride;
                if self.section(address, 32).is_none() {
                    continue;
                }
                // A bind with addends may point inside an object, so it cannot establish isa.
                // For resolved pointers, every exact alias must agree with the approved identity.
                let known =
                    match self.fixups.get(address) {
                        Some(Pointer::Import { name, exact }) => *exact && constant_class(name),
                        _ => self.pointer(address).zip(self.context).is_some_and(
                            |(pointer, context)| context.symbols_match(pointer, constant_class),
                        ),
                    };
                if !known {
                    continue;
                }
                let Some((flags, length, characters)) = self
                    .pointer(address + 8)
                    .zip(self.pointer(address + 24))
                    .zip(self.pointer(address + 16))
                    .map(|((flags, length), characters)| (flags, length, characters))
                else {
                    continue;
                };
                // These supported constant-object flags select 8-bit UTF-8 bytes (0x7c8) or
                // UTF-16LE code units (0x7d0). Length counts units, not decoded Unicode scalars.
                if !matches!(flags, 0x7c8 | 0x7d0) || length > 4096 {
                    continue;
                }
                let width = if flags == 0x7d0 { 2 } else { 1 };
                self.charge_name_bytes(length as usize * width)?;
                let Some(bytes) = self.read(characters, length as usize * width) else {
                    continue;
                };
                // Reserve conservatively for decoding scratch plus escaped/abbreviated display.
                // Invalid UTF-8 or unpaired UTF-16 surrogates reject the candidate, not replace bytes.
                self.storage.charge(length as usize * 8 + 2048)?;
                let value = if width == 2 {
                    let units: Vec<_> = bytes
                        .chunks_exact(2)
                        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                        .collect();
                    let Ok(value) = String::from_utf16(&units) else {
                        continue;
                    };
                    value
                } else {
                    let Ok(value) = std::str::from_utf8(bytes) else {
                        continue;
                    };
                    value.to_owned()
                };
                // Bound display by Unicode scalars; Rust's quoted Debug form escapes controls and
                // keeps literal text visually separate from owner/type labels.
                let abbreviated: String = value.chars().take(240).collect();
                let name = format!("{abbreviated:?}");
                self.add(address, RecordKind::ConstantString, &name, None)?;
                for (delta, field) in [(8, "flags"), (16, "characters"), (24, "length")] {
                    self.add(
                        address + delta,
                        RecordKind::ConstantStringField,
                        &name,
                        Some(field),
                    )?;
                }
            }
        }
        Ok(())
    }
}
