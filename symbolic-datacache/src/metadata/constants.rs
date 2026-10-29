//! Constant-object ABIs require both declared section roots and exact runtime-class identities.

use super::fixups::Pointer;
use super::Image;
use crate::{Reason, RecordKind};

fn integer_class(name: &str) -> bool {
    name == "_OBJC_CLASS_$_NSConstantIntegerNumber"
}

fn dictionary_class(name: &str) -> bool {
    name == "_OBJC_CLASS_$_NSConstantDictionary"
}

impl Image<'_, '_> {
    fn constant_identity(&self, address: u64, matches: fn(&str) -> bool) -> bool {
        match self.fixups.get(address) {
            Some(Pointer::Import { name, exact }) => *exact && matches(name),
            _ => self
                .pointer(address)
                .zip(self.context)
                .is_some_and(|(isa, context)| context.symbols_match(isa, matches)),
        }
    }

    pub(super) fn constant_objects(&mut self) -> Result<(), Reason> {
        for (start, count) in self.roots(&["__objc_intobj"], 24) {
            for index in 0..count {
                self.step()?;
                let address = start + index * 24;
                if !self.constant_identity(address, integer_class) {
                    continue;
                }
                let Some(encoding) = self
                    .pointer(address + 8)
                    .and_then(|pointer| self.name(pointer))
                else {
                    continue;
                };
                let Some(bytes) = self.read(address + 16, 8) else {
                    continue;
                };
                let bits = u64::from_le_bytes(bytes.try_into().map_err(|_| Reason::SourceError)?);
                let name = match encoding {
                    "q" => (bits as i64).to_string(),
                    "Q" => bits.to_string(),
                    _ => continue,
                };
                self.add(address, RecordKind::ConstantInteger, &name, None)?;
                for (delta, field) in [(8, "encoding"), (16, "value")] {
                    self.add(
                        address + delta,
                        RecordKind::ConstantIntegerField,
                        &name,
                        Some(field),
                    )?;
                }
            }
        }
        for (start, count) in self.roots(&["__objc_dictobj"], 40) {
            for index in 0..count {
                self.step()?;
                let address = start + index * 40;
                if !self.constant_identity(address, dictionary_class) {
                    continue;
                }
                let Some(count) = self.pointer(address + 16).filter(|count| *count <= 4096) else {
                    continue;
                };
                if ![24, 32].into_iter().all(|delta| {
                    self.pointer(address + delta)
                        .is_some_and(|pointer| self.read(pointer, count as usize * 8).is_some())
                }) {
                    continue;
                }
                let name = format!("{count} entries");
                self.add(address, RecordKind::ConstantDictionary, &name, None)?;
                for (delta, field) in [(8, "options"), (16, "count"), (24, "keys"), (32, "objects")]
                {
                    self.add(
                        address + delta,
                        RecordKind::ConstantDictionaryField,
                        &name,
                        Some(field),
                    )?;
                }
            }
        }
        Ok(())
    }
}
