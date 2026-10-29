//! Describe Objective-C ABI objects reached from the image's declared class and protocol lists.
//!
//! Class objects and their read-only class data are separate artifacts, as are their metaclass
//! counterparts. Only exact structure/field addresses are emitted; method bodies and allocation
//! instance types are not inferred. Layout offsets below are for the 64-bit Objective-C runtime.

use super::Image;
use crate::{Reason, RecordKind};

impl<'data> Image<'data, '_> {
    /// Root sections contain 8-byte VM pointers. Follow a validated class's isa once to its
    /// metaclass, rather than recursively chasing isa/superclass graphs that can contain cycles.
    pub(super) fn objc(&mut self) -> Result<(), Reason> {
        for (start, count) in self.roots(&["__objc_classlist", "__objc_nlclslist"], 8) {
            for index in 0..count {
                self.step()?;
                if let Some(pointer) = self.pointer(start + index * 8) {
                    if let Some(isa) = self.class(pointer, false)? {
                        self.class(isa, true)?;
                    }
                }
            }
        }
        for (start, count) in self.roots(&["__objc_protolist"], 8) {
            for index in 0..count {
                self.step()?;
                if let Some(pointer) = self.pointer(start + index * 8) {
                    self.protocol(pointer)?;
                }
            }
        }
        Ok(())
    }

    /// Label the class object, class_ro_t, and their ABI field slots with the same validated owner.
    /// Return isa for the caller's single metaclass hop; never relabel the referenced instance body.
    fn class(&mut self, address: u64, metaclass: bool) -> Result<Option<u64>, Reason> {
        let Some((isa, data, name)) = self.class_header(address, metaclass) else {
            return Ok(None);
        };
        let (object_kind, data_kind, object_field, data_field) = if metaclass {
            (
                RecordKind::MetaclassObject,
                RecordKind::MetaclassData,
                RecordKind::MetaclassObjectField,
                RecordKind::MetaclassDataField,
            )
        } else {
            (
                RecordKind::ClassObject,
                RecordKind::ClassData,
                RecordKind::ClassObjectField,
                RecordKind::ClassDataField,
            )
        };
        self.add(address, object_kind, name, None)?;
        self.add(data, data_kind, name, None)?;
        // objc_class's five 8-byte slots are isa, superclass, cache/vtable storage, and data bits.
        // Offset zero is already represented by the object record; these are addresses of fields,
        // not addresses obtained by following the fields' pointer values.
        for (delta, field) in [
            (8, "superclass"),
            (16, "cache"),
            (24, "vtable"),
            (32, "data"),
        ] {
            self.add(address + delta, object_field, name, Some(field))?;
        }
        // class_ro_t begins with four u32 values (flags/start/size/reserved), followed by seven
        // pointers. The +24 name pointer supplies the owner for both this record and its children.
        for (delta, field) in [
            (4, "instance_start"),
            (8, "instance_size"),
            (12, "reserved"),
            (16, "ivar_layout"),
            (24, "name"),
            (32, "methods"),
            (40, "protocols"),
            (48, "ivars"),
            (56, "weak_ivar_layout"),
            (64, "properties"),
        ] {
            self.add(data + delta, data_field, name, Some(field))?;
        }
        if let Some(ivars) = self.pointer(data + 48) {
            self.ivars(ivars, name)?;
        }
        if let Some(methods) = self.pointer(data + 32) {
            self.methods(methods, name, metaclass, 0)?;
        }
        if let Some(protocols) = self.pointer(data + 40) {
            self.protocol_list(protocols, name)?;
        }
        Ok(Some(isa))
    }

    /// Validate the complete 40-byte class header and 72-byte class_ro_t before assigning a name.
    /// Section ownership, alignment, RO_META, and plausible instance bounds jointly reject lookalikes.
    fn class_header(&self, address: u64, metaclass: bool) -> Option<(u64, u64, &'data str)> {
        if address & 7 != 0 {
            return None;
        }
        let section = self.section(address, 40)?;
        if !matches!(section.name.as_str(), "__objc_data" | "__data") {
            return None;
        }
        // class_data_bits_t stores low-bit runtime flags alongside the aligned class-data pointer.
        let data = self.pointer(address + 32)? & !7;
        let section = self.section(data, 72)?;
        if !matches!(
            section.name.as_str(),
            "__objc_const" | "__objc_data" | "__const" | "__data"
        ) {
            return None;
        }
        let flags = self.u32(data)?;
        let start = self.u32(data + 4)?;
        let size = self.u32(data + 8)?;
        // RO_META is bit 0. The instance-size ceiling is a plausibility guard, not a decoded type size
        // to expose to consumers or evidence that a capture allocation is an instance of this class.
        if (flags & 1 != 0) != metaclass || start > size || size > 1 << 30 {
            return None;
        }
        Some((
            self.pointer(address)?,
            data,
            self.name(self.pointer(data + 24)?)?,
        ))
    }

    /// ivar_list_t has u32 entry size/count followed by 32-byte ivar_t records. Require that exact
    /// known stride and a fully contained array before reading names or emitting entry field slots.
    fn ivars(&mut self, address: u64, owner: &str) -> Result<(), Reason> {
        let Some((32, count)) = self.u32(address).zip(self.u32(address + 4)) else {
            return Ok(());
        };
        if count > 100_000 || self.section(address, 8 + count as usize * 32).is_none() {
            return Ok(());
        }
        self.add(address, RecordKind::IvarList, owner, None)?;
        self.add(address + 4, RecordKind::IvarList, owner, Some("count"))?;
        for index in 0..u64::from(count) {
            self.step()?;
            let entry = address + 8 + index * 32;
            let Some(name) = self
                .pointer(entry + 8)
                .and_then(|pointer| self.name(pointer))
            else {
                continue;
            };
            let length = owner.len().saturating_add(name.len()).saturating_add(2);
            if length > self.limits.name_length {
                return Err(Reason::NameLengthLimit);
            }
            self.storage.charge(length)?;
            let name = format!("{owner}::{name}");
            // ivar_t: offset/name/type pointers at +0/+8/+16, then u32 alignment and size.
            // The offset pointer's storage is described; its value is not an allocation address.
            for (delta, field) in [
                (0, "offset"),
                (8, "name"),
                (16, "type"),
                (24, "alignment"),
                (28, "size"),
            ] {
                self.add(entry + delta, RecordKind::IvarEntry, &name, Some(field))?;
            }
        }
        Ok(())
    }

    /// protocol_list_t starts with an unsigned pointer-sized count, then that many protocol pointers.
    /// Although read through the shared 64-bit helper, this first word is a count, not a target VA.
    fn protocol_list(&mut self, address: u64, owner: &str) -> Result<(), Reason> {
        let Some(count) = self.pointer(address).filter(|count| *count <= 100_000) else {
            return Ok(());
        };
        if self.section(address, 8 + count as usize * 8).is_none() {
            return Ok(());
        }
        self.add(address, RecordKind::ProtocolList, owner, None)?;
        for index in 0..count {
            self.step()?;
            if let Some(pointer) = self.pointer(address + 8 + index * 8) {
                self.protocol(pointer)?;
            }
        }
        Ok(())
    }

    /// Recognize protocol_t's known 72-byte prefix and its declared size at +64. Optional later ABI
    /// fields are not decoded, and adopted-protocol pointers are labeled without recursive traversal.
    fn protocol(&mut self, address: u64) -> Result<(), Reason> {
        if self.section(address, 72).is_none()
            || !self
                .u32(address + 64)
                .is_some_and(|size| (72..=4096).contains(&size))
        {
            return Ok(());
        }
        let Some(name) = self
            .pointer(address + 8)
            .and_then(|pointer| self.name(pointer))
        else {
            return Ok(());
        };
        self.add(address, RecordKind::Protocol, name, None)?;
        // The first slot is isa; +8 is name, +16 adopted protocols, then method/property pointers.
        // Size and flags are u32 fields at +64/+68 rather than 8-byte pointers.
        for (delta, field) in [
            (8, "name"),
            (16, "protocols"),
            (24, "instance_methods"),
            (32, "class_methods"),
            (40, "optional_instance_methods"),
            (48, "optional_class_methods"),
            (56, "properties"),
            (64, "size"),
            (68, "flags"),
        ] {
            self.add(
                address + delta,
                RecordKind::ProtocolField,
                name,
                Some(field),
            )?;
        }
        Ok(())
    }
}
