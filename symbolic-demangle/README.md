[![Build Status](https://travis-ci.org/getsentry/symbolic.svg?branch=master)](https://travis-ci.org/getsentry/symbolic)

# symbolic-demangle

Demangling support for various languages and compilers.

Currently supported languages are:

- C++ (GCC-style compilers and MSVC)
- Rust (both `legacy` and `v0`)
- Swift (vendored Swift 6.3.1 demangler)
- ObjC (only symbol detection)

As the demangling schemes for the languages are different, the supported demangling features are
inconsistent. For example, argument types were not encoded in legacy Rust mangling and thus not
available in demangled names.

This module is part of the `symbolic` crate and can be enabled via the `demangle` feature.

## Runtime Type Names

Use `demangle_type(name, language)` only when the source identifies a runtime type encoding.
It supports bare C++ RTTI names and legacy Swift `_Tt` runtime names without relaxing
ordinary function-symbol detection. For example, `7TFPFont` with `Language::Cpp` becomes
`TFPFont`, and `_TtC10Foundation13__DataStorage` with `Language::Swift` becomes
`Foundation.__DataStorage`. Keep the raw name as the identity; display names can collide.

Unsupported languages, disabled features, malformed names, and exceeded budgets return the
borrowed original name. Input and output are limited to 4096 bytes. C++ parsing/printing have
recursion limits of 32/64. Swift parsing/printing have depth limits of 64, a 256 KiB node-factory
allocation limit, and a 16384-node print-work limit. Bounds apply during parsing and rendering,
not just to the final output buffer. Other Swift runtime spellings remain unsupported.

## Examples

```rust
use symbolic::common::{Language, Name};
use symbolic::demangle::{Demangle, DemangleOptions};

let name = Name::new("__ZN3std2io4Read11read_to_end17hb85a0f6802e14499E");
assert_eq!(name.detect_language(), Language::Rust);
assert_eq!(name.try_demangle(DemangleOptions::default()), "std::io::Read::read_to_end");
```

License: MIT
