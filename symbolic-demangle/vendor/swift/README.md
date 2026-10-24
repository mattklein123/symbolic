# Vendored Swift Demangler

This folder contains a vendored subset of the [Swift Programming Language]. The Swift library is
reduced to the demangler only to reduce the size of this package.

The current version is **Swift 6.3.1**.

## Sentry Modifications

Two patches already shipped by upstream Symbolic are retained: `1-arguments.patch` controls
function argument/return-type display, and `2-metatype-compat.patch` accepts an older metatype
specialization encoding after the Swift 6.3 update.

The runtime-type API additionally restores Swift's legacy grammar parser, `OldDemangler.cpp`.
Modern apps still expose this grammar through Objective-C runtime names such as `_TtC...`.
The source comes from the matching release, pinned to Swift Git blob
`7acd278a0827972f1866737fac3e1e5e25785dcd` from `swift-6.3.1-RELEASE` before local patches.
`3-runtime-type-bounds.patch` adds opt-in node allocation, parsing-depth, print-depth, output,
and print-work limits. Default settings preserve ordinary function-symbol behavior. The Rust
build includes the old parser but does not enable `SWIFT_SUPPORT_OLD_MANGLING` globally.

## How to Update

1. **Check out the [latest release] of Swift:**
   1. Create a directory that will house swift and its dependencies:
      ```
      $ mkdir swift-source && cd swift-source
      ```
   2. Clone the swift repository into a subdirectory:
      ```
      $ git clone https://github.com/apple/swift.git
      ```
   3. Check out the release branch of the latest release:
      ```
      $ cd swift
      $ git checkout swift-6.3.1-RELEASE
      ```
   4. Check out dependencies:
      ```
      $ ./utils/update-checkout --clone
      ```
   5. Build the complete swift project (be very patient, this may take long):
      ```
      $ ./utils/build-script --skip-build
      ```
2. **Copy updated sources and headers from the checkout to this library:**
   1. Run the update script in this directory (requires Python 3):
      ```
      $ ./update.py swift-source
      ```
   2. Check for modifications.
   3. Commit _"feat(demangle): Import libswift demangle x.x.x"_ before proceeding.
3. **Apply the patch:**
   1. Apply `1-arguments.patch`, `2-metatype-compat.patch`, and
      `3-runtime-type-bounds.patch`, in that order. Paths are relative to the repository root.
      Keep `OldDemangler.cpp` in the updater's copied sources and the Rust build source list.
   2. Build the Rust library and ensure tests work.
   3. Commit the changes.
4. **Add tests for new mangling schemes:**
   1. Identify new mangling schemes. Skip if there are no known changes.
   2. Add test cases to `symbolic-demangle/tests/test_swift.rs`.
5. **Update Repository metadata**:
   1. Bump the Swift version number in this README.
   2. Check for changes in the license and update the files.
   3. Refresh each affected patch against its pre-patch sources, keeping the three purposes
      separate and preserving upstream source formatting.
6. **Create a pull request.**

[swift programming language]: https://github.com/apple/swift
[latest release]: https://github.com/apple/swift/releases/latest/
