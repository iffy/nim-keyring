# v0.4.2 - 2024-02-22

- **FIX:** Annotate dbus.append calls with {.gcsafe.}

# v0.4.1 - 2023-02-06

- **FIX:** Fix memory leak on Windows (#16)

# v0.4.0 - 2023-01-06

- **NEW:** Add `keyringAvailable()` to determine if the keyring works. This is to help distinguish between transient errors and more permanent ones.

# v0.3.1 - 2022-07-15

- **FIX:** Added more helpful errors when dbus calls fail on Linux

# v0.3.0 - 2020-12-30

- **NEW:** Add error code to macOS error messages
- **NEW:** Added CHANGELOG
- **FIX:** Handle case when deleting password doesn't have search results
- **FIX:** Change `assert` to `doAssert` in Linux code.

