# keyring

This is a Nim library that provides access to the operating system keyring.  It uses the following backends:

- macOS: Keychain
- Windows: Credential Management win32 API
- Linux: **NOT SUPPORTED YET** but will use libsecret

## Usage

```nim
import keyring

setPassword("my-service", "myuser", "secretpassword")
assert getPassword("my-service", "myuser").get() == "secretpassword"
deletePassword("my-service", "myuser")
```

Note that `getPassword(...)` returns `Option[string]`, so you can check whether a password was previously saved with `.isNone()`/`.isSome()`.

