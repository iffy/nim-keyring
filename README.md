# keyring

**SECURITY NOTE:** Though an effort has been made to ensure secret confidentiality and memory safety, this library has not undergone strenous security testing.  Use it at your own risk.

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

