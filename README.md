# keyring

![](https://github.com/iffy/nim-keyring/workflows/CI/badge.svg?branch=master)


**SECURITY NOTE:** Though an effort has been made to ensure secret confidentiality and memory safety, this library has not undergone strenous security testing.  Use it at your own risk.

This is a Nim library that provides access to the operating system keyring.  It uses the following backends:

- macOS: Keychain
- Windows: Credential Management win32 API
- Linux: [Secret Service API](https://specifications.freedesktop.org/secret-service/latest/index.html).  Note that no encryption is done en route to the Secret Service backend.  According to the [spec](https://specifications.freedesktop.org/secret-service/latest/ch07.html#idm46060787734752) this is probably okay.

## Usage

```
nimble install https://github.com/iffy/keyring.git
```

```nim
import keyring

setPassword("my-service", "myuser", "secretpassword")
assert getPassword("my-service", "myuser").get() == "secretpassword"
deletePassword("my-service", "myuser")
```

Note that `getPassword(...)` returns `Option[string]`, so you can check whether a password was previously saved with `.isNone()`/`.isSome()`.

