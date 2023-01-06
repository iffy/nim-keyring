# keyring

<a href="https://github.com/iffy/nim-keyring/actions"><img src="https://github.com/iffy/nim-keyring/workflows/CI/badge.svg?branch=master"/></a>


**SECURITY NOTE:** Though an effort has been made to ensure secret confidentiality and memory safety, this library has not undergone strenuous security testing.  Use it at your own risk.

This is a Nim library that provides access to the operating system keyring.  It uses the following backends:

- macOS: Keychain via [Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
- Windows: [Credential Management win32 API](https://docs.microsoft.com/en-us/windows/win32/api/wincred/)
- Linux: [Secret Service API](https://specifications.freedesktop.org/secret-service/latest/index.html).  Note that no encryption is done en route to the Secret Service backend.  According to the [spec](https://specifications.freedesktop.org/secret-service/latest/ch07.html#idm46060787734752) this is probably okay.

## Usage

```
nimble install keyring
```

```nim
import keyring

assert keyringAvailable()
setPassword("my-service", "myuser", "secretpassword")
assert getPassword("my-service", "myuser").get() == "secretpassword"
deletePassword("my-service", "myuser")
```

Note that `getPassword(...)` returns `Option[string]`, so you can check whether a password was previously saved with `.isNone()`/`.isSome()`.

### Error handling

All 3 procs can raise `KeyringFailed` or `KeyringNotSupported` in the case of an error.  Some errors are transient, such as if the user doesn't enter the right password.  Other errors are more permanent (e.g. keychain software isn't installed on Linux). Use `keyringAvailable()` to detect if the keyring works for the current system.

Additionally, different OS implementations might raise other errors (e.g. DBus erros on Linux), so the following is a more complete example that handles errors:

```nim
import keyring

if not keyringAvailable():
  echo "Keyring is not going to work."

try:
  setPassword("my-service", "myuser", "secret")
except KeyringFailed:
  discard
except:
  discard

var password:string
try:
  let ret = getPassword("my-service", "myuser")
  if ret.isSome:
    password = ret.get()
except KeyringFailed:
  discard
except:
  discard

try:
  deletePassword("my-service", "myuser")
except KeyringFailed:
  discard
except:
  discard
```
