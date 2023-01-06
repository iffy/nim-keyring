import std/options

import ./errors

proc keyringAvailable*(): bool = false

proc setPassword*(service: string, username: string, password: string) {.raises: [KeyringError].} =
  raise newException(KeyringNotSupported, "Keyring not yet supported on Android")

proc getPassword*(service: string, username: string): Option[string] {.raises: [KeyringError].} =
  raise newException(KeyringNotSupported, "Keyring not yet supported on Android")

proc deletePassword*(service: string, username: string) {.raises: [KeyringError].} =
  raise newException(KeyringNotSupported, "Keyring not yet supported on Android")
