import keyring/errors
export errors

when defined(macosx):
  import keyring/macos
  export macos
elif defined(windows):
  import keyring/windows
  export windows
elif defined(linux):
  import keyring/linux
  export linux
else:
  raise newException(KeyringError, "OS not supported")
