when defined(macosx):
  import keyring/macos
  export macos
elif defined(windows):
  import keyring/windows
  export windows
else:
  raise newException(CatchableError, "OS not supported")
