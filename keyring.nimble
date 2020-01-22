# Package

version       = "0.1.0"
author        = "Matt Haggard"
description   = "Cross-platform OS keyring interface"
license       = "MIT"
srcDir        = "src"



# Dependencies

requires "nim >= 1.0.2"
when defined(windows):
  requires "winim >= 3.2.4"
when defined(linux):
  # TODO: until dbus PRs are merged in, use my own version
  # requires "dbus >= 0.0.1"
  requires "https://github.com/iffy/nim-dbus.git#master" # nimble install https://github.com/iffy/nim-dbus.git@#master
