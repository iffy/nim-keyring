# Package

version       = "0.4.0"
author        = "Matt Haggard"
description   = "Cross-platform OS keyring interface"
license       = "MIT"
srcDir        = "src"



# Dependencies

requires "nim >= 1.0.2"
when defined(windows):
  requires "winim >= 3.2.4"
when defined(linux):
  requires "dbus >= 0.0.1"
