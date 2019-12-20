import os
import osproc
import options
export options
import streams
import base64

proc setPassword*(service: string, username: string, password: string) =
  ## Save a password in the OS keychain
  let cmd = quoteShellCommand([
    # see `security add-generic-password --help`
    "add-generic-password",
    "-a", username,
    "-s", service,
    "-U",
    "-w", password.encode()
  ])
  let p = startProcess(findExe"security", args = ["-i"])
  p.inputStream().writeLine(cmd)
  p.close()
  if p.waitForExit() != 0:
    raise newException(CatchableError, "Error saving password")

proc getPassword*(service: string, username: string): Option[string] =
  ## Retrieve a previously-saved password from the OS keychain
  let res = execCmdEx(quoteShellCommand([
    # see `security find-generic-password --help`
    "security",
    "find-generic-password",
    "-a", username,
    "-s", service,
    "-w",
  ]))
  if res.exitCode == 0:
    return some(res.output[0 .. ^2].decode())
  else:
    return none[string]()

proc deletePassword*(service: string, username: string) =
  ## Delete a saved password (if it exists)
  discard execCmdEx(quoteShellCommand([
    # see `security delete-generic-password --help`
    "security",
    "delete-generic-password",
    "-a", username,
    "-s", service,
  ]))
