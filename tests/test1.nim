import unittest
import keyring
import os
import osproc

# Run the tests on a system that doesn't support keyring
# to see that appropriate errors are raised.
const NOTSUPPORTED = defined(testkeyringnotsupported)


# If you want the passwords to hang around after the test,
# run with -d:nocleanup
const DOCLEANUP = not defined(nocleanup)
template clean(body:untyped):untyped =
  when DOCLEANUP:
    body

template cd(dirname: string, body: untyped): untyped =
  block:
    let orig = getCurrentDir().absolutePath()
    try:
      setCurrentDir(dirname)
      body
    finally:
      setCurrentDir(orig)

test "not supported":
  when NOTSUPPORTED:
    check keyringAvailable() == false
    expect KeyringNotSupported:
      setPassword("foo", "bar", "baz")
    expect KeyringNotSupported:
      discard getPassword("foo", "bar")
    expect KeyringNotSupported:
      deletePassword("foo", "bar")
  else:
    check keyringAvailable() == true
    echo "Run this test with -d:testkeyringnotsupported on a system where keyring is not supported to test"

when not NOTSUPPORTED:
  test "set/get":
    let
      service = "nimkeyring-service"
      user = "user"
      password = "password"

    setPassword(service, user, password)
    check getPassword(service, user).get() == password
    deletePassword(service, user)
    check getPassword(service, user).isNone()

  test "update":
    let
      service = "nimkeyring-service"
      user = "user"
      password1 = "password1"
      password2 = "password2"

    setPassword(service, user, password1)
    clean:
      defer: deletePassword(service, user)
    check getPassword(service, user).get() == password1
    setPassword(service, user, password2)
    check getPassword(service, user).get() == password2

  test "binary":
    let
      service = "nimkeyring-service"
      user = "user"
      password = "password\x00foo"

    setPassword(service, user, password)
    clean:
      defer: deletePassword(service, user)
    check getPassword(service, user).get() == password

  test "no such password":
    check getPassword("gumshoe", "treble bark").isNone()

  test "deleting non-existent":
    deletePassword("gumshoe1", "treble bark2")
    deletePassword("gumshoe1", "treble bark2")

  test "unique":
    setPassword("nimkeyring-service1", "user1", "a")
    clean:
      defer: deletePassword("nimkeyring-service1", "user1")
    setPassword("nimkeyring-service2", "user1", "b")
    clean:
      defer: deletePassword("nimkeyring-service2", "user1")
    setPassword("nimkeyring-service1", "user2", "c")
    clean:
      defer: deletePassword("nimkeyring-service1", "user2")
    setPassword("nimkeyring-service2", "user2", "d")
    clean:
      defer: deletePassword("nimkeyring-service2", "user2")

    check getPassword("nimkeyring-service1", "user1").get() == "a"
    check getPassword("nimkeyring-service2", "user1").get() == "b"
    check getPassword("nimkeyring-service1", "user2").get() == "c"
    check getPassword("nimkeyring-service2", "user2").get() == "d"

  test "process twice":
    # macOS in particular sometimes has problems the second time
    # you run a process that accesses passwords
    let filename = "nimkeyring_double_test.nim"
    let snippet = """
import keyring
const service = "nimkeyring-twice"
const account = "double"
const password = "some password"
let existing = getPassword(service, account)
if existing.isNone:
  # first run
  setPassword(service, account, password)
  assert getPassword(service, account).get() == password
else:
  # second run
  deletePassword(service, account)
  assert existing.get() == password
    """
    clean:
      defer: deletePassword("nimkeyring-twice", "double")
    cd currentSourcePath().parentDir().absolutePath():
      writeFile(filename, snippet)
      defer: removeFile(filename)
      checkpoint "Run #1"
      let (outp1, rc1) = execCmdEx("nim c -r " & filename)
      checkpoint outp1
      assert rc1 == 0
      
      checkpoint "Run #2"
      let (outp2, rc2) = execCmdEx("nim c -r " & filename)
      checkpoint outp2
      assert rc2 == 0
