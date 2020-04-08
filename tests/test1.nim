import unittest
import keyring

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
  defer:
    deletePassword(service, user)
  check getPassword(service, user).get() == password1
  setPassword(service, user, password2)
  check getPassword(service, user).get() == password2

test "binary":
  let
    service = "nimkeyring-service"
    user = "user"
    password = "password\x00foo"

  setPassword(service, user, password)
  defer:
    deletePassword(service, user)
  check getPassword(service, user).get() == password

test "no such password":
  check getPassword("gumshoe", "treble bark").isNone()

test "deleting non-existent":
  deletePassword("gumshoe1", "treble bark2")
  deletePassword("gumshoe1", "treble bark2")

test "unique":
  setPassword("nimkeyring-service1", "user1", "a")
  defer:
    deletePassword("nimkeyring-service1", "user1")
  setPassword("nimkeyring-service2", "user1", "b")
  defer:
    deletePassword("nimkeyring-service2", "user1")
  setPassword("nimkeyring-service1", "user2", "c")
  defer:
    deletePassword("nimkeyring-service1", "user2")
  setPassword("nimkeyring-service2", "user2", "d")
  defer:
    deletePassword("nimkeyring-service2", "user2")

  check getPassword("nimkeyring-service1", "user1").get() == "a"
  check getPassword("nimkeyring-service2", "user1").get() == "b"
  check getPassword("nimkeyring-service1", "user2").get() == "c"
  check getPassword("nimkeyring-service2", "user2").get() == "d"
