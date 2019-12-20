import unittest
import keyring

test "set/get":
  let
    service = "service"
    user = "user"
    password = "password"

  setPassword(service, user, password)
  check getPassword(service, user).get() == password
  deletePassword(service, user)
  check getPassword(service, user).isNone()

test "binary":
  let
    service = "service"
    user = "user"
    password = "password\x00foo"

  setPassword(service, user, password)
  check getPassword(service, user).get() == password
  deletePassword(service, user)

test "no such password":
  check getPassword("gumshoe", "treble bark").isNone()

test "unique":
  setPassword("service1", "user1", "a")
  setPassword("service2", "user1", "b")
  setPassword("service1", "user2", "c")
  setPassword("service2", "user2", "d")

  check getPassword("service1", "user1").get() == "a"
  check getPassword("service2", "user1").get() == "b"
  check getPassword("service1", "user2").get() == "c"
  check getPassword("service2", "user2").get() == "d"
  