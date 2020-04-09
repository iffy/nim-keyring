import unittest
import strutils

when defined(macosx):
  import keyring/macos_keyringapi

  test "CFString roundtrip":
    let orig = "hello world!"
    let cf = mkCFString(orig)
    defer: CFRelease(cf)
    let res = $cf
    check res == orig
    check res.len == orig.len
  
  test "CFData roundtrip":
    let orig = "hello world!"
    let cf = mkCFData(orig)
    defer: CFRelease(cf)
    let res = $cf
    check res == orig
    check res.len == orig.len

  test "CFData roundtrip large":
    let orig = "hello world!".repeat(10)
    let cf = mkCFData(orig)
    defer: CFRelease(cf)
    let res = $cf
    check res == orig
    check res.len == orig.len