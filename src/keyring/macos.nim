import options
export options
import base64

import ./macos_keyringapi

# Big thanks to https://github.com/keybase/go-keychain
# which served as an excellent reference implementation for this code

proc setPassword*(service: string, username: string, password: string) =
  ## Save a password in the OS keychain

  # macOS password type
  let
    key1 = kSecClass
    val1 = kSecClassGenericPassword
    # service
    k_service = kSecAttrService
    v_service = mkCFString(service)
    # account
    k_account = kSecAttrAccount
    v_account = mkCFString(username)
    # password
    k_password = kSecValueData
    v_password = mkCFData(password.encode())

  defer: CFRelease(v_service)
  defer: CFRelease(v_account)
  defer: CFRelease(v_password)

  var ikeys:array[4,CFStringRef] = [key1, k_service, k_account, k_password]
  var ivals:array[4,CFTypeRef] = [val1, v_service, v_account, v_password]
  let ilen:CFIndex = ikeys.len.CFIndex
  let item = CFDictionaryCreate(nil, ikeys.addr, ivals.addr, ilen, nil, nil)
  defer: CFRelease(item)

  var err = SecItemAdd(item, nil)
  if err == errSecDuplicateItem:
    # Since it's a duplicate, update the existing item
    var qkeys:array[5, CFStringRef] = [key1, k_service, k_account, kSecMatchLimit,    kSecReturnData]
    var qvals:array[5, CFTypeRef]   = [val1, v_service, v_account, kSecMatchLimitOne, kCFBooleanFalse]
    let qlen:CFIndex = qkeys.len.CFIndex
    let query = CFDictionaryCreate(nil, qkeys.addr, qvals.addr, qlen, nil, nil)
    defer: CFRelease(query)

    var pkeys:array[2, CFStringRef] = [key1, k_password]
    var pvals:array[2, CFTypeRef] = [val1, v_password]
    let plen:CFIndex = pkeys.len.CFIndex
    let patch = CFDictionaryCreate(nil, pkeys.addr, pvals.addr, plen, nil, nil)
    defer: CFRelease(patch)

    err = SecItemUpdate(query, patch)
  
  if err != errSecSuccess:
    raise newException(CatchableError, "Error saving password")

proc getPassword*(service: string, username: string): Option[string] =
  ## Retrieve a previously-saved password from the OS keychain
  let
    key1 = kSecClass
    val1 = kSecClassGenericPassword
    # service
    k_service = kSecAttrService
    v_service = mkCFString(service)
    # account
    k_account = kSecAttrAccount
    v_account = mkCFString(username)

  defer: CFRelease(v_service)
  defer: CFRelease(v_account)
  
  var qkeys:array[5, CFStringRef] = [key1, k_service, k_account, kSecMatchLimit,    kSecReturnData]
  var qvals:array[5, CFTypeRef] =   [val1, v_service, v_account, kSecMatchLimitOne, kCFBooleanTrue]
  let qlen:CFIndex = qkeys.len.CFIndex
  let query = CFDictionaryCreate(nil, qkeys.addr, qvals.addr, qlen, nil, nil)
  defer: CFRelease(query)
  
  var password: CFDataRef
  let err = SecItemCopyMatching(query, cast[ptr CFTypeRef](password.addr))
  if err == errSecSuccess:
    CFRetain(password)
    defer: CFRelease(password)
    result = some(password.getCFData().decode())
  else:
    result = none[string]()

proc deletePassword*(service: string, username: string) =
  ## Delete a saved password (if it exists)
  let
    key1 = kSecClass
    val1 = kSecClassGenericPassword
    # service
    k_service = kSecAttrService
    v_service = mkCFString(service)
    # account
    k_account = kSecAttrAccount
    v_account = mkCFString(username)

  defer: CFRelease(v_service)
  defer: CFRelease(v_account)
  
  var qkeys:array[4, CFStringRef] = [key1, k_service, k_account, kSecMatchLimit]
  var qvals:array[4, CFStringRef] = [val1, v_service, v_account, kSecMatchLimitOne]
  let qlen:CFIndex = qkeys.len.CFIndex
  let query = CFDictionaryCreate(nil, qkeys.addr, qvals.addr, qlen, nil, nil)
  defer: CFRelease(query)

  let err = SecItemDelete(query)
  if err == errSecItemNotFound:
    discard
  elif err == errSecSuccess:
    discard
  else:
    raise newException(CatchableError, "Error deleting password")
