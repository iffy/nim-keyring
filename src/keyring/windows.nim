import winim
import options
export options
import base64

import ./errors

template toLPWSTR(x:string):LPWSTR = cast[LPWSTR](&(+$x))
template toLPCWSTR(x:string):LPCWSTR = cast[LPCWSTR](&(+$x))

template targetname(service: string, username: string):string =
  username & "@" & service

proc keyringAvailable*(): bool = true

proc setPassword*(service: string, username: string, password: string) {.raises: [KeyringError].} =
  ## Save a password in the OS keychain
  let username = username
  let targetname = targetname(service, username)
  let credential_blob = password.encode()
  var cred = CREDENTIALW(
    Type: CRED_TYPE_GENERIC,
    TargetName: targetname.toLPWSTR(),
    UserName: username.toLPWSTR(),
    CredentialBlobSize: cast[DWORD](credential_blob.len),
    CredentialBlob: cast[LPBYTE](&credential_blob),
    Persist: CRED_PERSIST_ENTERPRISE,
  )
  var pcred:PCREDENTIALW = cred.unsafeAddr
  let flags:DWORD = 0

  let res = CredWriteW(pcred, flags)
  if res == 0:
    let err_code = GetLastError()
    var err_msg = "Unknown error"
    case err_code
    of ERROR_NO_SUCH_LOGON_SESSION:
      err_msg = "ERROR_NO_SUCH_LOGON_SESSION: The logon session does not exist or there is no credential set associated with this logon session. Network logon sessions do not have an associated credential set."
    of ERROR_INVALID_PARAMETER:
      err_msg = "ERROR_INVALID_PARAMETER: Certain fields cannot be changed in an existing credential. This error is returned if a field does not match the value in a protected field of the existing credential."
    of ERROR_INVALID_FLAGS:
      err_msg = "ERROR_INVALID_FLAGS: A value that is not valid was specified for the Flags parameter."
    of ERROR_BAD_USERNAME:
      err_msg = "ERROR_BAD_USERNAME: The UserName member of the passed in Credential structure is not valid. For a description of valid user name syntax, see the definition of that member."
    of ERROR_NOT_FOUND:
      err_msg = "ERROR_NOT_FOUND: CRED_PRESERVE_CREDENTIAL_BLOB was specified and there is no existing credential by the same TargetName and Type."
    of SCARD_E_NO_READERS_AVAILABLE:
      err_msg = "SCARD_E_NO_READERS_AVAILABLE: The CRED_TYPE_CERTIFICATE credential being written requires the smart card reader to be available."
    of SCARD_E_NO_SMARTCARD, SCARD_W_REMOVED_CARD:
      err_msg = "SCARD_E_NO_SMARTCARD, SCARD_W_REMOVED_CARD: A CRED_TYPE_CERTIFICATE credential being written requires the smart card to be inserted."
    of SCARD_W_WRONG_CHV:
      err_msg = "SCARD_W_WRONG_CHV: The wrong PIN was supplied for the CRED_TYPE_CERTIFICATE credential being written."
    else:
      err_msg = "Unknown error (" & $err_code & ")"
    raise newException(KeyringError, err_msg)

proc getPassword*(service: string, username: string): Option[string] {.raises: [KeyringError, ValueError].} =
  ## Retrieve a previously-saved password from the OS keychain
  let targetname = targetname(service, username)
  let cred_type:DWORD = CRED_TYPE_GENERIC
  let flags:DWORD = 0
  
  var cred = CREDENTIALW()
  var pcred:PCREDENTIALW = cred.unsafeAddr
  let res = CredReadW(
    targetname.toLPCWSTR(),
    cred_type,
    flags,
    pcred.unsafeAddr)
  defer: pcred.unsafeAddr.CredFree #Win32 buffer must be freed
  
  if res == 0:
    let err_code = GetLastError()
    var err_msg:string
    case err_code
    of ERROR_NOT_FOUND:
      return none[string]()
    of ERROR_NO_SUCH_LOGON_SESSION:
      err_msg = "ERROR_NO_SUCH_LOGON_SESSION: The logon session does not exist or there is no credential set associated with this logon session. Network logon sessions do not have an associated credential set."
    of ERROR_INVALID_FLAGS:
      err_msg = "ERROR_INVALID_FLAGS: A flag that is not valid was specified for the Flags parameter."
    else:
      err_msg = "Unknown error (" & $err_code & ")"
    raise newException(KeyringError, err_msg)
    
  let password = ($cast[cstring](pcred[].CredentialBlob))[0 .. pcred[].CredentialBlobSize-1].decode()
  return some(password)

proc deletePassword*(service: string, username: string) {.raises: [KeyringError].} =
  ## Delete a saved password (if it exists)
  let targetname = targetname(service, username)
  let res = CredDeleteW(
    targetname.toLPCWSTR(),
    CRED_TYPE_GENERIC,
    0,
  )
  if res == 0:
    let err_code = GetLastError()
    var err_msg:string
    case err_code
    of ERROR_NOT_FOUND:
      return
    of ERROR_NO_SUCH_LOGON_SESSION:
      err_msg = "ERROR_NO_SUCH_LOGON_SESSION: The logon session does not exist or there is no credential set associated with this logon session. Network logon sessions do not have an associated credential set."
    of ERROR_INVALID_FLAGS:
      err_msg = "ERROR_INVALID_FLAGS: A flag that is not valid was specified for the Flags parameter."
    else:
      err_msg = "Unknown error (" & $err_code & ")"
    raise newException(KeyringError, err_msg)
