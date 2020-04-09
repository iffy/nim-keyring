{.passL: "-framework CoreFoundation".}
{.passL: "-framework Security".}

#---------------------------------------------------
# CoreFoundation
#---------------------------------------------------
type
  CFIndex* = distinct int

  CFTypeRef* {.pure, inheritable.} = ptr object
  CFTypeID* = distinct uint32
  CFPropertyList = ptr object of CFTypeRef

  CFAbstractDictionary = ptr object of CFPropertyList # CFDictionary
  # CFAbstractMutableDictionary = ptr object of CFAbstractDictionary # CFMutableDictionary

  CFDictionary = ptr object of CFAbstractDictionary
  # CFMutableDictionary = ptr object of CFDictionary

  CFDictionaryRef = ptr object of CFDictionary

  CFDictionaryKeyCallBacks = object
  CFDictionaryValueCallBacks = object

  CFRange* {.bycopy.} = object
    location*: CFIndex
    length*: CFIndex

  CFDataRef* = ptr object of CFTypeRef

  CFBooleanRef* = ptr object of CFTypeRef

# Types
proc CFRelease*(cf: CFTypeRef) {.importc.}
proc CFRetain*(cf: CFTypeRef) {.importc.}
proc CFGetTypeID*(cf: CFTypeRef): CFTypeID {.importc.}
proc CFBooleanGetTypeID*(): CFTypeID {.importc.}
proc CFDataGetTypeID*(): CFTypeID {.importc.}
proc CFNullGetTypeID*(): CFTypeID {.importc.}
proc CFStringGetTypeID*(): CFTypeID {.importc.}

proc CFDictionaryCreate*(allocator: pointer, keys: pointer, values: pointer, numValues: CFIndex, keyCallBacks: ptr CFDictionaryKeyCallBacks, valueCallBacks: ptr CFDictionaryValueCallBacks): CFDictionaryRef {.importc.}

proc CFDictionaryGetCount*(theDict: CFDictionaryRef): CFIndex {.importc.}
proc CFDictionaryGetKeysAndValues*(theDict: CFDictionaryRef, keys: pointer, values: pointer) {.importc.}

#---------------------------------------------------
# CFData
#---------------------------------------------------

# proc CFRangeMake*(loc, length: CFIndex): CFRange {.importc.}

proc CFDataCreate(allocator: pointer, bytes: pointer, length: CFIndex): CFDataRef {.importc.}
proc CFDataGetLength(theData: CFDataRef): CFIndex {.importc.}
proc CFDataGetBytes(theData: CFDataRef, rang: CFRange, bytes: pointer) {.importc.}
proc CFDataGetBytePtr(theData: CFDataRef): pointer {.importc.}

#---------------------------------------------------
# Booleans
#---------------------------------------------------
var
  kCFBooleanTrue* {.importc.} : CFBooleanRef
  kCFBooleanFalse* {.importc.} : CFBooleanRef

#---------------------------------------------------
# Strings
#---------------------------------------------------

type
  CFStringEncoding* = distinct int
  CFString* = object of CFTypeRef
  CFStringRef* = ptr object of CFString

const
  kCFStringEncodingISOLatin1* = (0x0201).CFStringEncoding

proc CFStringCreateWithCString*(alloc: pointer, str: cstring, encoding: CFStringEncoding): CFStringRef {.importc.}

proc CFStringGetCStringPtr*(theString: CFStringRef, encoding: CFStringEncoding): ptr cstring {.importc.}
proc CFStringGetCString*(theString: CFStringRef, buffer: cstring, bufferSize: CFIndex, encoding: CFStringEncoding): bool {.importc.}
proc CFStringGetMaximumSizeForEncoding(length: CFIndex, encoding: CFStringEncoding): CFIndex {.importc.}
proc CFStringGetLength(theString: CFStringRef): CFIndex {.importc.}


#---------------------------------------------------
# Porcelain
#---------------------------------------------------
proc `==`*(a, b: CFTypeID):bool {.borrow.}

proc mkCFString*(x:string):CFStringRef {.inline.} =
  CFStringCreateWithCString(nil, x.cstring, kCFStringEncodingISOLatin1)

proc `$`*(s:CFStringRef):string =
  let numchars = CFStringGetLength(s)
  let size = CFStringGetMaximumSizeForEncoding(numchars, kCFStringEncodingISOLatin1).int + 1
  result = newString(size - 1)
  if not CFStringGetCString(s, result.cstring, size.CFIndex, kCFStringEncodingISOLatin1):
    raise newException(ValueError, "Unable to get CFString value")

proc mkCFData*(x:string):CFDataRef {.inline.} =
  CFDataCreate(nil, x.cstring, (x.len).CFIndex)

proc getCFData*(theData: CFDataRef): string =
  if theData.isNil:
    raise newException(CatchableError, "Attempting to access nil CFDataRef")
  let length = CFDataGetLength(theData)

  when false:
    # CFDataGetBytes method
    let rang = CFRange(location:0.CFIndex, length:length)
    result = newString(length.int)
    CFDataGetBytes(theData, rang, result.cstring)
  else:
    # CFDataGetBytePtr method
    result = newString(length.int)
    let p = CFDataGetBytePtr(theData)
    copyMem(result.cstring, p, length.int)
  

proc `$`*(s:CFDataRef):string {.inline.} =
  s.getCFData()

proc `$`*(d:CFDictionaryRef):string =
  result.add "CF{"
  let count = d.CFDictionaryGetCount().int
  let keys = cast[ptr UncheckedArray[pointer]] (alloc(sizeof(pointer) * count))
  defer:
    keys.dealloc
  let vals = cast[ptr UncheckedArray[pointer]] (alloc(sizeof(pointer) * count))
  defer:
    vals.dealloc
  d.CFDictionaryGetKeysAndValues(keys, vals)
  for i in 0..count-1:
    # keys must be CFStringRef
    let key = cast[CFStringRef](keys[i])
    result.add "\"" & $key & "\":"
    let val = cast[CFTypeRef](vals[i])
    let typeid = val.CFGetTypeID
    if typeid == CFStringGetTypeID():
      result.add "\"" & $cast[CFStringRef](val) & "\""
    elif typeid == CFBooleanGetTypeID():
      let bval = cast[CFBooleanRef](val)
      if bval == kCFBooleanTrue:
        result.add("true")
      else:
        result.add("false")
    elif typeid == CFDataGetTypeID():
      result.add("\"" & (cast[CFDataRef](val)).getCFData() & "\"")
    elif typeid == CFNullGetTypeID():
      result.add("null")
    else:
      result.add("unknown")
    result.add ","
  result.add "}"

#---------------------------------------------------
# Security stuff
#
# Some of these are from /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/System/Library/Frameworks/Security.framework/Headers/
#---------------------------------------------------

type
  OSStatus* = enum
    errSecCertificateValidityPeriodTooLong = -67901,    # The validity period in the certificate exceeds the maximum allowed.
    errSecCertificateNameNotAllowed = -67900,    # The requested name is not allowed for this certificate.
    errSecCertificatePolicyNotAllowed = -67899,    # The requested policy is not allowed for this certificate.
    errSecTimestampRevocationNotification = -67898,    # A timestamp authority revocation notification was issued.
    errSecTimestampRevocationWarning = -67897,    # A timestamp authority revocation warning was issued.
    errSecTimestampWaiting = -67896,    # A timestamp transaction is waiting.
    errSecTimestampRejection = -67895,    # A timestamp transaction was rejected.
    errSecSigningTimeMissing = -67894,    # A signing time was expected but was not found.
    errSecTimestampSystemFailure = -67893,    # The timestamp request cannot be handled due to system failure.
    errSecTimestampAddInfoNotAvailable = -67892,    # The additional information requested is not available.
    errSecTimestampUnacceptedExtension = -67891,    # The requested extension is not supported by the Timestamp Authority.
    errSecTimestampUnacceptedPolicy = -67890,    # The requested policy is not supported by the Timestamp Authority.
    errSecTimestampTimeNotAvailable = -67889,    # The time source for the Timestamp Authority is not available.
    errSecTimestampBadDataFormat = -67888,    # The timestamp data submitted has the wrong format.
    errSecTimestampBadRequest = -67887,    # The timestamp transaction is not permitted or supported.
    errSecTimestampBadAlg = -67886,    # An unrecognized or unsupported Algorithm Identifier in timestamp.
    errSecTimestampServiceNotAvailable = -67885,    # The timestamp service is not available.
    errSecTimestampNotTrusted = -67884,    # The timestamp was not trusted.
    errSecTimestampInvalid = -67883,    # The timestamp was not valid.
    errSecTimestampMissing = -67882,    # A timestamp was expected but was not found.
    errSecExtendedKeyUsageNotCritical = -67881,    # The extended key usage extension was not marked critical.
    errSecMissingRequiredExtension = -67880,    # A required certificate extension is missing.
    errSecInvalidModifyMode = -67879,    # The modify mode is not valid.
    errSecInvalidNewOwner = -67878,    # The new owner is not valid.
    errSecInvalidIndexInfo = -67877,    # The index information is not valid.
    errSecInvalidAccessRequest = -67876,    # The access request is not valid.
    errSecInvalidDBLocation = -67875,    # The database location is not valid.
    errSecUnsupportedOperator = -67874,    # The operator is not supported.
    errSecUnsupportedNumSelectionPreds = -67873,    # The number of selection predicates is not supported.
    errSecUnsupportedQueryLimits = -67872,    # The query limits are not supported.
    errSecMissingValue = -67871,    # A missing value was detected.
    errSecDatastoreIsOpen = -67870,    # The data store is open.
    errSecDatabaseLocked = -67869,    # The database is locked.
    errSecInvalidParsingModule = -67868,    # The parsing module was not valid.
    errSecIncompatibleFieldFormat = -67867,    # The field format was incompatible.
    errSecFieldSpecifiedMultiple = -67866,    # Too many fields were specified.
    errSecUnsupportedNumRecordTypes = -67865,    # The number of record types is not supported.
    errSecUnsupportedNumIndexes = -67864,    # The number of indexes is not supported.
    errSecUnsupportedNumAttributes = -67863,    # The number of attributes is not supported.
    errSecUnsupportedLocality = -67862,    # The locality is not supported.
    errSecUnsupportedIndexInfo = -67861,    # The index information is not supported.
    errSecUnsupportedFieldFormat = -67860,    # The field format is not supported.
    errSecNoFieldValues = -67859,    # No field values were detected.
    errSecInvalidCRLIndex = -67858,    # The CRL index was not valid.
    errSecInvalidBundleInfo = -67857,    # The bundle information was not valid.
    errSecRequestDescriptor = -67856,    # The request descriptor was not valid.
    errSecInvalidRequestor = -67855,    # The requestor was not valid.
    errSecInvalidValidityPeriod = -67854,    # The validity period was not valid.
    errSecInvalidEncoding = -67853,    # The encoding was not valid.
    errSecInvalidTupleCredendtials = -67852,    # The tuple credentials are not valid.
    errSecInvalidBaseACLs = -67851,    # The base ACLs are not valid.
    errSecInvalidTupleGroup = -67850,    # The tuple group was not valid.
    errSecUnsupportedService = -67849,    # The service is not supported.
    errSecUnsupportedAddressType = -67848,    # The address type is not supported.
    errSecRequestRejected = -67847,    # The request was rejected.
    errSecRequestLost = -67846,    # The request was lost.
    errSecRejectedForm = -67845,    # The trust policy had a rejected form.
    errSecNoDefaultAuthority = -67844,    # No default authority was detected.
    errSecNotTrusted = -67843,    # The certificate was not trusted.
    errSecMultipleValuesUnsupported = -67842,    # Multiple values are not supported.
    errSecInvalidTuple = -67841,    # The tuple was not valid.
    errSecInvalidStopOnPolicy = -67840,    # The stop-on policy was not valid.
    errSecInvalidResponseVector = -67839,    # The response vector was not valid.
    errSecInvalidRequestInputs = -67838,    # The request inputs are not valid.
    errSecInvalidReason = -67837,    # The trust policy reason was not valid.
    errSecInvalidTimeString = -67836,    # The time specified was not valid.
    errSecInvalidPolicyIdentifiers = -67835,    # The policy identifiers are not valid.
    errSecInvalidIndex = -67834,    # The index was not valid.
    errSecInvalidIdentifier = -67833,    # The identifier was not valid.
    errSecInvalidID = -67832,    # The ID was not valid.
    errSecInvalidFormType = -67831,    # The form type was not valid.
    errSecInvalidCRL = -67830,    # The CRL was not valid.
    errSecInvalidCRLType = -67829,    # The CRL type was not valid.
    errSecInvalidCRLEncoding = -67828,    # The CRL encoding was not valid.
    errSecInvaldCRLAuthority = -67827,    # The CRL authority was not valid.
    errSecInvalidCertAuthority = -67826,    # The certificate authority was not valid.
    errSecVerifyActionFailed = -67825,    # A verify action has failed.
    errSecInvalidAuthority = -67824,    # The authority was not valid.
    errSecInvalidAction = -67823,    # The action was not valid.
    errSecInsufficientCredentials = -67822,    # Insufficient credentials were detected.
    errSecCertificateSuspended = -67821,    # The certificate was suspended.
    errSecCertificateRevoked = -67820,    # The certificate was revoked.
    errSecCertificateNotValidYet = -67819,    # The certificate is not yet valid.
    errSecCertificateExpired = -67818,    # An expired certificate was detected.
    errSecCertificateCannotOperate = -67817,    # The certificate cannot operate.
    errSecInvalidCRLGroup = -67816,    # An invalid CRL group was detected.
    errSecInvalidDigestAlgorithm = -67815,    # An invalid digest algorithm was detected.
    errSecAlreadyLoggedIn = -67814,    # The user is already logged in.
    errSecInvalidLoginName = -67813,    # An invalid login name was detected.
    errSecDeviceVerifyFailed = -67812,    # A device verification failure has occurred.
    errSecPublicKeyInconsistent = -67811,    # The public key was inconsistent.
    errSecBlockSizeMismatch = -67810,    # A block size mismatch occurred.
    errSecQuerySizeUnknown = -67809,    # The query size is unknown.
    errSecVerifyFailed = -67808,    # A cryptographic verification failure has occurred.
    errSecStagedOperationNotStarted = -67807,    # A staged operation was not started.
    errSecStagedOperationInProgress = -67806,    # A staged operation is in progress.
    errSecMissingAttributeWrappedKeyFormat = -67805,    # A wrapped key format attribute was missing.
    errSecInvalidAttributeWrappedKeyFormat = -67804,    # A wrapped key format attribute was not valid.
    errSecMissingAttributeSymmetricKeyFormat = -67803,    # A symmetric key format attribute was missing.
    errSecInvalidAttributeSymmetricKeyFormat = -67802,    # A symmetric key format attribute was not valid.
    errSecMissingAttributePrivateKeyFormat = -67801,    # A private key format attribute was missing.
    errSecInvalidAttributePrivateKeyFormat = -67800,    # A private key format attribute was not valid.
    errSecMissingAttributePublicKeyFormat = -67799,    # A public key format attribute was missing.
    errSecInvalidAttributePublicKeyFormat = -67798,    # A public key format attribute was not valid.
    errSecMissingAttributeAccessCredentials = -67797,    # An access credentials attribute was missing.
    errSecInvalidAttributeAccessCredentials = -67796,    # An access credentials attribute was not valid.
    errSecMissingAttributeDLDBHandle = -67795,    # A database handle attribute was missing.
    errSecInvalidAttributeDLDBHandle = -67794,    # A database handle attribute was not valid.
    errSecMissingAttributeIterationCount = -67793,    # An iteration count attribute was missing.
    errSecInvalidAttributeIterationCount = -67792,    # An iteration count attribute was not valid.
    errSecMissingAttributeSubprime = -67791,    # A subprime attribute was missing.
    errSecInvalidAttributeSubprime = -67790,    # A subprime attribute was not valid.
    errSecMissingAttributeBase = -67789,    # A base attribute was missing.
    errSecInvalidAttributeBase = -67788,    # A base attribute was not valid.
    errSecMissingAttributePrime = -67787,    # A prime attribute was missing.
    errSecInvalidAttributePrime = -67786,    # A prime attribute was not valid.
    errSecMissingAttributeVersion = -67785,    # A version attribute was missing.
    errSecInvalidAttributeVersion = -67784,    # A version attribute was not valid.
    errSecMissingAttributeEndDate = -67783,    # An end date attribute was missing.
    errSecInvalidAttributeEndDate = -67782,    # An end date attribute was not valid.
    errSecMissingAttributeStartDate = -67781,    # A start date attribute was missing.
    errSecInvalidAttributeStartDate = -67780,    # A start date attribute was not valid.
    errSecMissingAttributeEffectiveBits = -67779,    # An effective bits attribute was missing.
    errSecInvalidAttributeEffectiveBits = -67778,    # An effective bits attribute was not valid.
    errSecMissingAttributeMode = -67777,    # A mode attribute was missing.
    errSecInvalidAttributeMode = -67776,    # A mode attribute was not valid.
    errSecMissingAttributeKeyType = -67775,    # A key type attribute was missing.
    errSecInvalidAttributeKeyType = -67774,    # A key type attribute was not valid.
    errSecMissingAttributeLabel = -67773,    # A label attribute was missing.
    errSecInvalidAttributeLabel = -67772,    # A label attribute was not valid.
    errSecMissingAlgorithmParms = -67771,    # An algorithm parameters attribute was missing.
    errSecInvalidAlgorithmParms = -67770,    # An algorithm parameters attribute was not valid.
    errSecMissingAttributeRounds = -67769,    # The number of rounds attribute was missing.
    errSecInvalidAttributeRounds = -67768,    # The number of rounds attribute was not valid.
    errSecMissingAttributeOutputSize = -67767,    # An output size attribute was missing.
    errSecInvalidAttributeOutputSize = -67766,    # An output size attribute was not valid.
    errSecMissingAttributeBlockSize = -67765,    # A block size attribute was missing.
    errSecInvalidAttributeBlockSize = -67764,    # A block size attribute was not valid.
    errSecMissingAttributeKeyLength = -67763,    # A key length attribute was missing.
    errSecInvalidAttributeKeyLength = -67762,    # A key length attribute was not valid.
    errSecMissingAttributePassphrase = -67761,    # A passphrase attribute was missing.
    errSecInvalidAttributePassphrase = -67760,    # A passphrase attribute was not valid.
    errSecMissingAttributeSeed = -67759,    # A seed attribute was missing.
    errSecInvalidAttributeSeed = -67758,    # A seed attribute was not valid.
    errSecMissingAttributeRandom = -67757,    # A random number attribute was missing.
    errSecInvalidAttributeRandom = -67756,    # A random number attribute was not valid.
    errSecMissingAttributePadding = -67755,    # A padding attribute was missing.
    errSecInvalidAttributePadding = -67754,    # A padding attribute was not valid.
    errSecMissingAttributeSalt = -67753,    # A salt attribute was missing.
    errSecInvalidAttributeSalt = -67752,    # A salt attribute was not valid.
    errSecMissingAttributeInitVector = -67751,    # An init vector attribute was missing.
    errSecInvalidAttributeInitVector = -67750,    # An init vector attribute was not valid.
    errSecMissingAttributeKey = -67749,    # A key attribute was missing.
    errSecInvalidAttributeKey = -67748,    # A key attribute was not valid.
    errSecInvalidAlgorithm = -67747,    # An invalid algorithm was encountered.
    errSecInvalidContext = -67746,    # An invalid context was encountered.
    errSecInvalidOutputVector = -67745,    # The output vector is not valid.
    errSecInvalidInputVector = -67744,    # The input vector is not valid.
    errSecUnsupportedVectorOfBuffers = -67743,    # The vector of buffers is not supported.
    errSecInvalidKeyFormat = -67742,    # The key format is not valid.
    errSecUnsupportedKeyLabel = -67741,    # The key label is not supported.
    errSecInvalidKeyLabel = -67740,    # The key label is not valid.
    errSecUnsupportedKeyAttributeMask = -67739,    # The key attribute mask is not supported.
    errSecInvalidKeyAttributeMask = -67738,    # The key attribute mask is not valid.
    errSecUnsupportedKeyUsageMask = -67737,    # The key usage mask is not supported.
    errSecInvalidKeyUsageMask = -67736,    # The key usage mask is not valid.
    errSecUnsupportedKeySize = -67735,    # The key size is not supported.
    errSecUnsupportedKeyFormat = -67734,    # The key header format is not supported.
    errSecKeyHeaderInconsistent = -67733,    # The key header is inconsistent.
    errSecKeyBlobTypeIncorrect = -67732,    # The key blob type is incorrect.
    errSecKeyUsageIncorrect = -67731,    # The key usage is incorrect.
    errSecAlgorithmMismatch = -67730,    # An algorithm mismatch was encountered.
    errSecNotLoggedIn = -67729,    # You are not logged in.
    errSecAttachHandleBusy = -67728,    # The CSP handle was busy.
    errSecDeviceError = -67727,    # A device error was encountered.
    errSecPrivilegeNotSupported = -67726,    # The privilege is not supported.
    errSecOutputLengthError = -67725,    # An output length error was encountered.
    errSecInputLengthError = -67724,    # An input length error was encountered.
    errSecEventNotificationCallbackNotFound = -67723,    # An event notification callback was not found.
    errSecModuleManagerNotFound = -67722,    # A module was not found.
    errSecModuleManagerInitializeFailed = -67721,    # A module failed to initialize.
    errSecAttributeNotInContext = -67720,    # An attribute was not in the context.
    errSecInvalidSubServiceID = -67719,    # An invalid subservice ID was encountered.
    errSecModuleNotLoaded = -67718,    # A module was not loaded.
    errSecInvalidServiceMask = -67717,    # An invalid service mask was encountered.
    errSecInvalidAddinFunctionTable = -67716,    # An invalid add-in function table was encountered.
    errSecLibraryReferenceNotFound = -67715,    # A library reference was not found.
    errSecAddinUnloadFailed = -67714,    # The add-in unload operation has failed.
    errSecInvalidKeyHierarchy = -67713,    # An invalid key hierarchy was encountered.
    errSecInvalidKeyRef = -67712,    # An invalid key was encountered.
    errSecAddinLoadFailed = -67711,    # The add-in load operation has failed.
    errSecEMMUnloadFailed = -67710,    # The EMM unload has failed.
    errSecEMMLoadFailed = -67709,    # The EMM load has failed.
    errSecInvalidPVC = -67708,    # An invalid PVC was encountered.
    errSecPVCAlreadyConfigured = -67707,    # The PVC is already configured.
    errSecInvalidScope = -67706,    # An invalid scope was encountered.
    errSecPrivilegeNotGranted = -67705,    # The privilege was not granted.
    errSecIncompatibleVersion = -67704,    # An incompatible version was encountered.
    errSecInvalidSampleValue = -67703,    # An invalid sample value was encountered.
    errSecInvalidACL = -67702,    # An invalid ACL was encountered.
    errSecInvalidRecord = -67701,    # An invalid record was encountered.
    errSecInvalidAccessCredentials = -67700,    # Invalid access credentials were encountered.
    errSecACLChangeFailed = -67699,    # An ACL change operation has failed.
    errSecACLAddFailed = -67698,    # An ACL add operation has failed.
    errSecACLReplaceFailed = -67697,    # An ACL replace operation has failed.
    errSecACLDeleteFailed = -67696,    # An ACL delete operation has failed.
    errSecCallbackFailed = -67695,    # A callback has failed.
    errSecInvalidValue = -67694,    # An invalid value was detected.
    errSecInvalidQuery = -67693,    # The specified query was not valid.
    errSecTagNotFound = -67692,    # The specified tag was not found.
    errSecInvalidCertificateGroup = -67691,    # An invalid certificate group was encountered.
    errSecInvalidCertificateRef = -67690,    # An invalid certificate reference was encountered.
    errSecInvalidName = -67689,    # An invalid name was encountered.
    errSecInvalidSignature = -67688,    # An invalid signature was encountered.
    errSecUnknownTag = -67687,    # An unknown tag was encountered.
    errSecVerificationFailure = -67686,    # A verification failure occurred.
    errSecInvalidNumberOfFields = -67685,    # An invalid number of fields were encountered.
    errSecCRLAlreadySigned = -67684,    # The certificate revocation list is already signed.
    errSecInvalidNetworkAddress = -67683,    # An invalid network address was encountered.
    errSecInvalidPassthroughID = -67682,    # An invalid passthrough ID was encountered.
    errSecInvalidDBList = -67681,    # An invalid DB list was encountered.
    errSecInvalidHandle = -67680,    # An invalid handle was encountered.
    errSecInvalidGUID = -67679,    # An invalid GUID was encountered.
    errSecModuleManifestVerifyFailed = -67678,    # A module manifest verification failure has occurred.
    errSecFunctionFailed = -67677,    # A function has failed.
    errSecSelfCheckFailed = -67676,    # Self-check has failed.
    errSecInvalidPointer = -67675,    # An invalid pointer was encountered.
    errSecMDSError = -67674,    # A Module Directory Service error has occurred.
    errSecInvalidData = -67673,    # Invalid data was encountered.
    errSecMemoryError = -67672,    # A memory error has occurred.
    errSecInternalError = -67671,    # An internal error has occurred.
    errSecFunctionIntegrityFail = -67670,    # A function address was not within the verified module.
    errSecPVCReferentNotFound = -67669,    # A reference to the calling module was not found in the list of authorized callers.
    errSecInvalidHandleUsage = -67668,    # The CSSM handle does not match with the service type.
    errSecNotInitialized = -67667,    # A function was called without initializing CSSM.
    errSecMobileMeFailedConsistencyCheck = -67666,
    errSecMobileMeCSRVerifyFailure = -67665,
    errSecMobileMeNoRequestPending = -67664,
    errSecMobileMeRequestAlreadyPending = -67663,
    errSecMobileMeServerServiceErr = -67662,
    errSecMobileMeServerAlreadyExists = -67661,
    errSecMobileMeServerNotAvailable = -67660,
    errSecMobileMeServerError = -67659,
    errSecMobileMeRequestRedirected = -67658,
    errSecMobileMeRequestQueued = -67657,
    errSecUnknownQualifiedCertStatement = -67656,    # An unknown qualified certificate statement was encountered.
    errSecInvalidSubjectName = -67655,    # An invalid certificate subject name was encountered.
    errSecTrustSettingDeny = -67654,    # The trust setting for this policy was set to Deny.
    errSecResourceSignBadExtKeyUsage = -67653,    # Resource signing has encountered an error in the extended key usage.
    errSecResourceSignBadCertChainLength = -67652,    # Resource signing has encountered an incorrect certificate chain length.
    errSecCodeSigningDevelopment = -67651,    # Code signing indicated use of a development-only certificate.
    errSecCodeSigningNoExtendedKeyUsage = -67650,    # Code signing found no extended key usage.
    errSecCodeSigningBadPathLengthConstraint = -67649,    # Code signing encountered an incorrect path length constraint.
    errSecCodeSigningNoBasicConstraints = -67648,    # Code signing found no basic constraints.
    errSecCodeSigningBadCertChainLength = -67647,    # Code signing encountered an incorrect certificate chain length.
    errSecOCSPResponseNonceMismatch = -67646,    # The OCSP response nonce did not match the request.
    errSecOCSPResponderUnauthorized = -67645,    # The OCSP responder rejected this request as unauthorized.
    errSecOCSPResponderSignatureRequired = -67644,    # The OCSP responder requires a signature.
    errSecOCSPResponderTryLater = -67643,    # The OCSP responder is busy, try again later.
    errSecOCSPResponderInternalError = -67642,    # The OCSP responder encountered an internal error.
    errSecOCSPResponderMalformedReq = -67641,    # The OCSP responder was given a malformed request.
    errSecOCSPNoSigner = -67640,    # The OCSP response had no signer.
    errSecOCSPSignatureError = -67639,    # The OCSP response had an invalid signature.
    errSecRecordModified = -67638,    # The record was modified.
    errSecOCSPNotTrustedToAnchor = -67637,    # The OCSP response was not trusted to a root or anchor certificate.
    errSecNetworkFailure = -67636,    # A network failure occurred.
    errSecIncompleteCertRevocationCheck = -67635,    # An incomplete certificate revocation check occurred.
    errSecEndOfData = -67634,    # An end-of-data was detected.
    errSecOCSPStatusUnrecognized = -67633,    # The OCSP server did not recognize this certificate.
    errSecOCSPUnavailable = -67632,    # OCSP service is unavailable.
    errSecOCSPBadRequest = -67631,    # The OCSP request was incorrect or could not be parsed.
    errSecOCSPBadResponse = -67630,    # The OCSP response was incorrect or could not be parsed.
    errSecSSLBadExtendedKeyUsage = -67629,    # The appropriate extended key usage for SSL was not found.
    errSecSMIMESubjAltNameNotCritical = -67628,    # The subject alternative name extension is not marked as critical.
    errSecSMIMENoEmailAddress = -67627,    # No email address was found in the certificate.
    errSecSMIMEKeyUsageNotCritical = -67626,    # The key usage extension is not marked as critical.
    errSecSMIMEBadKeyUsage = -67625,    # The key usage is not compatible with SMIME.
    errSecSMIMEBadExtendedKeyUsage = -67624,    # The appropriate extended key usage for SMIME was not found.
    errSecSMIMEEmailAddressesNotFound = -67623,    # An email address mismatch was encountered.
    errSecIDPFailure = -67622,    # The issuing distribution point was not valid.
    errSecCRLPolicyFailed = -67621,    # The CRL policy failed.
    errSecCRLNotTrusted = -67620,    # The CRL is not trusted.
    errSecUnknownCRLExtension = -67619,    # An unknown CRL extension was encountered.
    errSecUnknownCertExtension = -67618,    # An unknown certificate extension was encountered.
    errSecCRLBadURI = -67617,    # The CRL has a bad Uniform Resource Identifier.
    errSecCRLServerDown = -67616,    # The CRL server is down.
    errSecCRLNotFound = -67615,    # The CRL was not found.
    errSecCRLNotValidYet = -67614,    # The CRL is not yet valid.
    errSecCRLExpired = -67613,    # The CRL has expired.
    errSecInvalidRoot = -67612,    # The root or anchor certificate is not valid.
    errSecPathLengthConstraintExceeded = -67611,    # The path length constraint was exceeded.
    errSecInvalidIDLinkage = -67610,    # The ID linkage is not valid.
    errSecInvalidExtendedKeyUsage = -67609,    # The extended key usage is not valid.
    errSecInvalidKeyUsageForPolicy = -67608,    # The key usage is not valid for the specified policy.
    errSecInvalidSubjectKeyID = -67607,    # The subject key ID is not valid.
    errSecInvalidAuthorityKeyID = -67606,    # The authority key ID is not valid.
    errSecNoBasicConstraintsCA = -67605,    # No basic CA constraints were found.
    errSecNoBasicConstraints = -67604,    # No basic constraints were found.
    errSecUnknownCriticalExtensionFlag = -67603,    # There is an unknown critical extension flag.
    errSecHostNameMismatch = -67602,    # A host name mismatch has occurred.
    errSecIncompatibleKeyBlob = -67601,    # The specified database has an incompatible key blob.
    errSecIncompatibleDatabaseBlob = -67600,    # The specified database has an incompatible blob.
    errSecInvalidKeyBlob = -67599,    # The specified database has an invalid key blob.
    errSecInvalidDatabaseBlob = -67598,    # The specified database has an invalid blob.
    errSecFileTooBig = -67597,    # The file is too big.
    errSecQuotaExceeded = -67596,    # The quota was exceeded.
    errSecAppleSSLv2Rollback = -67595,    # A SSLv2 rollback error has occurred.
    errSecConversionError = -67594,    # A conversion error has occurred.
    errSecAppleInvalidKeyEndDate = -67593,    # The specified key has an invalid end date.
    errSecAppleInvalidKeyStartDate = -67592,    # The specified key has an invalid start date.
    errSecAppleSignatureMismatch = -67591,    # A signature mismatch has occurred.
    errSecApplePublicKeyIncomplete = -67590,    # The public key is incomplete.
    errSecAppleAddAppACLSubject = -67589,    # Adding an application ACL subject failed.
    errSecDeviceFailed = -67588,    # A device failure has occurred.
    errSecDeviceReset = -67587,    # A device reset has occurred.
    errSecInsufficientClientID = -67586,    # The client ID is not correct.
    errSecServiceNotAvailable = -67585,    # The required service is not available.

    errSecMissingEntitlement = -34018,    # A required entitlement isn't present.

    errSecDecode = -26275,    # Unable to decode the provided data.

    errSecNotSigner = -26267,    # A certificate was not signed by its proposed parent.

    errSecInDarkWake = -25320,    # In dark wake, no UI possible
    errSecInvalidPrefsDomain = -25319,    # The specified preferences domain is not valid.
    errSecCreateChainFailed = -25318,    # One or more certificates required to validate this certificate cannot be found.
    errSecDataNotModifiable = -25317,    # The contents of this item cannot be modified.
    errSecDataNotAvailable = -25316,    # The contents of this item cannot be retrieved.
    errSecInteractionRequired = -25315,    # User interaction is required, but is currently not allowed.
    errSecNoPolicyModule = -25314,    # A required component (policy module) could not be loaded. You may need to restart your computer.
    errSecNoCertificateModule = -25313,    # A required component (certificate module) could not be loaded. You may need to restart your computer.
    errSecNoStorageModule = -25312,    # A required component (data storage module) could not be loaded. You may need to restart your computer.
    errSecKeySizeNotAllowed = -25311,    # This item specifies a key size which is too large or too small.
    errSecWrongSecVersion = -25310,    # This keychain was created by a different version of the system software and cannot be opened.
    errSecReadOnlyAttr = -25309,    # The specified attribute could not be modified.
    errSecInteractionNotAllowed = -25308,    # User interaction is not allowed.
    errSecNoDefaultKeychain = -25307,    # A default keychain could not be found.
    errSecNoSuchClass = -25306,    # The specified item does not appear to be a valid keychain item.
    errSecInvalidSearchRef = -25305,    # Unable to search the current keychain.
    errSecInvalidItemRef = -25304,    # The specified item is no longer valid. It may have been deleted from the keychain.
    errSecNoSuchAttr = -25303,    # The specified attribute does not exist.
    errSecDataTooLarge = -25302,    # This item contains information which is too large or in a format that cannot be displayed.
    errSecBufferTooSmall = -25301,    # There is not enough memory available to use the specified item.
    errSecItemNotFound = -25300,    # The specified item could not be found in the keychain.
    errSecDuplicateItem = -25299,    # The specified item already exists in the keychain.
    errSecInvalidCallback = -25298,    # The specified callback function is not valid.
    errSecDuplicateCallback = -25297,    # The specified callback function is already installed.
    errSecDuplicateKeychain = -25296,    # A keychain with the same name already exists.
    errSecInvalidKeychain = -25295,    # The specified keychain is not a valid keychain file.
    errSecNoSuchKeychain = -25294,    # The specified keychain could not be found.
    errSecAuthFailed = -25293,    # The user name or passphrase you entered is not correct.
    errSecReadOnly = -25292,    # This keychain cannot be modified.
    errSecNotAvailable = -25291,    # No keychain is available. You may need to restart your computer.

    errSecPkcs12VerifyFailure = -25264,    # MAC verification failed during PKCS12 import (wrong password?)
    errSecNoTrustSettings = -25263,    # No Trust Settings were found.
    errSecInvalidTrustSettings = -25262,    # The Trust Settings Record was corrupted.
    errSecInvalidPasswordRef = -25261,    # The password reference was invalid.
    errSecPassphraseRequired = -25260,    # Passphrase is required for import/export.
    errSecMultiplePrivKeys = -25259,    # An attempt was made to import multiple private keys.
    errSecKeyIsSensitive = -25258,    # Key material must be wrapped for export.
    errSecUnknownFormat = -25257,    # Unknown format in import.
    errSecUnsupportedFormat = -25256,    # Import/Export format unsupported.
    errSecTrustNotAvailable = -25245,    # No trust results are available.
    errSecInvalidOwnerEdit = -25244,    # Invalid attempt to change the owner of this item.
    errSecNoAccessForItem = -25243,    # The specified item has no access control.
    errSecInvalidTrustSetting = -25242,    # The specified trust setting is invalid.
    errSecPolicyNotFound = -25241,    # The specified policy cannot be found.
    errSecACLNotSimple = -25240,    # The specified access control list is not in standard (simple) form.

    errSecCoreFoundationUnknown = -4960,
    errSecInternalComponent = -2070,
    errSecBadReq = -909,    # Bad parameter or invalid state for operation.
    errSecUserCanceled = -128,    # User canceled the operation.
    errSecAllocate = -108,    # Failed to allocate memory.
    errSecWrPerm = -61,     # Write permissions error.
    errSecParam = -50,     # One or more parameters passed to a function were not valid.
    errSecOpWr = -49,     # File already open with write permission.
    errSecIO = -36,     # I/O error.
    errSecDiskFull = -34,     # The disk is full.
    errSecUnimplemented = -4,      # Function or operation not implemented.
    errSecSuccess = 0,       # No error.

  KeychainStatus* = enum
    kSecUnlockStateStatus        = 1
    kSecReadPermStatus           = 2
    kSecWritePermStatus          = 4

# Following are key for the CFDictionary used in adding/finding/deleting items from the keyring
var
  kSecClass* {.importc.}: CFStringRef
  kSecValueData* {.importc.}: CFStringRef
  kSecClassGenericPassword* {.importc.} : CFStringRef
  kSecClassInternetPassword* {.importc.} : CFStringRef
  kSecClassCertificate* {.importc.} : CFStringRef
  kSecClassKey* {.importc.} : CFStringRef
  kSecClassIdentity* {.importc.} : CFStringRef

# kSecClassGenericPassword item attributes:
var
  # kSecAttrAccess (OS X only)
  # kSecAttrAccessControl
  # kSecAttrAccessGroup (iOS; also OS X if kSecAttrSynchronizable and/or kSecUseDataProtectionKeychain set)
  # kSecAttrAccessible (iOS; also OS X if kSecAttrSynchronizable and/or kSecUseDataProtectionKeychain set)
  # kSecAttrCreationDate
  # kSecAttrModificationDate
  # kSecAttrDescription
  # kSecAttrComment
  # kSecAttrCreator
  # kSecAttrType
  # kSecAttrLabel
  # kSecAttrIsInvisible
  # kSecAttrIsNegative
  kSecAttrAccount* {.importc.} : CFStringRef
  kSecAttrService* {.importc.} : CFStringRef
  # kSecAttrGeneric
  # kSecAttrSynchronizable

# Query keys:
var
  kSecReturnData* {.importc.} : CFStringRef
  kSecMatchLimit* {.importc.} : CFStringRef
  kSecMatchLimitOne* {.importc.} : CFStringRef

proc SecItemAdd*(attributes:CFDictionaryRef, res:pointer):OSStatus {.importc.}
proc SecItemUpdate*(query: CFDictionaryRef, attributesToUpdate: CFDictionaryRef): OSStatus {.importc.}
proc SecItemCopyMatching*(query: CFDictionaryRef, res: ptr CFTypeRef): OSStatus {.importc.}
proc SecItemDelete*(query: CFDictionaryRef): OSStatus {.importc.}
