import options
export options
import dbus
import tables

const
  SS_PREFIX = "org.freedesktop.Secret."
  SS_PATH = "/org/freedesktop/secrets"
  BUS_NAME = "org.freedesktop.secrets"
  SERVICE_INTERFACE = SS_PREFIX & "Service"
  COLLECTION_INTERFACE = SS_PREFIX & "Collection"
  ITEM_INTERFACE = SS_PREFIX & "Item"
  DEFAULT_COLLECTION = "/org/freedesktop/secrets/aliases/default"


# References:
#   https://specifications.freedesktop.org/secret-service/latest/
#   https://specifications.freedesktop.org/secret-service/latest/ch14.html#type-Secret
#   https://github.com/mitya57/secretstorage

# Docker Instructions (https://georgik.rocks/how-to-start-d-bus-in-docker-container/)
# docker run --rm -it --cap-add ipc_lock -v $(pwd):/code -w /code nimlang/nim /bin/bash
# const BASIC = """
# nimble install -y c2nim
# nimble install -y https://github.com/iffy/nim-dbus.git

# apt-get update -q && apt-get install -y dbus libdbus-1-dev gnome-keyring
# dbus-run-session -- bash
# echo '' | gnome-keyring-daemon --unlock
# """

proc toByteArray(s:string):seq[uint8] =
  for c in s:
    result.add(ord(c).uint8)

proc dbusByteArrayToString(d: DbusValue):string =
  assert d.kind == dtArray
  for item in d.arrayValue:
    result.add(char(item.asNative(uint8)))

proc `$`(objpath:ObjectPath):string =
  cast[string](objpath)

proc call(bus: Bus, msg: Message):seq[DbusValue] = 
  let pending = bus.sendMessageWithReply(msg)
  let reply = pending.waitForReply()
  if reply.type == rtError:
    case reply.errorName
    of "org.freedesktop.DBus.Error.ServiceUnknown":
      raise newException(CatchableError, "No SecretService backend available.")
  reply.raiseIfError()
  var it = reply.iterate()
  while true:
    result.add(it.unpackCurrent(DbusValue))
    try:
      it.advanceIter()
    except:
      break

proc openSession(bus:Bus): ObjectPath =
  var msg = makeCall(
    BUS_NAME,
    ObjectPath(SS_PATH),
    SERVICE_INTERFACE,
    "OpenSession",
  )
  msg.append("plain")
  msg.append(newVariant[string](""))
  let open_result = bus.call(msg)
  result = open_result[^1].objectPathValue
  assert $result != ""

proc unlock(bus:Bus, thing:ObjectPath) =
  var unlock_msg = makeCall(
    BUS_NAME,
    ObjectPath(SS_PATH),
    SERVICE_INTERFACE,
    "Unlock",
  )
  unlock_msg.append(@[thing])
  let unlock_result = bus.call(unlock_msg)
  assert $(unlock_result[0].arrayValue[0].objectPathValue) == $thing
  assert $(unlock_result[1].objectPathValue) == "/" # special value indicating no prompt needed

proc setPassword*(service: string, username: string, password: string) {.gcsafe.} =
  ## Save a password in the OS keychain
  let label = service & ":" & username
  let bus = getBus(dbus.DBUS_BUS_SESSION)
  let session_object_path = bus.openSession()
  bus.unlock(ObjectPath(DEFAULT_COLLECTION))
  
  var create_msg = makeCall(
    BUS_NAME,
    ObjectPath(DEFAULT_COLLECTION),
    COLLECTION_INTERFACE,
    "CreateItem",
  )
  var outer = DbusValue(
    kind: dtArray,
    arrayValueType: DbusType(
      kind: dtDictEntry,
      keyType: dtString,
      valueType: dtVariant,
    )
  )
  outer.add(
    (SS_PREFIX & "Item.Label").asDbusValue(),
    newVariant(label).asDbusValue()
  )
  var inner = DbusValue(
    kind: dtArray,
    arrayValueType: DbusType(
      kind: dtDictEntry,
      keyType: dtString,
      valueType: dtString,
    )
  )
  inner.add("service".asDbusValue(), service.asDbusValue())
  inner.add("username".asDbusValue(), username.asDbusValue())
  outer.add(
    (SS_PREFIX & "Item.Attributes").asDbusValue(),
    newVariant(inner).asDbusValue()
  )
  create_msg.append(outer)
  # TODO: this is where in-transit encryption would happen
  create_msg.append(
    DbusValue(kind: dtStruct, structValues: @[
      session_object_path.asDbusValue(),
      "".toByteArray().asDbusValue(),
      password.toByteArray().asDbusValue(),
      "text/plain".asDbusValue(),
    ])
  )
  # create_msg.append(password)
  create_msg.append(true)
  discard bus.call(create_msg)

proc getPassword*(service: string, username: string): Option[string] {.gcsafe.} =
  ## Retrieve a previously-saved password from the OS keychain
  let bus = getBus(dbus.DBUS_BUS_SESSION)
  let session_object_path = bus.openSession()
  bus.unlock(ObjectPath(DEFAULT_COLLECTION))

  # SearchItems
  var search_msg = makeCall(
    BUS_NAME,
    ObjectPath(DEFAULT_COLLECTION),
    COLLECTION_INTERFACE,
    "SearchItems",
  )
  var attrs = {
    "service": service,
    "username": username,
  }.toTable()
  search_msg.append(attrs)
  var found_item_path:ObjectPath
  try:
    let search_result = bus.call(search_msg)
    assert search_result[0].kind == dtArray
    assert search_result[0].arrayValue.len > 0
    found_item_path = search_result[0].arrayValue[0].objectPathValue
  except:
    return none[string]()

  # unlock and retrieve
  bus.unlock(found_item_path)
  var get_msg = makeCall(
    BUS_NAME,
    found_item_path,
    ITEM_INTERFACE,
    "GetSecret",
  )
  get_msg.append(session_object_path)
  try:
    let get_result = bus.call(get_msg)
    let secret = get_result[0]
    assert secret.kind == dtStruct
    return some[string](dbusByteArrayToString(secret.structValues[2]))
  except:
    return none[string]()

proc deletePassword*(service: string, username: string) {.gcsafe.} =
  ## Delete a saved password (if it exists)
  let bus = getBus(dbus.DBUS_BUS_SESSION)
  discard bus.openSession()
  bus.unlock(ObjectPath(DEFAULT_COLLECTION))

  # SearchItems
  var search_msg = makeCall(
    BUS_NAME,
    ObjectPath(DEFAULT_COLLECTION),
    COLLECTION_INTERFACE,
    "SearchItems",
  )
  var attrs = {
    "service": service,
    "username": username,
  }.toTable()
  search_msg.append(attrs)
  var found_item_path:ObjectPath
  let search_result = bus.call(search_msg)
  assert search_result[0].kind == dtArray
  assert search_result[0].arrayValue.len > 0
  let val0 = search_result[0].arrayValue[0]
  if val0.kind != dtObjectPath:
    # not found
    return
  found_item_path = val0.objectPathValue

  # unlock and delete
  bus.unlock(found_item_path)
  var get_msg = makeCall(
    BUS_NAME,
    found_item_path,
    ITEM_INTERFACE,
    "Delete",
  )
  discard bus.call(get_msg)
