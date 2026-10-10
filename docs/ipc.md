# Local IPC Contract (version 1)

Transport: Windows named pipe `\\.\pipe\WinLLDP`, byte mode, local
clients only. Security descriptor: SYSTEM and Administrators full control;
the configured read group (default Authenticated Users, `ipc.read_group`)
`FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES |
FILE_WRITE_EA` (`0x12019B`). That is read and write without
`FILE_CREATE_PIPE_INSTANCE`, so no member of the read group can create an
instance of the pipe and answer other clients in the service's place. The
first instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so the
service fails to start its IPC if another process already owns the name.
Clients open the pipe with `SECURITY_IDENTIFICATION`, so a server at that
name can learn who the client is but cannot act as the client.

Framing: each message is a 4-byte big-endian unsigned length followed by
one UTF-8 JSON object. A request is at most 64 KiB (`MAX_REQUEST_LEN`);
a response is at most 8 MiB (`MAX_MESSAGE_LEN`). A client sends one
request and reads one response; a connection may carry many
request/response pairs in sequence.

Limits for untrusted local clients: at most 32 connections are served at a
time (further connections are closed immediately), and a connection that
sends no request for 30 seconds is closed. Each neighbor keeps at most 64
optional TLVs and 4 KiB of organizationally specific and unknown TLV data
(`lldp-core::neighbor`), which bounds the size of `ListNeighbors`.

## Request

```json
{"v": 1, "op": "<Operation>", "params": { ... }}
```

`params` is omitted when the operation takes none. Unknown members are
rejected.

| Operation | Params | Admin | Result |
| --- | --- | --- | --- |
| `GetServiceStatus` | none | no | `ServiceStatus` |
| `ListInterfaces` | none | no | `Interface[]` |
| `GetInterfaceStatus` | `interface` | no | `Interface` or null |
| `ListNeighbors` | `interface?` | no | `Neighbor[]` |
| `GetNeighborDetails` | `interface`, `chassis_id`, `port_id` | no | `Neighbor` |
| `GetLocalAdvertisement` | `interface?` | no | `LocalAdvertisement[]` |
| `GetStatistics` | `interface?` | no | `Statistics[]` |
| `SetInterfaceMode` | `interface`, `mode` (`disabled`, `rx_only`, `tx_only`, `rx_tx`) | yes | `{changed: string[], mode}` |
| `ReloadConfiguration` | none | yes | `{requested: true}` |

`interface` accepts an alias (case-insensitive) or an adapter GUID with or
without braces.

"Admin" operations require that the client's token holds the local
Administrators group enabled, which means an elevated process. The service
verifies this per connection with `ImpersonateNamedPipeClient` and
`CheckTokenMembership`.

## Response

```json
{"v": 1, "ok": true, "result": ...}
{"v": 1, "ok": false, "error": {"code": "forbidden", "message": "..."}}
```

Error codes: `unsupported_version`, `bad_request`, `forbidden`,
`interface_not_found`, `neighbor_not_found`, `invalid_configuration`,
`internal`.

## Types

The authoritative definitions are the `serde` structs in
`crates/lldp-ipc/src/view.rs`. Summary:

- `ServiceStatus`: `version`, `uptime_secs`, `npcap_version`,
  `backend_status`, `config_path`, `config_loaded_unix`, `policy_applied`,
  `interfaces_known`, `interfaces_managed`, `neighbors_total`,
  `system_name`, `chassis_id`.
- `Interface`: `guid`, `alias`, `description`, `mac`, `if_index`, `kind`
  (`physical_ethernet`, `wifi`, `virtual`, `other`), `connected`,
  `link_speed`, `mode`, `managed`, `neighbors`, `addresses[]`.
- `Lldpdu` (embedded in `Neighbor` and `LocalAdvertisement`):
  `chassis_id {subtype, subtype_name, value, hex}`, `port_id {...}`, `ttl`,
  `port_description`, `system_name`, `system_description`,
  `capabilities {supported[], enabled[], short}`,
  `management_addresses[] {address, family, interface_numbering,
  interface_number, oid_hex}`, `org_tlvs[] {oui, organization, subtype,
  decoded, data_hex}`, `unknown_tlvs[] {tlv_type, value_hex}`.
- `Neighbor`: `interface_guid`, `interface_alias`, `scope`, `source_mac`,
  `ttl_remaining`, `first_seen_unix`, `last_seen_unix`, `expires_unix`,
  `frames`, plus the `Lldpdu` members (`ttl` is the advertised TTL).
- `LocalAdvertisement`: `interface_guid`, `interface_alias`, `mode`,
  `destination_mac`, `source_mac`, `lldpdu_hex`, plus the `Lldpdu` members.
- `Statistics`: the `lldpStatsRx/TxPort*` counters (including
  `tx_lldpdu_length_errors`) plus `rem_inserts`, `rem_deletes`,
  `rem_drops`, `rx_queue_overflow`. `Interface` has `too_many_neighbors` (the 802.1AB variable). `rx_frames_total` counts every LLDP
  frame received, including those then discarded.

`decoded` for organizational TLVs is an object with a `type` member naming
the TLV (for example `port_vlan_id`, `mac_phy_configuration_status`,
`network_policy`) and TLV-specific fields. Unknown OUIs have `decoded: null`
and the raw `data_hex`.

## Versioning

`v` is incremented only for incompatible changes. Adding a result member
or a new operation is compatible. Clients must ignore unknown result
members.

## Deferred

Event subscriptions (push notifications of neighbor and interface
changes) are not part of version 1. Poll `ListNeighbors`; `winlldp debug`
does this at a configurable interval.
