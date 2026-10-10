# WinLLDP roadmap

Work that is known and not yet done. Completed work and its evidence are in
docs/standards-compliance.md.

## Unverified decoders

Two sets of received TLVs are decoded from an understanding of their
formats that has not been checked against the defining standard. Both are
display-only: WinLLDP never transmits them, the raw TLV is always kept, and
a wrong decoder can mislabel or misread a field in `winlldp neighbors
--detail` and the JSON output but cannot affect the protocol or cause a
frame to be rejected.

Until each is checked, the code carries a `verify` note and the fields
should not be relied on.

### 1. IEEE 802.1 Link Aggregation TLV

- What: OUI 00-80-C2, subtype 7. Decoded in
  `crates/lldp-codec/src/org/ieee8021.rs` (`LinkAggregation`) as a status
  octet (bit 0 capable, bit 1 aggregated) and a 4-octet aggregated port ID.
- Why it is open: IEEE Std 802.1Q-2022 Annex D lists the subtype but
  refers to IEEE Std 802.1AX for the format. The layout used is that of the
  deprecated IEEE 802.3 Link Aggregation TLV (802.3-2022 79.3.3), which was
  checked. 802.1AX may define further bits in the status octet (a port
  type), which would currently be ignored.
- Needed: IEEE Std 802.1AX (the annex that defines the Link Aggregation
  TLV). It is in the IEEE GET Program.
- To close: compare the field layout and any usage rules, decode whatever
  the status octet carries beyond the two bits, add tests, and remove the
  `verify` note from the module comment and from
  docs/standards-compliance.md section 4.2.
- Lab: not exercised. The Cisco switch in the lab did not send this TLV on
  an access port; a port in a port channel would.

### 2. LLDP-MED TLVs

- What: OUI 00-12-BB, decoded in `crates/lldp-codec/src/org/med.rs`:
  Capabilities (1), Network Policy (2), Location Identification (3),
  Extended Power via MDI (4), and the inventory TLVs: hardware, firmware,
  and software revision, serial number, manufacturer, model, asset ID
  (5 to 11).
- Why it is open: the formats are defined in ANSI/TIA-1057, which has not
  been available. Nothing in this decoder has been compared with the text.
  In particular the Extended Power via MDI priority is read as four bits;
  the equivalent IEEE 802.3 field turned out to be two bits when checked,
  so this one deserves a look first.
- Needed: ANSI/TIA-1057. It is a TIA standard and is not in the IEEE GET
  Program.
- To close: check each subtype's layout, bit fields, and length rules,
  correct the decoder, add tests, and remove the `verify` note from the
  module comment and from docs/standards-compliance.md.
- Lab: not exercised. The switch sends LLDP-MED only to a neighbor that
  advertises it, and WinLLDP does not.
