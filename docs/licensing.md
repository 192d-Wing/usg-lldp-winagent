# Licensing

- **WinLLDP** is MIT licensed (see LICENSE).
- **WiX Toolset v7** is used to build the MSI. WiX v7 adopts the Open
  Source Maintenance Fee v1.1, which applies to organizations with more
  than US$10,000 in annual revenue that use WiX to generate revenue. This
  project does not generate revenue, so the fee does not apply. WiX v7
  still requires one-time EULA acceptance on each build machine
  (`wix eula accept wix7`); the CI workflows do this.
  Reference: https://docs.firegiant.com/wix/osmf/
- **Npcap** is not redistributed. It is a deployment prerequisite that the
  organization installs under Npcap's own license terms. The Npcap free
  edition permits internal use; redistribution inside another product
  would require the Npcap OEM Redistribution License, which this project
  deliberately avoids by not bundling Npcap.
  Reference: https://npcap.com/oem/
- **Rust crates**: licenses are checked in CI with `cargo deny` against
  the allow list in `deny.toml` (MIT, Apache-2.0, BSD, ISC, Zlib,
  Unicode). A CycloneDX SBOM is attached to every release.
- **Standards**: IEEE 802.1AB-2016 is available at no cost through the
  IEEE GET Program. No IEEE text is reproduced in this repository.
