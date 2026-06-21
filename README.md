# Passy: Flipper Zero Passport Reader

**Passy** is a tool for reading electronic passports (ePassports/eMRTDs) using the Flipper Zero device. It extracts and decodes data securely stored in modern passports, designed for hobbyists, researchers, and security professionals.

---

## Features

- Reads and decodes ePassport data from a wide range of countries
- Utilizes MRZ (Machine Readable Zone) information for secure access
- Extensible for new country support—contribute your flag!
- Advanced menu for debugging and exploring additional data groups (DGs)

---

## Tested with the following countries

🇺🇸
🇵🇱
🇨🇱
🇫🇷
🇬🇧
🇵🇭
🇷🇺
🇹🇼
🇺🇦
🇦🇿
🇨🇦
🇮🇹
🇪🇸
🇪🇪
🇨🇭
🇦🇺
🇭🇰
🇦🇹
🇳🇱
🇬🇪
🇰🇷
🇨🇳
🇸🇬
🇧🇩
🇧🇬
🇯🇵
🇬🇷
🇨🇷
🇹🇷
🇲🇽
🇷🇸
🇹🇭
🇫🇮

*If it works for yours, submit a PR to add your country flag!*

---

## Usage

eMRTDs are secured to prevent unauthorized reading. The key for accessing the data is derived from:

- Passport number
- Date of birth
- Date of expiry

**Use the Flipper Zero to scan your passport’s NFC chip and enter the required information.**

---

## Limitations

- Advanced menu is hidden unless Debug mode is enabled
- Some data groups (DGs) are not fully parsed under "advanced" menu
- Country coverage is limited (see above)

---

## Development

### Prerequisites

- Flipper Zero device (updated firmware recommended)
- [ufbt](https://github.com/flipperdevices/flipperzero-ufbt) for building
- [asn1c](https://github.com/vlm/asn1c) ASN.1 compiler (for protocol/data parsing)

### Installation

Clone this repository:

```bash
git clone https://github.com/bettse/passy.git
cd passy
```

Build the ASN.1 code (optional, required for development):

```bash
asn1c -D ./lib/asn1 -no-gen-example -pdu=all eMRTD.asn1
```

---

## PACE Authentication & Deep Scanning (v2.0)

A massive overhaul to Passy was contributed by **honey181**. This update brings the app into the modern era:
- **Full PACE Authentication:** Added support for the PACE protocol using Brainpool cryptographic curves, allowing Passy to read modern passports and national IDs that completely reject the legacy BAC protocol.
- **Deep Scanner ("Dump All"):** A robust 31-file deep scanner that seamlessly sweeps the entire theoretical eMRTD filesystem (0x0101 to 0x011F), grabbing undocumented files while safely ignoring dead links without breaking the Secure Messaging connection.
- **Unified Dumps:** All files and images (like DG2 facial data and DG7 signature data) are now cleanly extracted and saved to `/ext/apps_data/passy/dumps/<passport_number>/`.

*Note: PACE authentication and the Deep Scanner have been heavily tested exclusively against Polish National IDs (eID) 🇵🇱. Compatibility with other modern eMRTDs may vary based on specific curve support. If it works for your country's modern ID, let us know!*

---

## Roadmap / To Do

- [x] Support PACE protocol (Added in v2.0 by honey181)
- [ ] Add support for more countries' passports
- [ ] Improve parsing of additional DGs

---

## Contributing

Contributions are welcome! If Passy works with a new country, feel free to:

1. Add your country’s flag to the list above
2. Submit a pull request

---

## License

[MIT License](LICENSE)

---

## Acknowledgments

- Inspired by the global ePassport community
- Powered by Flipper Zero and open-source tooling
