# Signing-key reference data

> **Warning: this certificate list is preliminary.** Coverage and freshness are
> not guaranteed, and the inferred entries have not been confirmed by Epic.

Researched on 2026-11-06. `certs/keys.tsv` is an independently researched set of
public X.509 certificates associated with the vendors named in [Epic's Linux v2
announcement](https://onlineservices.epicgames.com/news/introducing-easy-anti-cheat-linux-v2).
Epic names vendors, but does not publish certificate fingerprints or its complete
key allowlist there. These are **candidate vendor keys, not an official Epic
allowlist**. A match does not establish that a particular game enables Linux v2
or that Epic currently accepts that certificate.

## What is included

All files contain public certificates only. The SHA-256 fingerprint is over the
DER-encoded certificate, rather than its PEM text. Fingerprints and subject key
identifiers (SKIs) are lowercase hexadecimal without separators. `role` describes
the certificate's established use; `ca` is a trust anchor and does not mean its
private key directly signs every kernel. Sources in the registry are pinned to
Git commits where available, and every certificate was parsed with OpenSSL.

| Vendor named by Epic | Bundled certificate | Evidence and scope |
| --- | --- | --- |
| Canonical | `canonical-uefi-ca.pem` | Canonical's [vendor-owned shim submission](https://github.com/canonical/shim-review/tree/33a5ddb3ffec66857f133a046d23b09dd2af943d) contains this CA. Current [Ubuntu security documentation](https://documentation.ubuntu.com/security/security-features/platform-protections/secure-boot/) describes the Canonical key embedded in shim and signed official kernels/modules. This establishes the vendor trust root; a current per-release leaf signer was not independently collected. |
| Fedora | `fedora-ca-20200709.pem` | The [accepted Fedora shim review](https://github.com/rhboot/shim-review/issues/495) links the [review submission](https://github.com/vathpela/shim-review/tree/9c80b35fead24ecfa4ef5e772413135f72ed1b70), whose README explicitly identifies this vendor CA. It also says Fedora uses ephemeral module-signing keys. No single current default-kernel leaf/module certificate covering all Fedora builds is asserted. The submission is for aarch64; it establishes Fedora's CA identity, not exhaustive architecture coverage. |
| Universal Blue | `ublue-public-key.pem`, `ublue-public-key-2.pem` | These are the actual `ublue kernel` and older `ublue akmods` certificates in the [official akmods repository](https://github.com/ublue-os/akmods/tree/16e5137ab2abf193d10578b6d4fbf9f8c590fde9/certs). The official [main image build's `secureboot` recipe](https://github.com/ublue-os/main/blob/main/Justfile) downloads both and runs `sbverify --cert` against the image's `vmlinuz`. This is direct kernel-signing evidence. Different images can retain Fedora kernels or use a different kernel stream; these two keys do not establish every Universal Blue image's signer. |
| Debian | `debian-uefi-ca.pem`, `debian-prod-2022-linux.pem` | The CA comes from Debian's [2026 Debian 13 shim submission](https://github.com/steve-mcintyre/shim-review/tree/6ead6d6c6ea9192bbf6d0d108d50923b6d5a5eac). The direct Linux signer is still in the Debian FTP team's [active code-signing configuration](https://salsa.debian.org/ftp-team/code-signing/-/tree/master/etc), rather than `etc/retired`. [Debian's Secure Boot documentation](https://wiki.debian.org/SecureBoot) identifies this 2022 Linux signer in current kernel logs and says standard Linux images are signed by default. Its [original introduction](https://lists.debian.org/debian-kernel/2022/09/msg00035.html) supplies the same SHA-256 fingerprint. OpenSSL verified its chain to the bundled Debian CA. |
| openSUSE | `suse-trust-root.pem` | The [accepted openSUSE Tumbleweed review](https://github.com/rhboot/shim-review/issues/487) links a [submission containing SUSE Trust Root](https://github.com/rfrohl/shim-review/tree/SUSE-Leap16.0-shim-16.1-20250819). Its certificate was downloaded and compared byte-for-byte with the Enterprise submission's certificate: identical. This is shared CA coverage, not a separately established current default-kernel leaf signer. |
| SUSE Enterprise | `suse-trust-root.pem` | The [accepted Enterprise shim review](https://github.com/rhboot/shim-review/issues/489) links the [SUSE submission](https://github.com/rfrohl/shim-review/tree/6c5f509eb28453e53caa8ac796e13e9dc92e30b2). It embeds SUSE Trust Root and describes signed kernels and non-ephemeral module signing. Current kernel leaf certificates for each product/service pack were not independently collected. |
| Rocky Linux | `rocky-root-ca.pem` | The [vendor-owned Rocky 10 review submission](https://github.com/rocky-linux/shim-review/tree/042eb38d860e1a39523e9a39b1b5c9d48e594b96) identifies the Rocky Secure Boot Root CA and explains that the distribution signs its kernels and bootloaders. It explicitly uses ephemeral module keys per kernel build. This is CA coverage; current kernel leaf/module signers for Rocky 8/9/10 were not independently collected. |
| Microsoft UEFI CA | `microsoft-uefi-ca-2023.pem`, `microsoft-uefi-ca-2011.pem` | Both come from [Microsoft's official Secure Boot Objects repository](https://github.com/microsoft/secureboot_objects/tree/3d762aecbaecd12402efd21ba89c8c7bd40da4bd/PreSignedObjects/DB/Certificates). These primarily identify the bootloader signing chain and are not distribution kernel/module signing keys. The 2011 certificate expired on 2026-06-27 and is retained as a legacy reference, not labelled current. The 2023 certificate expires in 2038. [shim's current guidance](https://github.com/rhboot/shim-review) states that new submissions after 2026-06-27 must use the 2023 CA. |
| AlmaLinux | `almalinux-sb-cert-3.pem` | AlmaLinux's [current security page](https://almalinux.org/security/) labels certificate 3 current and certificates 1/2 previous. Its [2026 vendor-owned review submission](https://github.com/AlmaLinux/shim-review/tree/0af0b0c8263adcafcad9a44fd321913ee0ff75d7) says this self-signed CA has been used since January 2025, superseding the expired certificate previously used for GRUB/kernel signing. This establishes the current vendor CA; current kernel leaf/module certificates for every supported major release were not independently collected. |

`ublue-public-key-2.pem` is included because upstream's current verification recipe
still checks both keys. Its older subject name alone would not justify treating
it as a current signing key. Similarly, Microsoft's 2011 CA is historical data;
its presence must not conceal the 2023 transition.

## How to interpret matches

A successful cryptographic verification of a kernel PE image against a bundled
certificate establishes a signature or certificate-chain relationship to that
candidate vendor key. A CA can validate a chain carried inside the image; its
SKI will generally differ from the actual leaf signer's SKI. Firmware enrollment,
an installed shim, a familiar subject name, or a module's claimed signer string
does not establish that relationship.

The checker can only inspect the supplied file. Proving that file is the image
currently executing requires additional measured-boot/attestation evidence. A
kernel or module signed by the user's own enrolled MOK is not thereby signed by
one of these vendors. `modinfo` signature identifiers are useful hints and are
not cryptographic verification of a module. Ephemeral per-build signing keys
mean a static vendor CA list cannot enumerate all module SKIs.

There is no claim of completeness across products, release streams, architectures,
key rotations, revocations, or older installations. In particular, only Debian
and Universal Blue direct Linux signer certificates were independently obtained
in this snapshot; other distributions currently have CA coverage. An unmatched
key is unknown to this snapshot, not proof that Epic rejects it. Vendor provenance
was established from vendor repositories, documented trust roots and reviewed
shim submissions; Epic's acceptance of each exact key remains an inference.

## Refresh and local validation

Refresh from the linked vendor sources, inspect the certificate's subject,
issuer, validity, constraints and purpose, and confirm its actual use by the
vendor's default kernel build/signing process. Do not substitute RPM/APT GPG
keys, OCI/cosign keys, test certificates, firmware platform/KEK keys, or locally
generated DKMS keys. Keep superseded keys clearly identified if compatibility
with existing installations requires retaining them.

For each bundled PEM, these read-only commands reproduce the registry values:

```sh
openssl x509 -in certs/debian-prod-2022-linux.pem -noout -fingerprint -sha256
openssl x509 -in certs/debian-prod-2022-linux.pem -noout -ext subjectKeyIdentifier
openssl x509 -in certs/debian-prod-2022-linux.pem -noout -subject -issuer -dates
openssl verify -CAfile certs/debian-uefi-ca.pem certs/debian-prod-2022-linux.pem
```

These checks establish certificate integrity and the Debian certificate chain;
they do not query Epic, a game's servers, or the host's active boot state.
