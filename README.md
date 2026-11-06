# EAC Linux v2 preflight

A read-only Bash checker for the **running Linux boot session**. It reports
local evidence for Epic's requirements, with a candidate distribution signing-key
reference inferred from the vendors Epic names.

> **Warning: the certificate list is preliminary.** It is an inferred,
> potentially incomplete or outdated reference, not an official Epic allowlist.
> A matching certificate does not confirm EAC Linux v2 acceptance, and a missing
> match does not prove that Epic rejects the key.

```bash
bash ./eacv2-check.sh
bash ./eacv2-check.sh --kernel /boot/vmlinuz-linux
bash ./eacv2-check.sh --list-keys
```

Run as your normal user first. Files hidden by permissions produce `UNKNOWN`.
Running with sufficient read privileges may expose more evidence. The checker
does not use sudo, mount filesystems, install packages, enroll keys, change boot
arguments, load BPF programs, or access the network.

## Required and optional tools

The following commands must be available in `PATH` for their corresponding
checks. Package names vary by Linux distribution; common names are listed below.

| Tool / commands | Common package name(s) | Required for |
| --- | --- | --- |
| `bash` 4 or newer | `bash` | Running the checker |
| `env`, `dirname`, `cat`, `od` | `coreutils` | Executable startup, locating bundled files, reading system evidence and decoding EFI variables / TPM log bytes |
| `realpath` | `coreutils` | Confining filesystem reads when using `--root` |
| `gzip` | `gzip` | Optional: reading the running kernel's `/proc/config.gz` for build-time lockdown and compiled-out kexec evidence |
| `modinfo` | `kmod` | Optional: comparing module signing-key IDs with the candidate list; live-system checks only |
| `lspci` | `pciutils` | Optional: adding PCI device names and numeric IDs to problematic IOMMU groups; live-system checks only |
| `openssl` **and** `sbverify` | `openssl` **and** `sbsigntools` or `sbsigntool` | Optional: cryptographically checking an on-disk kernel/UKI against the candidate certificates; both commands are needed |

The minimum runtime dependencies are Bash and coreutils. Install all packages
listed above to enable every implemented check and signing-key hint. Missing
optional tools do not abort the checker: affected evidence remains unavailable
or is reported as an informational omission. Having every tool installed does
not guarantee a `PASS`; kernel features, permissions and accessible evidence
still determine the results.

Keep `certs/` next to the script. Live checks also need the standard Linux
`/proc` and `/sys` interfaces; EFI variables and securityfs evidence must be
accessible for the corresponding checks.

`--kernel IMAGE` selects an explicit image. Otherwise, the checker tries the
running release's module/boot paths and a simple `/vmlinuz-*` `BOOT_IMAGE` path.
The selected disk image is **not proof of what was booted**. A UKI's outer
signature and the embedded kernel's signing chain may differ.

## What is checked

The requirements were researched on **2026-11-06** from
[Epic's EAC Linux v2 announcement](https://onlineservices.epicgames.com/news/introducing-easy-anti-cheat-linux-v2),
published October 14, 2026. Epic says the requirements may evolve.

| Requirement | Evidence used | Limit |
| --- | --- | --- |
| Signed kernel and modules | Unsigned-module taint and names of loaded modules carrying `E`; optional kernel signature verification and module signing-key IDs | Running-image identity, full chain, MOK enrollment and Epic trust are not certified |
| TPM 2.0 | TPM version from sysfs | No TPM commands or attestation test |
| Secure Boot | EFI SecureBoot and SetupMode variables | Enabled does not establish acceptable keys |
| Measured boot | Readable, nonempty firmware TPM event log | Log coverage, PCR replay and remote attestation are not validated |
| IOMMU | Group default-domain types and passthrough/disable boot options; IDs and devices for problematic groups | Observed translated domains do not certify all device DMA paths |
| Lockdown | Runtime integrity mode plus explicit boot activation evidence | Runtime activation alone does not establish boot-time activation |
| Kexec disabled | Runtime disable, preloaded image state, boot command line or compiled-out interfaces | A late sysctl can leave a previously loaded image usable |
| BPF LSM | `bpf` in the active runtime LSM list | Build configuration alone is insufficient |

The `--handheld` option explicitly selects Epic's IOMMU exception for handhelds.
It does not imply that any specific handheld is supported, or exempt it from the
other checks. No minimum kernel version is invented: feature evidence is used.
The Linux distribution's name alone is not treated as an incompatibility.

## Reading results

- `PASS`: the specific local prerequisite was observed.
- `FAIL`: a local blocker was observed.
- `UNKNOWN`: evidence is unavailable or requires stronger validation.
- `SKIP`: the user selected the handheld IOMMU exception.

In a terminal, `PASS` is green, `FAIL` is red, `UNKNOWN` and diagnostic `WARN`
messages are yellow, and `SKIP` is cyan. Summary counts and the final result use
the same colors. Warnings provide context and do not add failed checks.
Status labels remain visible without color.

Every check run ends with a short summary listing all eight check names and their
results in execution order, followed by totals and the overall result. The
summary uses the same status colors as the detailed output.

Color defaults to `--color=auto`: redirected/piped output and `TERM=dumb` stay
plain, and a nonempty `NO_COLOR` environment variable disables automatic color.
Use `--color=always` to force ANSI colors or `--color=never` to disable them.
An explicit color setting takes precedence over `NO_COLOR`.

Checks include evidence lines in the form `current=...; expected=...`, so a
mismatch identifies the observed value and the condition being checked. Where
several items contribute evidence, they are listed individually: both Secure
Boot variables, every visible TPM and firmware event log, all kexec runtime
states, and each problematic module or IOMMU group. Missing, unreadable and
empty evidence are identified explicitly rather than treated as a disabled
feature. Expectations can describe alternatives, such as disabling kexec at
boot or compiling both interfaces out of the running kernel.

Signing diagnostics also show failed candidate-certificate verification attempts
and group unmatched module signing-key IDs with all affected module names.
These are inconclusive comparisons against the preliminary certificate list,
not additional failures or proof that Epic rejects those keys. When available,
kernel signature metadata is shown as unverified information.

Exit codes are `1` for observed blockers, `2` for an indeterminate result, `0`
for help/key listing, and `64` for invalid arguments. There is deliberately no
"certified compatible" exit status. A clean local configuration still needs
Epic's actual policy and attestation checks. Distribution certificates are an
**inferred candidate set**, not an authoritative Epic allowlist. An unmatched
key is inconclusive because the reference may be incomplete or outdated.

See [signing-key research and provenance](docs/signing-keys.md) for the vendor
certificate sources, roles, rotations, and remaining gaps. Certificate subject
names are not used as proof. Kernel checks use `sbverify --cert`; module `sig_key`
matches are explicitly metadata hints and do not verify module signatures.
Package repository OpenPGP keys are unrelated to these X.509 signing keys.

The signing check lists loaded modules whose `/sys/module/<name>/taint` contains
`E`, meaning they were unsigned or their signatures could not be verified by the
kernel when loaded. This list uses runtime evidence and needs no additional
tools. It also works with `--root` snapshots containing those sysfs files.
Unavailable module sysfs or unreadable taint files are reported as unavailable
evidence. Global bit 13 persists after unloading a module, so a failure can remain even when the
loaded-module list is empty. A module without `E` is not thereby confirmed to
use an Epic-accepted key.

The IOMMU check identifies each group with an identity (passthrough) domain,
an unreadable type, or an unclassified domain type, and lists its device
addresses. On the live system, optional `lspci` adds PCI device names and numeric
IDs. Without it, or when inspecting an offline snapshot, device addresses are
still shown. Missing device information is reported without hiding the group.

## Validation

Development validation additionally needs `python3` (package `python3` or `python`) and
`shellcheck` (package `shellcheck`). Neither is needed to run the checker.
The certificate tests need `openssl` and are skipped if it is absent. `sbsign`
(package `sbsigntools` or `sbsigntool`) is only needed to reproduce the manual signing test
described below; the checker itself does not invoke it.

```bash
bash -n eacv2-check.sh
shellcheck eacv2-check.sh
python3 -m unittest discover -s tests -v
```

Tests execute the Bash program against temporary filesystem snapshots, including
missing evidence, TPM versions, EFI attribute offsets, IOMMU passthrough, runtime
versus build/boot state, and unsigned-module taint. `--root DIRECTORY` is also
available for inspecting an offline snapshot; it is clearly labeled and reads
snapshot files rather than falling back to the live host.
Snapshot symlinks resolving outside the supplied root are refused; kernel build
evidence comes only from `/proc/config.gz`. Offline module metadata scanning is
omitted to prevent an external module tool from following host paths.

Real `sbsign`/`sbverify` checks were also run using `sbsigntools` 0.9.5-4
extracted into `/tmp`, with no package installation. A temporary signed copy of a
kernel image verified against its signing certificate and failed against another
certificate with the same displayed subject name. The local CachyOS kernel image
was also inspected and had no PE signature table.

An initial unprivileged run on the available Manjaro installation (kernel
`7.3.0-2-cachyos-bore`) found unsigned-module taint, Secure Boot off, an identity
IOMMU domain, lockdown off and kexec enabled. TPM 2.0 and active BPF LSM were
observed. The TPM event log was not readable. This records that test environment,
not a general conclusion about Manjaro or stock Manjaro kernels.

## Additional primary sources

- [Linux module signature verification](https://docs.kernel.org/admin-guide/module-signing.html)
  explains signature enforcement and the unsigned-module taint.
- [Linux kernel taint flags](https://docs.kernel.org/admin-guide/tainted-kernels.html)
  document the persistent bit 13, distinct from proprietary/out-of-tree flags.
- [Kernel parameters](https://docs.kernel.org/admin-guide/kernel-parameters.html)
  document lockdown, IOMMU passthrough and `sysctl.*` boot arguments.
- [Kexec sysctl](https://docs.kernel.org/admin-guide/sysctl/kernel.html#kexec-load-disabled)
  documents why disabling loading can leave an existing image usable.
- [Active LSM interfaces](https://docs.kernel.org/admin-guide/LSM/index.html)
  document `/sys/kernel/security/lsm`; [BPF LSM](https://docs.kernel.org/bpf/prog_lsm.html)
  explains the feature.
- [TPM event logs](https://docs.kernel.org/security/tpm/tpm_event_log.html)
  explain why a measurement log must be validated against PCRs.
- [IOMMU group ABI](https://github.com/torvalds/linux/blob/master/Documentation/ABI/testing/sysfs-kernel-iommu_groups)
  documents the default-domain `type` interface.
- [sbverify manual](https://man.archlinux.org/man/sbverify.1.en)
  distinguishes cryptographic verification from merely listing signatures.
