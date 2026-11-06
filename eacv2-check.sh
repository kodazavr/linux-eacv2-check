#!/usr/bin/env bash
# Read-only EAC Linux v2 preflight. Requirements snapshot: 2026-11-06.
# Primary source and implementation references: README.md and docs/signing-keys.md.
set -uo pipefail
export LC_ALL=C
shopt -s nullglob

ROOT='' BLOCKED=0 UNKNOWN=0 PASSED=0 SKIPPED=0 HANDHELD=0
CONFIG='' CMDLINE='' KERNEL='' KERNEL_IMAGE='' LIST_KEYS=0
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
declare -a BOOT_ARGS=()

usage() {
    cat <<'EOF'
Usage: eacv2-check.sh [--handheld] [--kernel IMAGE] [--root DIRECTORY]
       eacv2-check.sh --list-keys

Read-only checks of the currently booted system against Epic's EAC Linux v2
requirements (researched 2026-11-06). No installation, network access or changes.

  --handheld      Explicitly apply Epic's non-handheld IOMMU exception.
  --kernel IMAGE Inspect a kernel/UKI image's signature against candidate keys.
                 This does not prove that IMAGE is the kernel currently running.
  --root DIR     Inspect an offline proc/sys/etc/boot snapshot, not the live OS.
  --list-keys    List bundled, inferred distribution certificates and sources.
  -h, --help     Show this help.

Results: PASS = observed local prerequisite; FAIL = observed blocker;
UNKNOWN = insufficient evidence; SKIP = explicitly selected exception.
Exit: 1 blockers found; 2 inconclusive; 0 help/key listing; 64 invalid invocation.
This preflight cannot certify Epic acceptance or perform remote attestation.
EOF
}

report() {
    local status=$1 title=$2 detail=$3
    case $status in
        PASS) PASSED=$((PASSED + 1));;
        FAIL) BLOCKED=$((BLOCKED + 1));;
        UNKNOWN) UNKNOWN=$((UNKNOWN + 1));;
        SKIP) SKIPPED=$((SKIPPED + 1));;
    esac
    printf '[%s] %s: %s\n' "$status" "$title" "$detail"
}

checked_path() {
    local path=$1 resolved
    if [[ -n $ROOT ]]; then
        resolved=$(realpath -e -- "$path" 2>/dev/null) || return 1
        [[ $resolved == "$ROOT/"* ]] || return 1
        printf '%s' "$resolved"
    else printf '%s' "$path"; fi
}

read_file() {
    local path
    path=$(checked_path "${ROOT}$1") || return 1
    cat -- "$path" 2>/dev/null
}

config_has() { [[ $'\n'$CONFIG$'\n' == *$'\n'"$1=$2"$'\n'* ]]; }
config_disabled() { [[ $'\n'$CONFIG$'\n' == *$'\n'"# $1 is not set"$'\n'* ]]; }

load_config() {
    local path data
    # Only /proc/config.gz describes the running kernel, rather than mutable
    # disk artifacts bearing its release name.
    if path=$(checked_path "${ROOT}/proc/config.gz") && command -v gzip >/dev/null && data=$(gzip -cd -- "$path" 2>/dev/null); then
        CONFIG=$data
    fi
}

parse_cmdline() {
    local rest=$CMDLINE token pattern='^(([^[:space:]\"]|\"[^\"]*\")+)[[:space:]]*'
    # Parse quoted kernel values as data. Never eval a command line or os-release.
    rest="${rest#"${rest%%[![:space:]]*}"}"
    while [[ $rest =~ $pattern ]]; do
        token=${BASH_REMATCH[1]}
        rest=${rest:${#BASH_REMATCH[0]}}
        # Accept unquoted tokens and fully quoted values, not embedded name
        # quotes that the kernel would retain as part of an unrecognized name.
        if [[ $token == *=\"*\" && ${token%%=*} != *\"* ]]; then
            token="${token%%=*}=${token#*=\"}"
            token=${token%\"}
            [[ $token != *\"* ]] || continue
        elif [[ $token == *\"* ]]; then continue; fi
        [[ $token == -- ]] && break
        BOOT_ARGS+=("$token")
    done
}

boot_value() {
    local wanted=$1 token name value=
    for token in "${BOOT_ARGS[@]}"; do
        name=${token%%=*}
        name=${name//-/_}
        name=${name//\//.}
        if [[ $name == "$wanted" && $token == *=* ]]; then value=${token#*=}; fi
    done
    printf '%s' "$value"
}

check_signatures() {
    local taint base path flags name available=0 unreadable=0 module
    local -a flagged=()
    taint=$(read_file /proc/sys/kernel/tainted) || taint=
    if base=$(checked_path "${ROOT}/sys/module") && [[ -d $base && -r $base && -x $base ]]; then
        available=1
        for path in "$base"/*/taint; do
            if flags=$(read_file "${path#"$ROOT"}"); then
                [[ $flags == *E* ]] || continue
                name=${path%/taint}
                flagged+=("${name##*/} (taint=$flags)")
            else
                unreadable=$((unreadable + 1))
            fi
        done
    fi
    # Bit 13 means an unsigned/unverifiable module has been loaded this boot.
    if [[ $taint =~ ^[0-9]{1,10}$ ]] && (( (10#$taint & 8192) != 0 )); then
        report FAIL 'Signed kernel and modules' 'Kernel taint bit 13 records an unsigned/unverifiable module loaded this boot (even if since unloaded).'
    elif (( ${#flagged[@]} )); then
        report FAIL 'Signed kernel and modules' 'Loaded modules carry unsigned/unverifiable E taint.'
    else
        report UNKNOWN 'Signed kernel and modules' 'No attested running-image/module chain. Candidate distribution key matches are evidence only; all enrolled MOKs must also be well-known.'
    fi
    if (( ${#flagged[@]} )); then
        printf '[INFO] Unsigned/unverified loaded modules (kernel E taint):\n'
        for module in "${flagged[@]}"; do printf '  - %s\n' "$module"; done
    elif (( available && unreadable == 0 )); then
        printf '[INFO] No loaded modules with E taint found; global taint persists after unloading and this does not establish Epic key trust.\n'
    fi
    if (( ! available )); then
        printf '[INFO] Loaded module taint list unavailable in this filesystem view.\n'
    elif (( unreadable )); then
        printf '[INFO] %d module taint file(s) unreadable; loaded module list may be incomplete.\n' "$unreadable"
    fi
}

normalize_hex() {
    local value=${1//:/}
    printf '%s' "${value,,}"
}

key_hints() {
    local file vendor fingerprint ski role _source _date extra actual value cert matched=0
    local registry="$SCRIPT_DIR/certs/keys.tsv" image=$KERNEL_IMAGE
    if [[ ! -r $registry ]]; then
        printf '[INFO] Signing keys: bundled candidate key registry is unavailable.\n'
        return
    fi
    if [[ -z $image ]]; then
        local boot_image
        boot_image=$(boot_value BOOT_IMAGE)
        for file in "${ROOT}/usr/lib/modules/$KERNEL/vmlinuz" "${ROOT}/boot/vmlinuz-$KERNEL"; do
            if file=$(checked_path "$file") && [[ -r $file ]]; then image=$file; break; fi
        done
        if [[ -z $image && $boot_image == /vmlinuz-* && $boot_image != *'/'*'/'* && $boot_image != *..* && -r ${ROOT}/boot$boot_image ]]; then
            image=$(checked_path "${ROOT}/boot$boot_image") || image=
        fi
    fi
    if [[ -n $image ]]; then
        printf '[INFO] Kernel image candidate: %s (on disk; identity with running kernel is unproven).\n' "$image"
        if command -v sbverify >/dev/null && command -v openssl >/dev/null; then
            while IFS=$'\t' read -r file vendor fingerprint ski role _source _date extra; do
                [[ -n $file && $file != \#* && $file != */* && -z $extra ]] || continue
                cert="$SCRIPT_DIR/certs/$file"
                actual=$(openssl x509 -in "$cert" -noout -fingerprint -sha256 2>/dev/null) || continue
                actual=$(normalize_hex "${actual#*=}")
                [[ $actual == "$fingerprint" ]] || continue
                if sbverify --cert "$cert" "$image" >/dev/null 2>&1; then
                    printf '[INFO] Kernel signature verifies against inferred %s key (%s; SHA256 %s).\n' "$vendor" "$role" "$fingerprint"
                    matched=$((matched + 1))
                fi
            done < "$registry"
            if (( matched == 0 )); then
                printf '[INFO] Kernel signature: no verification against bundled keys; list may be incomplete, image unsigned/unsupported, or verifier may have failed.\n'
            fi
        else
            printf '[INFO] Kernel signature: optional openssl and sbverify (sbsigntools) are needed for cryptographic candidate-key checks.\n'
        fi
    else
        printf '[INFO] Kernel signature: no unambiguous on-disk candidate found; use --kernel IMAGE.\n'
    fi
    # sig_key is a key identifier from disk metadata, not cryptographic proof
    # that a loaded module was signed or is identical to its current disk file.
    if [[ -z $ROOT ]] && command -v modinfo >/dev/null; then
        local module rest id total=0 known=0 missing=0 names='' module_match
        while read -r module rest; do
            [[ $module =~ ^[a-zA-Z0-9_]+$ ]] || continue
            total=$((total + 1))
            value=$(modinfo -k "$KERNEL" -F sig_key "$module" 2>/dev/null) || value=
            id=$(normalize_hex "$value")
            [[ -n $id ]] || { missing=$((missing + 1)); continue; }
            module_match=0
            while IFS=$'\t' read -r file vendor fingerprint ski role _source _date extra; do
                [[ -n $ski && $file != \#* && $ski != - ]] || continue
                if [[ $id == "$ski" ]]; then
                    module_match=1
                    [[ ";$names;" == *";$vendor;"* ]] || names="${names:+$names;}$vendor"
                fi
            done < "$registry"
            known=$((known + module_match))
        done < <(read_file /proc/modules)
        if (( total )); then
            printf '[INFO] Module key hints (disk metadata): %d/%d match candidate SKIs; %d missing/unavailable. Vendors: %s.\n' "$known" "$total" "$missing" "${names:-none}"
            printf '[INFO] SKI matches are hints only; module signatures, loaded bytes, and all enrolled MOKs remain unverified.\n'
        fi
    fi
}

check_tpm() {
    local path version found=0 unreadable=0 base
    if ! base=$(checked_path "${ROOT}/sys/class/tpm"); then
        report UNKNOWN 'TPM 2.0' 'TPM sysfs unavailable in this filesystem view.'
        return
    fi
    for path in "$base"/tpm[0-9]*; do
        [[ -d $path ]] || continue
        found=1
        if version=$(read_file "${path#"$ROOT"}/tpm_version_major"); then
            if [[ $version == 2 ]]; then
                report PASS 'TPM 2.0' "TPM 2.0 exposed at ${path#"$ROOT"}; attestation usability is not tested."
                return
            fi
            [[ $version == 1 ]] || unreadable=1
        else unreadable=1; fi
    done
    if (( unreadable )); then
        report UNKNOWN 'TPM 2.0' 'TPM version unavailable; a device node alone does not prove TPM 2.0.'
    elif [[ -d ${ROOT}/sys/class/tpm && -r ${ROOT}/sys/class/tpm ]] || (( found )); then
        report FAIL 'TPM 2.0' 'No enabled TPM 2.0 exposed by the kernel. Check firmware TPM/fTPM/PTT and kernel driver support.'
    else
        report UNKNOWN 'TPM 2.0' 'TPM sysfs unavailable; cannot distinguish disabled hardware from restricted visibility.'
    fi
}

efi_byte() {
    local path="${ROOT}/sys/firmware/efi/efivars/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c" value
    # efivarfs files begin with FOUR attribute bytes, followed by variable data.
    path=$(checked_path "$path") || return 1
    value=$(od -An -tu1 -j4 -N1 -- "$path" 2>/dev/null) || return 1
    value=${value//[[:space:]]/}
    [[ $value == 0 || $value == 1 ]] || return 1
    printf '%s' "$value"
}

check_secure_boot() {
    local secure setup
    if [[ ! -d ${ROOT}/sys/firmware/efi ]]; then
        report UNKNOWN 'Secure Boot' 'UEFI sysfs absent (legacy boot or restricted/container view); Secure Boot cannot be established.'
    elif secure=$(efi_byte SecureBoot); then
        if [[ $secure == 0 ]]; then
            report FAIL 'Secure Boot' 'Firmware SecureBoot=0. Enable only with a correctly signed boot chain.'
        elif setup=$(efi_byte SetupMode); then
            if [[ $setup == 0 ]]; then
                report PASS 'Secure Boot' 'SecureBoot=1 and SetupMode=0. Trust in the keys used by the boot chain is assessed separately.'
            else report FAIL 'Secure Boot' 'Firmware is in SetupMode; Secure Boot is not enforcing a provisioned trust chain.'; fi
        else report UNKNOWN 'Secure Boot' 'SecureBoot=1, but SetupMode could not be read.'; fi
    else
        report UNKNOWN 'Secure Boot' 'UEFI SecureBoot variable unreadable/malformed; efivarfs or permissions may restrict access.'
    fi
}

check_measured_boot() {
    local path byte base
    base=$(checked_path "${ROOT}/sys/kernel/security") || base=/nonexistent-eac-snapshot
    for path in "$base"/tpm[0-9]*/binary_bios_measurements; do
        # securityfs file sizes can be zero even for a nonempty event log.
        if path=$(checked_path "$path") && byte=$(od -An -tx1 -N1 -- "$path" 2>/dev/null) && [[ -n $byte ]]; then
            report UNKNOWN 'Measured boot' 'TPM event log is readable and nonempty. Boot-component coverage and log/PCR consistency require validation and attestation.'
            return
        fi
    done
    report UNKNOWN 'Measured boot' 'No readable, nonempty TPM firmware event log. Check securityfs permissions and bootloader TPM measurements; PCR values alone are insufficient.'
}

check_iommu() {
    local path type groups=0 translated=0 missing=0 identity=0 arg setting='' unknown_type=0 base
    if (( HANDHELD )); then
        report SKIP 'IOMMU' "User declared handheld; applying Epic's non-handheld exception. Device acceptance is not established."
        return
    fi
    # Check ordered aliases as well as runtime default-domain types.
    for arg in "${BOOT_ARGS[@]}"; do
        case $arg in
            iommu.passthrough=1) setting=passthrough;;
            iommu.passthrough=0) setting=translated;;
            iommu=*)
                local option
                local -a options
                IFS=, read -r -a options <<< "${arg#*=}"
                for option in "${options[@]}"; do
                    case $option in pt) setting=passthrough;; nopt) setting=translated;; off|soft) setting=disabled;; esac
                done;;
            # Vendor switches can be irrelevant to this CPU; runtime groups
            # establish whether disabling the actual hardware took effect.
        esac
    done
    if [[ $setting == passthrough || $setting == disabled ]]; then
        report FAIL 'IOMMU' "Boot command line requests $setting; non-handheld systems require hardware IOMMU translation."
        return
    fi
    if ! base=$(checked_path "${ROOT}/sys/kernel/iommu_groups"); then
        report UNKNOWN 'IOMMU' 'IOMMU groups are unavailable in this filesystem view.'
        return
    fi
    for path in "$base"/[0-9]*; do
        [[ -d $path ]] || continue
        groups=$((groups + 1))
        if type=$(read_file "${path#"$ROOT"}/type"); then
            case $type in
                DMA|DMA-FQ) translated=$((translated + 1));;
                identity) identity=$((identity + 1));;
                *) unknown_type=$((unknown_type + 1));;
            esac
        else missing=$((missing + 1)); fi
    done
    if (( identity )); then
        report FAIL 'IOMMU' "$identity of $groups groups have identity (passthrough) default domains."
    elif (( groups == 0 )); then
        if [[ -d ${ROOT}/sys/kernel/iommu_groups && -r ${ROOT}/sys/kernel/iommu_groups ]]; then
            report FAIL 'IOMMU' 'No hardware IOMMU groups exposed. Check firmware IOMMU/VT-d/AMD-Vi and kernel support (CPU virtualization alone is insufficient).'
        else report UNKNOWN 'IOMMU' 'IOMMU groups are unavailable in this sysfs view.'; fi
    elif (( missing || unknown_type )); then
        report UNKNOWN 'IOMMU' "$groups groups found; $missing unreadable types and $unknown_type unclassified domains. Group presence alone does not prove translation."
    else
        report PASS 'IOMMU' "$translated groups have DMA/DMA-FQ translated default domains. Full DMA-device coverage is not attested."
    fi
}

check_lockdown() {
    local mode
    if mode=$(read_file /sys/kernel/security/lockdown); then
        case $mode in
            *'[none]'*) report FAIL Lockdown 'Runtime lockdown is disabled; integrity mode must be enabled at boot.';;
            *'[integrity]'*)
                if [[ $(boot_value lockdown) == integrity ]] || config_has CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY y; then
                    report PASS Lockdown 'Runtime integrity mode and explicit boot-time activation evidence found.'
                else report UNKNOWN Lockdown 'Integrity mode active, but explicit boot-time activation is not established by command line/config.'; fi;;
            *'[confidentiality]'*) report UNKNOWN Lockdown 'Confidentiality mode is stronger than integrity, but EAC compatibility with its extra BPF restrictions is unverified.';;
            *) report UNKNOWN Lockdown 'Unrecognized lockdown state.';;
        esac
    else
        report UNKNOWN Lockdown 'Cannot read /sys/kernel/security/lockdown; securityfs may be unmounted or restricted.'
    fi
}

check_kexec() {
    local disabled loaded crash
    disabled=$(read_file /proc/sys/kernel/kexec_load_disabled) || disabled=
    loaded=$(read_file /sys/kernel/kexec_loaded) || loaded=
    crash=$(read_file /sys/kernel/kexec_crash_loaded) || crash=
    if [[ $loaded == 1 || $crash == 1 ]]; then
        report FAIL Kexec 'A kexec or crash kernel is already loaded; disabling further loads does not remove it.'
    elif [[ $disabled == 0 ]]; then
        report FAIL Kexec 'kernel.kexec_load_disabled=0; kexec loading is not disabled.'
    elif config_disabled CONFIG_KEXEC_CORE && config_disabled CONFIG_KEXEC && config_disabled CONFIG_KEXEC_FILE; then
        report PASS Kexec 'Both kexec interfaces and KEXEC_CORE are compiled out in the kernel config.'
    elif [[ $disabled == 1 && $(boot_value sysctl.kernel.kexec_load_disabled) == 1 && $loaded == 0 && $crash == 0 ]]; then
        report PASS Kexec 'Loading disabled, no preloaded images, and sysctl.kernel.kexec_load_disabled=1 present on boot command line.'
    else
        report UNKNOWN Kexec 'Boot-time disable not established. Need runtime value 1, no loaded images and boot-time disable evidence; a late sysctl is insufficient.'
    fi
}

check_bpf() {
    local lsm
    if lsm=$(read_file /sys/kernel/security/lsm); then
        if [[ ,$lsm, == *,bpf,* ]]; then
            report PASS 'BPF LSM' 'bpf appears in the active runtime LSM list.'
        else report FAIL 'BPF LSM' 'bpf is absent from the active LSM list; CONFIG_BPF_LSM alone does not activate it.'; fi
    else
        report UNKNOWN 'BPF LSM' 'Cannot read /sys/kernel/security/lsm; runtime activation is not established.'
    fi
}

main() {
    while (( $# )); do
        case $1 in
            -h|--help) usage; return 0;;
            --list-keys) LIST_KEYS=1; shift;;
            --handheld) HANDHELD=1; shift;;
            --root|--kernel)
                if (( $# < 2 )) || [[ -z $2 ]]; then printf 'Missing value for %s\n' "$1" >&2; return 64; fi
                if [[ $1 == --root ]]; then
                    [[ -d $2 ]] || { printf 'Not a directory: %s\n' "$2" >&2; return 64; }
                    ROOT=$(cd -- "$2" && pwd -P) || return 64
                    [[ $ROOT == / ]] && ROOT=
                else KERNEL_IMAGE=$2; fi
                shift 2;;
            *) printf 'Unknown option: %s\n' "$1" >&2; return 64;;
        esac
    done
    if (( LIST_KEYS )); then
        printf 'INFERRED candidates, not an official Epic key allowlist. See docs/signing-keys.md.\n'
        cat -- "$SCRIPT_DIR/certs/keys.tsv" || return 2
        return 0
    fi
    if [[ -n $KERNEL_IMAGE && ! -r $KERNEL_IMAGE ]]; then
        printf 'Kernel image is not readable: %s\n' "$KERNEL_IMAGE" >&2
        return 64
    fi
    local os line
    os=Unknown
    while IFS= read -r line; do
        if [[ $line == PRETTY_NAME=* ]]; then os=${line#*=}; os=${os#\"}; os=${os%\"}; break; fi
    done < <(read_file /etc/os-release)
    KERNEL=$(read_file /proc/sys/kernel/osrelease) || KERNEL=unknown
    # Keep disk config fallback paths within the expected kernel-release format.
    [[ $KERNEL =~ ^[a-zA-Z0-9._+-]+$ ]] || KERNEL=unknown
    CMDLINE=$(read_file /proc/cmdline) || CMDLINE=
    parse_cmdline
    load_config
    printf 'EAC Linux v2 preflight (requirements researched 2026-11-06)\nOS: %s | Kernel: %s\n' "$os" "$KERNEL"
    [[ -z $ROOT ]] || printf 'OFFLINE SNAPSHOT: %s (no live-system verdict)\n' "$ROOT"
    printf 'PASS means local evidence only, not confirmed Epic acceptance.\n\n'
    check_signatures
    key_hints
    check_tpm
    check_secure_boot
    check_measured_boot
    check_iommu
    check_lockdown
    check_kexec
    check_bpf
    printf '\n%d PASS, %d FAIL, %d UNKNOWN, %d SKIP\n' "$PASSED" "$BLOCKED" "$UNKNOWN" "$SKIPPED"
    printf 'Signing-key policy and boot attestation require Epic validation. Requirements may change.\n'
    if (( BLOCKED )); then printf 'RESULT: NOT READY: observed requirement blockers.\n'; return 1; fi
    printf 'RESULT: INDETERMINATE: local checks cannot certify EAC Linux v2 compatibility.\n'
    return 2
}

main "$@"
