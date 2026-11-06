#!/usr/bin/env bash
# Read-only EAC Linux v2 preflight. Requirements snapshot: 2026-11-06.
# Primary source and implementation references: README.md and docs/signing-keys.md.
set -uo pipefail
export LC_ALL=C
shopt -s nullglob

ROOT='' BLOCKED=0 UNKNOWN=0 PASSED=0 SKIPPED=0 HANDHELD=0
CONFIG='' CMDLINE='' KERNEL='' KERNEL_IMAGE='' LIST_KEYS=0 CMDLINE_READABLE=0
COLOR_MODE=auto COLOR_ENABLED=0
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
declare -a BOOT_ARGS=()
declare -a CHECK_TITLES=() CHECK_STATUSES=()

usage() {
    cat <<'EOF'
Usage: eacv2-check.sh [--handheld] [--kernel IMAGE] [--root DIRECTORY]
                    [--color auto|always|never]
       eacv2-check.sh --list-keys

Read-only checks of the currently booted system against Epic's EAC Linux v2
requirements (researched 2026-11-06). No installation, network access or changes.

  --handheld      Explicitly apply Epic's non-handheld IOMMU exception.
  --kernel IMAGE Inspect a kernel/UKI image's signature against candidate keys.
                 This does not prove that IMAGE is the kernel currently running.
  --root DIR     Inspect an offline proc/sys/etc/boot snapshot, not the live OS.
  --list-keys    List bundled, inferred distribution certificates and sources.
  --color MODE   auto (default), always, or never; --color=MODE also works.
                 Auto honors NO_COLOR and TERM=dumb and colors terminals only.
  -h, --help     Show this help.

Results: PASS = observed local prerequisite; FAIL = observed blocker;
UNKNOWN = insufficient evidence; SKIP = explicitly selected exception.
Exit: 1 blockers found; 2 inconclusive; 0 help/key listing; 64 invalid invocation.
This preflight cannot certify Epic acceptance or perform remote attestation.
EOF
}

setup_color() {
    case $COLOR_MODE in
        always) COLOR_ENABLED=1;;
        never) COLOR_ENABLED=0;;
        auto)
            if [[ -t 1 && ${TERM:-dumb} != dumb && -z ${NO_COLOR:-} ]]; then COLOR_ENABLED=1; fi;;
    esac
}

color_text() {
    local level=$1 text=$2 code=''
    if (( COLOR_ENABLED )); then
        case $level in
            PASS) code=$'\e[32m';;
            FAIL) code=$'\e[31m';;
            WARN|UNKNOWN) code=$'\e[33m';;
            SKIP) code=$'\e[36m';;
        esac
    fi
    printf '%s%s' "$code" "$text"
    [[ -z $code ]] || printf '\033[0m'
    return 0
}

warning() {
    color_text WARN '[WARN]'
    printf ' %s\n' "$1"
}

report() {
    local status=$1 title=$2 detail=$3
    CHECK_TITLES+=("$title")
    CHECK_STATUSES+=("$status")
    case $status in
        PASS) PASSED=$((PASSED + 1));;
        FAIL) BLOCKED=$((BLOCKED + 1));;
        UNKNOWN) UNKNOWN=$((UNKNOWN + 1));;
        SKIP) SKIPPED=$((SKIPPED + 1));;
    esac
    color_text "$status" "[$status]"
    printf ' %s: %s\n' "$title" "$detail"
}

check_summary() {
    local index
    printf '\nCheck summary:\n'
    for index in "${!CHECK_TITLES[@]}"; do
        printf '  '
        color_text "${CHECK_STATUSES[$index]}" "[${CHECK_STATUSES[$index]}]"
        printf ' %s\n' "${CHECK_TITLES[$index]}"
    done
}

evidence() {
    printf '  - %s: current=%s; expected=%s\n' "$1" "${2:-<empty>}" "$3"
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
config_disabled() {
    [[ $'\n'$CONFIG$'\n' == *$'\n'"# $1 is not set"$'\n'* ]] || config_has "$1" n
}

config_value() {
    local key=$1 line
    if config_disabled "$key"; then printf 'n'; return; fi
    while IFS= read -r line; do
        if [[ $line == "$key="* ]]; then printf '%s' "${line#*=}"; return; fi
    done <<< "$CONFIG"
    printf '<unavailable>'
}

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

boot_observed() {
    local value
    if (( ! CMDLINE_READABLE )); then printf '<command line unavailable>'; return; fi
    value=$(boot_value "$1")
    printf '%s' "${value:-<absent or empty>}"
}

check_signatures() {
    local taint base path flags name available=0 unreadable=0 module
    local -a flagged=() unreadable_paths=()
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
                unreadable_paths+=("${path#"$ROOT"}")
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
    local taint_detail=${taint:-<unavailable>}
    if [[ $taint =~ ^[0-9]{1,10}$ ]]; then
        taint_detail="$taint (bit 13=$(( (10#$taint >> 13) & 1 )))"
    fi
    evidence /proc/sys/kernel/tainted "$taint_detail" 'bit 13=0 (no unsigned/unverified module history)'
    if (( ${#flagged[@]} )); then
        printf '[INFO] Unsigned/unverified loaded modules (kernel E taint):\n'
        for module in "${flagged[@]}"; do printf '  - %s; expected=no E taint\n' "$module"; done
    elif (( available && unreadable == 0 )); then
        printf '[INFO] No loaded modules with E taint found; global taint persists after unloading and this does not establish Epic key trust.\n'
    fi
    if (( ! available )); then
        warning 'Loaded module taint list unavailable in this filesystem view.'
        evidence /sys/module '<unavailable>' 'readable per-module taint files'
    elif (( unreadable )); then
        warning "$unreadable module taint file(s) unreadable; loaded module list may be incomplete."
        for path in "${unreadable_paths[@]}"; do evidence "$path" '<unreadable>' 'readable taint flags without E'; done
    fi
}

normalize_hex() {
    local value=${1//:/}
    printf '%s' "${value,,}"
}

key_hints() {
    local file vendor fingerprint ski role _source _date extra actual value cert matched=0 result index
    local -a attempted=() results=()
    local registry="$SCRIPT_DIR/certs/keys.tsv" image=$KERNEL_IMAGE
    if [[ ! -r $registry ]]; then
        warning 'Signing keys: bundled candidate key registry is unavailable.'
        evidence "$registry" '<unreadable or missing>' 'readable preliminary certificate registry'
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
                if ! actual=$(openssl x509 -in "$cert" -noout -fingerprint -sha256 2>/dev/null); then
                    evidence "$file certificate" '<unreadable or invalid>' "parseable X.509 certificate with SHA256 $fingerprint"
                    continue
                fi
                actual=$(normalize_hex "${actual#*=}")
                if [[ $actual != "$fingerprint" ]]; then
                    evidence "$file certificate SHA256" "$actual" "$fingerprint"
                    continue
                fi
                if sbverify --cert "$cert" "$image" >/dev/null 2>&1; then
                    printf '[INFO] Kernel signature verifies against inferred %s key (%s; SHA256 %s).\n' "$vendor" "$role" "$fingerprint"
                    matched=$((matched + 1))
                else
                    result=$?
                    attempted+=("$vendor / $file (SHA256 $fingerprint)")
                    results+=("verification exit $result")
                fi
            done < "$registry"
            if (( matched == 0 )); then
                warning 'Kernel signature: no verification against bundled keys; list may be incomplete, image unsigned/unsupported, or verifier may have failed.'
                for index in "${!attempted[@]}"; do
                    evidence "${attempted[$index]}" "${results[$index]}" 'exit 0 for at least one candidate; reference is preliminary'
                done
                if value=$(sbverify --list "$image" 2>&1); then
                    printf '[INFO] Kernel signature metadata (unverified):\n'
                    while IFS= read -r result; do printf '    %s\n' "$result"; done <<< "$value"
                else
                    evidence 'Kernel signature metadata' "${value:-<unavailable>}" 'readable PE signature metadata; listing alone does not verify trust'
                fi
            fi
        else
            warning 'Kernel signature: optional openssl and sbverify (sbsigntools/sbsigntool) are needed for cryptographic candidate-key checks.'
            local tool location
            for tool in openssl sbverify; do
                location=$(command -v "$tool") || location='<unavailable>'
                evidence "$tool" "$location" 'available executable for kernel signature verification'
            done
        fi
    else
        warning 'Kernel signature: no unambiguous on-disk candidate found; use --kernel IMAGE.'
    fi
    # sig_key is a key identifier from disk metadata, not cryptographic proof
    # that a loaded module was signed or is identical to its current disk file.
    if [[ -z $ROOT ]] && command -v modinfo >/dev/null; then
        local module rest id total=0 known=0 missing=0 names='' module_match
        local -A unmatched_modules=()
        local -a unmatched_ids=()
        while read -r module rest; do
            [[ $module =~ ^[a-zA-Z0-9_]+$ ]] || continue
            total=$((total + 1))
            value=$(modinfo -k "$KERNEL" -F sig_key "$module" 2>/dev/null) || value=
            id=$(normalize_hex "$value")
            if [[ -z $id ]]; then missing=$((missing + 1)); id='<unavailable>'; fi
            module_match=0
            while IFS=$'\t' read -r file vendor fingerprint ski role _source _date extra; do
                [[ -n $ski && $file != \#* && $ski != - ]] || continue
                if [[ $id == "$ski" ]]; then
                    module_match=1
                    [[ ";$names;" == *";$vendor;"* ]] || names="${names:+$names;}$vendor"
                fi
            done < "$registry"
            known=$((known + module_match))
            if (( ! module_match )); then
                if [[ -z ${unmatched_modules[$id]+present} ]]; then
                    unmatched_ids+=("$id")
                    unmatched_modules[$id]=$module
                else unmatched_modules[$id]+=", $module"; fi
            fi
        done < <(read_file /proc/modules)
        if (( total )); then
            printf '[INFO] Module key hints (disk metadata): %d/%d match candidate SKIs; %d missing/unavailable. Vendors: %s.\n' "$known" "$total" "$missing" "${names:-none}"
            printf '[INFO] SKI matches are hints only; module signatures, loaded bytes, and all enrolled MOKs remain unverified.\n'
            for id in "${unmatched_ids[@]}"; do
                evidence 'Module signing-key ID' "$id" 'SKI in preliminary certs/keys.tsv (a match is a hint, not proof of Epic trust)'
                printf '    Affected modules: %s\n' "${unmatched_modules[$id]}"
            done
        fi
    fi
}

check_tpm() {
    local path version found=0 unreadable=0 base tpm2=0 index
    local -a paths=() versions=()
    if ! base=$(checked_path "${ROOT}/sys/class/tpm"); then
        report UNKNOWN 'TPM 2.0' 'TPM sysfs unavailable in this filesystem view.'
        evidence /sys/class/tpm '<unavailable>' 'at least one enabled TPM with tpm_version_major=2'
        return
    fi
    for path in "$base"/tpm[0-9]*; do
        [[ -d $path ]] || continue
        found=1
        paths+=("${path#"$ROOT"}/tpm_version_major")
        if version=$(read_file "${path#"$ROOT"}/tpm_version_major"); then
            versions+=("$version")
            if [[ $version == 2 ]]; then
                tpm2=$((tpm2 + 1))
            elif [[ $version != 1 ]]; then
                unreadable=1
            fi
        else unreadable=1; versions+=('<unreadable>'); fi
    done
    if (( tpm2 )); then
        report PASS 'TPM 2.0' "$tpm2 enabled TPM 2.0 device(s) exposed; attestation usability is not tested."
    elif (( unreadable )); then
        report UNKNOWN 'TPM 2.0' 'TPM version unavailable; a device node alone does not prove TPM 2.0.'
    elif [[ -d ${ROOT}/sys/class/tpm && -r ${ROOT}/sys/class/tpm ]] || (( found )); then
        report FAIL 'TPM 2.0' 'No enabled TPM 2.0 exposed by the kernel. Check firmware TPM/fTPM/PTT and kernel driver support.'
    else
        report UNKNOWN 'TPM 2.0' 'TPM sysfs unavailable; cannot distinguish disabled hardware from restricted visibility.'
    fi
    for index in "${!paths[@]}"; do evidence "${paths[$index]}" "${versions[$index]}" '2'; done
    (( found )) || evidence /sys/class/tpm 'no visible TPM devices' 'at least one enabled TPM with tpm_version_major=2'
}

efi_byte() {
    local path="${ROOT}/sys/firmware/efi/efivars/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c" value
    # efivarfs files begin with FOUR attribute bytes, followed by variable data.
    path=$(checked_path "$path") || return 1
    value=$(od -An -tu1 -j4 -N1 -- "$path" 2>/dev/null) || return 1
    value=${value//[[:space:]]/}
    [[ $value =~ ^[0-9]+$ ]] || return 1
    printf '%s' "$value"
}

check_secure_boot() {
    local secure setup
    secure=$(efi_byte SecureBoot) || secure='<unavailable>'
    setup=$(efi_byte SetupMode) || setup='<unavailable>'
    if [[ ! -d ${ROOT}/sys/firmware/efi ]]; then
        report UNKNOWN 'Secure Boot' 'UEFI sysfs absent (legacy boot or restricted/container view); Secure Boot cannot be established.'
    elif [[ $secure == 0 ]]; then
        report FAIL 'Secure Boot' 'Firmware SecureBoot=0. Enable only with a correctly signed boot chain.'
    elif [[ $setup == 1 ]]; then
        report FAIL 'Secure Boot' 'Firmware is in SetupMode; Secure Boot is not enforcing a provisioned trust chain.'
    elif [[ $secure == 1 && $setup == 0 ]]; then
        report PASS 'Secure Boot' 'SecureBoot=1 and SetupMode=0. Trust in the keys used by the boot chain is assessed separately.'
    else
        report UNKNOWN 'Secure Boot' 'UEFI SecureBoot variable unreadable/malformed; efivarfs or permissions may restrict access.'
    fi
    evidence SecureBoot "$secure" '1'
    evidence SetupMode "$setup" '0'
}

check_measured_boot() {
    local path byte base readable=0 index
    local -a paths=() states=()
    base=$(checked_path "${ROOT}/sys/kernel/security") || base=/nonexistent-eac-snapshot
    for path in "$base"/tpm[0-9]*/binary_bios_measurements; do
        paths+=("${path#"$ROOT"}")
        # securityfs file sizes can be zero even for a nonempty event log.
        if path=$(checked_path "$path") && byte=$(od -An -tx1 -N1 -- "$path" 2>/dev/null); then
            if [[ -n $byte ]]; then states+=('readable and nonempty'); readable=$((readable + 1)); else states+=('empty'); fi
        else
            states+=('<unreadable>')
        fi
    done
    if (( readable )); then
        report UNKNOWN 'Measured boot' 'TPM event log is readable and nonempty. Boot-component coverage and log/PCR consistency require validation and attestation.'
    else
        report UNKNOWN 'Measured boot' 'No readable, nonempty TPM firmware event log. Check securityfs permissions and bootloader TPM measurements; PCR values alone are insufficient.'
    fi
    for index in "${!paths[@]}"; do evidence "${paths[$index]}" "${states[$index]}" 'readable nonempty event log'; done
    (( ${#paths[@]} )) || evidence '/sys/kernel/security/tpm*/binary_bios_measurements' 'no visible event log files' 'readable nonempty event log'
}

iommu_group_details() {
    local group=$1 reason=$2 devices device name description count=0
    printf '[INFO] IOMMU group %s: %s; expected=DMA or DMA-FQ\n' "${group##*/}" "$reason"
    if ! devices=$(checked_path "$group/devices") || [[ ! -d $devices || ! -r $devices || ! -x $devices ]]; then
        printf '  - Devices unavailable (missing or unreadable devices directory).\n'
        return
    fi
    for device in "$devices"/*; do
        name=${device##*/}
        description=$name
        # Snapshot addresses must never be looked up against live hardware.
        if [[ -z $ROOT && $name =~ ^[[:xdigit:]]{4}:[[:xdigit:]]{2}:[[:xdigit:]]{2}\.[0-7]$ ]] && command -v lspci >/dev/null; then
            description=$(lspci -D -nn -s "$name" 2>/dev/null) || description=
            [[ -n $description ]] || description=$name
        fi
        printf '  - %s\n' "$description"
        count=$((count + 1))
    done
    (( count )) || printf '  - No devices listed.\n'
}

check_iommu() {
    local path type groups=0 translated=0 missing=0 identity=0 arg setting='' unknown_type=0 base index
    local -a problem_paths=() problem_reasons=() boot_evidence=()
    if (( HANDHELD )); then
        report SKIP 'IOMMU' "User declared handheld; applying Epic's non-handheld exception. Device acceptance is not established."
        return
    fi
    # Check ordered aliases as well as runtime default-domain types.
    for arg in "${BOOT_ARGS[@]}"; do
        case $arg in
            iommu.passthrough=1) setting=passthrough; boot_evidence+=("$arg");;
            iommu.passthrough=0) setting=translated; boot_evidence+=("$arg");;
            iommu=*)
                boot_evidence+=("$arg")
                local option
                local -a options
                IFS=, read -r -a options <<< "${arg#*=}"
                for option in "${options[@]}"; do
                    case $option in pt) setting=passthrough;; nopt) setting=translated;; off|soft) setting=disabled;; esac
                done;;
            # Vendor switches can be irrelevant to this CPU; runtime groups
            # establish whether disabling the actual hardware took effect.
            intel_iommu=*|amd_iommu=*) boot_evidence+=("$arg");;
        esac
    done
    if [[ $setting == passthrough || $setting == disabled ]]; then
        report FAIL 'IOMMU' "Boot command line requests $setting; non-handheld systems require hardware IOMMU translation."
    fi
    if ! base=$(checked_path "${ROOT}/sys/kernel/iommu_groups"); then
        if [[ $setting != passthrough && $setting != disabled ]]; then
            report UNKNOWN 'IOMMU' 'IOMMU groups are unavailable in this filesystem view.'
        fi
        evidence /sys/kernel/iommu_groups '<unavailable>' 'hardware IOMMU groups with translated DMA domains'
        for arg in "${boot_evidence[@]}"; do evidence 'IOMMU boot argument' "$arg" 'hardware translation, passthrough disabled'; done
        return
    fi
    for path in "$base"/[0-9]*; do
        [[ -d $path ]] || continue
        groups=$((groups + 1))
        if type=$(read_file "${path#"$ROOT"}/type"); then
            case $type in
                DMA|DMA-FQ) translated=$((translated + 1));;
                identity)
                    identity=$((identity + 1))
                    problem_paths+=("$path")
                    problem_reasons+=('type=identity');;
                *)
                    unknown_type=$((unknown_type + 1))
                    problem_paths+=("$path")
                    problem_reasons+=("type=${type:-empty} (unclassified)");;
            esac
        else
            missing=$((missing + 1))
            problem_paths+=("$path")
            problem_reasons+=('type unreadable')
        fi
    done
    if [[ $setting == passthrough || $setting == disabled ]]; then
        : # The command-line blocker has already been reported.
    elif (( identity )); then
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
    evidence /sys/kernel/iommu_groups "$groups groups; $translated translated; $identity identity; $missing unreadable; $unknown_type unclassified" 'at least one group, all observed default domains DMA or DMA-FQ'
    for arg in "${boot_evidence[@]}"; do evidence 'IOMMU boot argument' "$arg" 'hardware translation, passthrough disabled'; done
    for index in "${!problem_paths[@]}"; do
        iommu_group_details "${problem_paths[$index]}" "${problem_reasons[$index]}"
    done
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
        mode='<unavailable>'
        report UNKNOWN Lockdown 'Cannot read /sys/kernel/security/lockdown; securityfs may be unmounted or restricted.'
    fi
    evidence /sys/kernel/security/lockdown "$mode" 'integrity active at boot'
    evidence 'lockdown boot parameter' "$(boot_observed lockdown)" 'integrity, or CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y'
    evidence CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY "$(config_value CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY)" 'y, or lockdown=integrity at boot'
}

kexec_compiled_out() {
    # KEXEC_CORE is hidden and may be omitted when both interfaces are off.
    if config_disabled CONFIG_KEXEC && config_disabled CONFIG_KEXEC_FILE; then return 0; fi
    # Conversely, a disabled core rules out its dependent interfaces, even if
    # their entries are omitted. Do not accept contradictory enabled values.
    config_disabled CONFIG_KEXEC_CORE || return 1
    local key
    for key in CONFIG_KEXEC CONFIG_KEXEC_FILE; do
        case $(config_value "$key") in
            n|'<unavailable>') ;;
            *) return 1;;
        esac
    done
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
    elif kexec_compiled_out; then
        report PASS Kexec 'Kexec loading is compiled out: both interfaces or their required core are disabled in the running kernel config.'
    elif [[ $disabled == 1 && $(boot_value sysctl.kernel.kexec_load_disabled) == 1 && $loaded == 0 && $crash == 0 ]]; then
        report PASS Kexec 'Loading disabled, no preloaded images, and sysctl.kernel.kexec_load_disabled=1 present on boot command line.'
    else
        report UNKNOWN Kexec 'Boot-time disable not established. Need runtime value 1, no loaded images and boot-time disable evidence; a late sysctl is insufficient.'
    fi
    evidence kernel.kexec_load_disabled "${disabled:-<unavailable>}" '1, or both interfaces compiled out'
    evidence /sys/kernel/kexec_loaded "${loaded:-<unavailable>}" '0, or unavailable when interfaces are compiled out'
    evidence /sys/kernel/kexec_crash_loaded "${crash:-<unavailable>}" '0, or unavailable when interfaces are compiled out'
    evidence 'sysctl.kernel.kexec_load_disabled boot parameter' "$(boot_observed sysctl.kernel.kexec_load_disabled)" '1, or both interfaces compiled out'
    local key
    evidence CONFIG_KEXEC_CORE "$(config_value CONFIG_KEXEC_CORE)" 'n, or optional when both interfaces are explicitly disabled'
    for key in CONFIG_KEXEC CONFIG_KEXEC_FILE; do
        evidence "$key" "$(config_value "$key")" 'n, or absent with core disabled; otherwise boot-time disable required'
    done
}

check_bpf() {
    local lsm
    if lsm=$(read_file /sys/kernel/security/lsm); then
        if [[ ,$lsm, == *,bpf,* ]]; then
            report PASS 'BPF LSM' 'bpf appears in the active runtime LSM list.'
        else report FAIL 'BPF LSM' 'bpf is absent from the active LSM list; CONFIG_BPF_LSM alone does not activate it.'; fi
    else
        lsm='<unavailable>'
        report UNKNOWN 'BPF LSM' 'Cannot read /sys/kernel/security/lsm; runtime activation is not established.'
    fi
    evidence /sys/kernel/security/lsm "$lsm" 'list containing bpf'
}

main() {
    while (( $# )); do
        case $1 in
            -h|--help) usage; return 0;;
            --list-keys) LIST_KEYS=1; shift;;
            --handheld) HANDHELD=1; shift;;
            --color|--color=*)
                if [[ $1 == --color ]]; then
                    if (( $# < 2 )); then printf 'Missing value for --color\n' >&2; return 64; fi
                    COLOR_MODE=$2; shift 2
                else COLOR_MODE=${1#*=}; shift; fi
                case $COLOR_MODE in auto|always|never) :;; *) printf 'Invalid color mode: %s\n' "$COLOR_MODE" >&2; return 64;; esac;;
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
    setup_color
    if (( LIST_KEYS )); then
        warning 'INFERRED candidates, not an official Epic key allowlist. See docs/signing-keys.md.'
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
    if CMDLINE=$(read_file /proc/cmdline); then CMDLINE_READABLE=1; else CMDLINE=''; fi
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
    check_summary
    printf '\n'
    color_text PASS "$PASSED PASS"; printf ', '
    color_text FAIL "$BLOCKED FAIL"; printf ', '
    color_text UNKNOWN "$UNKNOWN UNKNOWN"; printf ', '
    color_text SKIP "$SKIPPED SKIP"; printf '\n'
    warning 'Signing-key policy and boot attestation require Epic validation. Requirements may change.'
    if (( BLOCKED )); then color_text FAIL 'RESULT: NOT READY: observed requirement blockers.'; printf '\n'; return 1; fi
    color_text UNKNOWN 'RESULT: INDETERMINATE: local checks cannot certify EAC Linux v2 compatibility.'; printf '\n'
    return 2
}

main "$@"
