"""Run the real Bash checker against temporary Linux filesystem snapshots."""
import gzip
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "eacv2-check.sh"
GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"


class CheckerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.put("etc/os-release", 'ID=manjaro\nPRETTY_NAME="Manjaro Linux"\n')
        self.put("proc/sys/kernel/osrelease", "6.18-test\n")
        self.put("proc/cmdline", "lockdown=integrity sysctl.kernel.kexec_load_disabled=1\n")
        self.put("proc/sys/kernel/kexec_load_disabled", "1\n")
        self.put("proc/sys/kernel/tainted", "0\n")
        self.put("sys/kernel/kexec_loaded", "0\n")
        self.put("sys/kernel/kexec_crash_loaded", "0\n")
        self.put("sys/kernel/security/lockdown", "none [integrity] confidentiality\n")
        self.put("sys/kernel/security/lsm", "capability,lockdown,yama,bpf\n")
        self.put("sys/class/tpm/tpm0/tpm_version_major", "2\n")
        self.put("sys/kernel/security/tpm0/binary_bios_measurements", b"example event log")
        self.put("sys/kernel/iommu_groups/0/type", "DMA-FQ\n")
        self.put(f"sys/firmware/efi/efivars/SecureBoot-{GUID}", b"\x07\0\0\0\x01")
        self.put(f"sys/firmware/efi/efivars/SetupMode-{GUID}", b"\x07\0\0\0\x00")

    def put(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else value.encode())

    def run_check(self, *args, env=None):
        return subprocess.run(["bash", str(SCRIPT), "--root", str(self.root), *args],
                              text=True, capture_output=True, timeout=15, env=env)

    def status(self, result, check, expected):
        self.assertRegex(result.stdout, rf"(?m)^\[{expected}\] {check}:", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_good_local_evidence_does_not_certify_epic_trust(self):
        r = self.run_check()
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        for check in ("TPM 2.0", "Secure Boot", "IOMMU", "Lockdown", "Kexec", "BPF LSM"):
            self.status(r, check, "PASS")
        for check in ("Signed kernel and modules", "Measured boot"):
            self.status(r, check, "UNKNOWN")
        self.assertIn("INDETERMINATE", r.stdout)

    def test_final_summary_lists_all_eight_checks_in_execution_order(self):
        r = self.run_check()
        self.assertIn("Check summary:\n", r.stdout)
        summary = r.stdout.split("Check summary:\n", 1)[1]
        expected = [
            "  [UNKNOWN] Signed kernel and modules",
            "  [PASS] TPM 2.0",
            "  [PASS] Secure Boot",
            "  [UNKNOWN] Measured boot",
            "  [PASS] IOMMU",
            "  [PASS] Lockdown",
            "  [PASS] Kexec",
            "  [PASS] BPF LSM",
        ]
        self.assertEqual(summary.splitlines()[:8], expected)
        self.assertIn("6 PASS, 0 FAIL, 2 UNKNOWN, 0 SKIP", summary)
        self.assertTrue(summary.rstrip().endswith(
            "RESULT: INDETERMINATE: local checks cannot certify EAC Linux v2 compatibility."))
        self.assertEqual(r.returncode, 2)

    def test_final_summary_preserves_failure_and_skip_results(self):
        self.put("sys/kernel/security/lsm", "capability,lockdown\n")
        r = self.run_check("--handheld")
        self.assertIn("Check summary:\n", r.stdout)
        summary = r.stdout.split("Check summary:\n", 1)[1]
        self.assertIn("  [SKIP] IOMMU\n", summary)
        self.assertIn("  [FAIL] BPF LSM\n", summary)
        self.assertIn("4 PASS, 1 FAIL, 2 UNKNOWN, 1 SKIP", summary)
        self.assertEqual(r.returncode, 1)

    def test_final_summary_uses_status_colors(self):
        r = self.run_check("--color=always")
        self.assertIn("Check summary:\n", r.stdout)
        summary = r.stdout.split("Check summary:\n", 1)[1]
        self.assertIn("  \x1b[32m[PASS]\x1b[0m TPM 2.0\n", summary)
        self.assertIn("  \x1b[33m[UNKNOWN]\x1b[0m Measured boot\n", summary)

    def test_forced_color_distinguishes_pass_fail_and_unknown(self):
        self.put("proc/cmdline", "iommu=pt\n")
        r = self.run_check("--color=always")
        self.assertIn("\x1b[32m[PASS]\x1b[0m", r.stdout)
        self.assertIn("\x1b[31m[FAIL]\x1b[0m", r.stdout)
        self.assertIn("\x1b[33m[UNKNOWN]\x1b[0m", r.stdout)
        self.assertIn("\x1b[33m[WARN]\x1b[0m", r.stdout)
        self.assertIn("\x1b[31mRESULT: NOT READY:", r.stdout)
        self.assertEqual(r.returncode, 1)

    def test_automatic_color_stays_plain_when_captured(self):
        env = os.environ.copy()
        env.pop("NO_COLOR", None)
        env["TERM"] = "xterm-256color"
        self.assertNotIn("\x1b[", self.run_check(env=env).stdout)

    def test_color_never_and_invalid_color_mode(self):
        r = self.run_check("--color=never")
        self.assertEqual(r.returncode, 2)
        self.assertNotIn("\x1b[", r.stdout)
        self.assertEqual(self.run_check("--color=rainbow").returncode, 64)
        self.assertEqual(self.run_check("--color").returncode, 64)

    def test_explicit_color_setting_overrides_no_color_environment(self):
        env = os.environ.copy()
        env["NO_COLOR"] = "1"
        self.assertIn("\x1b[", self.run_check("--color", "always", env=env).stdout)
        self.assertNotIn("\x1b[", self.run_check(env=env).stdout)

    def test_disabled_runtime_features_fail_even_with_good_boot_arguments(self):
        self.put("sys/kernel/security/lockdown", "[none] integrity confidentiality\n")
        self.put("proc/sys/kernel/kexec_load_disabled", "0\n")
        self.put("sys/kernel/security/lsm", "capability,lockdown\n")
        r = self.run_check()
        self.assertEqual(r.returncode, 1)
        for check in ("Lockdown", "Kexec", "BPF LSM"):
            self.status(r, check, "FAIL")

    def test_runtime_disable_alone_does_not_prove_boot_time_disable(self):
        self.put("proc/cmdline", "quiet\n")
        r = self.run_check()
        self.status(r, "Kexec", "UNKNOWN")
        self.status(r, "Lockdown", "UNKNOWN")

    def test_loaded_kexec_image_fails_even_if_loading_is_now_disabled(self):
        self.put("sys/kernel/kexec_loaded", "1\n")
        self.status(self.run_check(), "Kexec", "FAIL")

    def test_unsigned_module_history_is_a_failure(self):
        self.put("proc/sys/kernel/tainted", "8192\n")
        self.status(self.run_check(), "Signed kernel and modules", "FAIL")

    def test_unsigned_or_unverified_loaded_modules_are_named(self):
        self.put("proc/sys/kernel/tainted", "8192\n")
        self.put("sys/module/nvidia/taint", "OE\n")
        self.put("sys/module/unsigned_driver/taint", "E\n")
        self.put("sys/module/other_driver/taint", "PO\n")
        self.put("sys/module/clean_driver/taint", "\n")
        r = self.run_check()
        self.status(r, "Signed kernel and modules", "FAIL")
        self.assertIn("  - nvidia (taint=OE)", r.stdout)
        self.assertIn("  - unsigned_driver (taint=E)", r.stdout)
        self.assertNotIn("  - other_driver", r.stdout)
        self.assertNotIn("  - clean_driver", r.stdout)

    def test_module_e_taint_is_a_blocker_without_global_taint_evidence(self):
        (self.root / "proc/sys/kernel/tainted").unlink()
        self.put("sys/module/unverified_driver/taint", "OE\n")
        r = self.run_check()
        self.status(r, "Signed kernel and modules", "FAIL")
        self.assertIn("  - unverified_driver (taint=OE)", r.stdout)

    def test_empty_loaded_module_list_does_not_clear_boot_taint(self):
        self.put("proc/sys/kernel/tainted", "8192\n")
        (self.root / "sys/module").mkdir(parents=True)
        r = self.run_check()
        self.status(r, "Signed kernel and modules", "FAIL")
        self.assertIn("No loaded modules with E taint found", r.stdout)
        self.assertIn("persists after unloading", r.stdout)

    def test_unavailable_module_taint_is_reported_without_claiming_a_clean_list(self):
        r = self.run_check()
        self.assertIn("Loaded module taint list unavailable", r.stdout)
        self.assertNotIn("No loaded modules with E taint found", r.stdout)

    def test_snapshot_module_taint_does_not_follow_external_symlinks(self):
        outside = self.root.parent / (self.root.name + "-module-taint")
        outside.write_text("E\n")
        self.addCleanup(outside.unlink)
        path = self.root / "sys/module/external_driver/taint"
        path.parent.mkdir(parents=True)
        path.symlink_to(outside)
        r = self.run_check()
        self.status(r, "Signed kernel and modules", "UNKNOWN")
        self.assertNotIn("  - external_driver", r.stdout)
        self.assertIn("1 module taint file(s) unreadable", r.stdout)

    def test_proprietary_and_out_of_tree_taints_do_not_mean_unsigned(self):
        self.put("proc/sys/kernel/tainted", "4097\n")
        self.status(self.run_check(), "Signed kernel and modules", "UNKNOWN")

    def test_secure_boot_reads_data_after_efi_attributes(self):
        self.put(f"sys/firmware/efi/efivars/SecureBoot-{GUID}", b"\x01\0\0\0\x00")
        self.status(self.run_check(), "Secure Boot", "FAIL")

    def test_setup_mode_is_a_failure(self):
        self.put(f"sys/firmware/efi/efivars/SetupMode-{GUID}", b"\x07\0\0\0\x01")
        self.status(self.run_check(), "Secure Boot", "FAIL")

    def test_missing_securityfs_is_unknown(self):
        (self.root / "sys/kernel/security/lockdown").unlink()
        (self.root / "sys/kernel/security/lsm").unlink()
        r = self.run_check()
        self.status(r, "Lockdown", "UNKNOWN")
        self.status(r, "BPF LSM", "UNKNOWN")

    def test_tpm_1_is_not_tpm_2(self):
        self.put("sys/class/tpm/tpm0/tpm_version_major", "1\n")
        self.status(self.run_check(), "TPM 2.0", "FAIL")

    def test_second_tpm_can_be_tpm2(self):
        self.put("sys/class/tpm/tpm0/tpm_version_major", "1\n")
        self.put("sys/class/tpm/tpm1/tpm_version_major", "2\n")
        self.status(self.run_check(), "TPM 2.0", "PASS")

    def test_identity_domain_is_passthrough(self):
        self.put("sys/kernel/iommu_groups/1/type", "identity\n")
        self.status(self.run_check(), "IOMMU", "FAIL")

    def test_tpm_evidence_lists_every_device_with_current_and_expected_versions(self):
        self.put("sys/class/tpm/tpm0/tpm_version_major", "1\n")
        self.put("sys/class/tpm/tpm1/tpm_version_major", "3\n")
        r = self.run_check()
        self.assertIn("tpm0/tpm_version_major: current=1; expected=2", r.stdout)
        self.assertIn("tpm1/tpm_version_major: current=3; expected=2", r.stdout)

    def test_secure_boot_evidence_includes_both_variables_even_when_disabled(self):
        self.put(f"sys/firmware/efi/efivars/SecureBoot-{GUID}", b"\x07\0\0\0\x00")
        self.put(f"sys/firmware/efi/efivars/SetupMode-{GUID}", b"\x07\0\0\0\x01")
        r = self.run_check()
        self.assertIn("SecureBoot: current=0; expected=1", r.stdout)
        self.assertIn("SetupMode: current=1; expected=0", r.stdout)

    def test_invalid_efi_byte_is_shown_without_being_accepted(self):
        self.put(f"sys/firmware/efi/efivars/SecureBoot-{GUID}", b"\x07\0\0\0\x02")
        r = self.run_check()
        self.status(r, "Secure Boot", "UNKNOWN")
        self.assertIn("SecureBoot: current=2; expected=1", r.stdout)

    def test_kexec_failure_lists_both_loaded_images_and_runtime_disable_state(self):
        self.put("sys/kernel/kexec_loaded", "1\n")
        self.put("sys/kernel/kexec_crash_loaded", "1\n")
        self.put("proc/sys/kernel/kexec_load_disabled", "0\n")
        r = self.run_check()
        self.status(r, "Kexec", "FAIL")
        for label, current, expected in (("kernel.kexec_load_disabled", 0, 1),
                                         ("/sys/kernel/kexec_loaded", 1, 0),
                                         ("/sys/kernel/kexec_crash_loaded", 1, 0)):
            self.assertIn(f"{label}: current={current}; expected={expected}", r.stdout)

    def test_lockdown_failure_shows_active_mode_and_boot_option(self):
        self.put("sys/kernel/security/lockdown", "[none] integrity confidentiality\n")
        self.put("proc/cmdline", "quiet lockdown=confidentiality\n")
        r = self.run_check()
        self.assertIn("/sys/kernel/security/lockdown: current=[none] integrity confidentiality; expected=integrity active at boot", r.stdout)
        self.assertIn("lockdown boot parameter: current=confidentiality; expected=integrity", r.stdout)

    def test_missing_bpf_lsm_shows_actual_runtime_list(self):
        self.put("sys/kernel/security/lsm", "capability,lockdown,yama\n")
        r = self.run_check()
        self.assertIn("/sys/kernel/security/lsm: current=capability,lockdown,yama; expected=list containing bpf", r.stdout)

    def test_module_taint_evidence_shows_current_and_expected_flags(self):
        self.put("sys/module/nvidia/taint", "OE\n")
        r = self.run_check()
        self.assertIn("nvidia (taint=OE)", r.stdout)
        self.assertIn("expected=no E taint", r.stdout)

    def test_iommu_group_evidence_states_expected_domain_types(self):
        self.put("sys/kernel/iommu_groups/7/type", "identity\n")
        r = self.run_check()
        self.assertIn("IOMMU group 7: type=identity", r.stdout)
        self.assertIn("expected=DMA or DMA-FQ", r.stdout)

    def test_iommu_failure_lists_all_relevant_boot_arguments(self):
        self.put("proc/cmdline", "iommu=pt iommu.passthrough=1\n")
        r = self.run_check()
        self.assertIn("IOMMU boot argument: current=iommu=pt; expected=hardware translation", r.stdout)
        self.assertIn("IOMMU boot argument: current=iommu.passthrough=1; expected=hardware translation", r.stdout)

    def test_iommu_boot_and_group_blockers_do_not_count_as_two_checks(self):
        self.put("proc/cmdline", "iommu=pt\n")
        self.put("sys/kernel/iommu_groups/7/type", "identity\n")
        r = self.run_check()
        self.assertEqual(r.stdout.count("[FAIL] IOMMU:"), 1)
        self.assertIn("IOMMU group 7: type=identity", r.stdout)
        self.assertIn("1 FAIL", r.stdout)

    def test_all_measured_boot_logs_report_their_observed_state(self):
        self.put("sys/kernel/security/tpm0/binary_bios_measurements", b"")
        self.put("sys/kernel/security/tpm1/binary_bios_measurements", b"event data")
        r = self.run_check()
        self.assertIn("tpm0/binary_bios_measurements: current=empty; expected=readable nonempty event log", r.stdout)
        self.assertIn("tpm1/binary_bios_measurements: current=readable and nonempty; expected=readable nonempty event log", r.stdout)

    def test_identity_groups_and_their_devices_are_identified(self):
        self.put("sys/kernel/iommu_groups/7/type", "identity\n")
        self.put("sys/kernel/iommu_groups/7/devices/0000:03:00.0/vendor", "0x10de\n")
        self.put("sys/kernel/iommu_groups/7/devices/0000:03:00.1/vendor", "0x10de\n")
        self.put("sys/kernel/iommu_groups/12/type", "identity\n")
        self.put("sys/kernel/iommu_groups/12/devices/0000:04:00.0/vendor", "0x1234\n")
        r = self.run_check()
        self.status(r, "IOMMU", "FAIL")
        self.assertIn("[INFO] IOMMU group 7: type=identity", r.stdout)
        self.assertIn("[INFO] IOMMU group 12: type=identity", r.stdout)
        for address in ("0000:03:00.0", "0000:03:00.1", "0000:04:00.0"):
            self.assertIn(f"  - {address}", r.stdout)
        self.assertNotIn("[INFO] IOMMU group 0:", r.stdout)

    def test_identity_group_without_visible_devices_is_still_identified(self):
        self.put("sys/kernel/iommu_groups/7/type", "identity\n")
        r = self.run_check()
        self.assertIn("[INFO] IOMMU group 7: type=identity", r.stdout)
        self.assertIn("Devices unavailable", r.stdout)

    def test_unreadable_and_unclassified_group_types_are_identified(self):
        (self.root / "sys/kernel/iommu_groups/0/type").unlink()
        self.put("sys/kernel/iommu_groups/2/type", "unmanaged\n")
        r = self.run_check()
        self.status(r, "IOMMU", "UNKNOWN")
        self.assertIn("[INFO] IOMMU group 0: type unreadable", r.stdout)
        self.assertIn("[INFO] IOMMU group 2: type=unmanaged (unclassified)", r.stdout)

    def test_group_devices_do_not_escape_snapshot_root(self):
        self.put("sys/kernel/iommu_groups/7/type", "identity\n")
        outside = self.root.parent / (self.root.name + "-devices")
        (outside / "external-device").mkdir(parents=True)
        self.addCleanup(shutil.rmtree, outside)
        (self.root / "sys/kernel/iommu_groups/7/devices").symlink_to(outside)
        r = self.run_check()
        self.assertIn("[INFO] IOMMU group 7: type=identity", r.stdout)
        self.assertIn("Devices unavailable", r.stdout)
        self.assertNotIn("external-device", r.stdout)

    def test_snapshot_group_devices_are_not_looked_up_using_host_lspci(self):
        self.put("sys/kernel/iommu_groups/7/type", "identity\n")
        self.put("sys/kernel/iommu_groups/7/devices/0000:03:00.0/vendor", "0x10de\n")
        self.put("bin/lspci", '#!/usr/bin/env bash\nprintf "HOST_LOOKUP_SHOULD_NOT_RUN"\n')
        (self.root / "bin/lspci").chmod(0o755)
        env = os.environ.copy()
        env["PATH"] = str(self.root / "bin") + os.pathsep + env["PATH"]
        r = subprocess.run(["bash", str(SCRIPT), "--root", str(self.root)],
                           text=True, capture_output=True, env=env, timeout=15)
        self.assertIn("  - 0000:03:00.0", r.stdout)
        self.assertNotIn("HOST_LOOKUP_SHOULD_NOT_RUN", r.stdout)

    def test_group_without_domain_type_is_not_enough(self):
        (self.root / "sys/kernel/iommu_groups/0/type").unlink()
        self.status(self.run_check(), "IOMMU", "UNKNOWN")

    def test_empty_group_directory_fails(self):
        (self.root / "sys/kernel/iommu_groups/0/type").unlink()
        (self.root / "sys/kernel/iommu_groups/0").rmdir()
        self.status(self.run_check(), "IOMMU", "FAIL")

    def test_passthrough_boot_options_fail(self):
        for arg in ("iommu=pt", "iommu.passthrough=1", "iommu=soft"):
            with self.subTest(arg=arg):
                self.put("proc/cmdline", arg)
                self.status(self.run_check(), "IOMMU", "FAIL")

    def test_config_support_is_not_runtime_activation(self):
        self.put("boot/config-6.18-test", "CONFIG_BPF_LSM=y\n")
        self.put("sys/kernel/security/lsm", "capability,lockdown\n")
        self.status(self.run_check(), "BPF LSM", "FAIL")

    def test_forced_boot_lockdown_and_compiled_out_kexec(self):
        self.put("proc/cmdline", "quiet\n")
        self.put("proc/config.gz", gzip.compress(
            b"CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y\n# CONFIG_KEXEC is not set\n"
            b"# CONFIG_KEXEC_FILE is not set\n# CONFIG_KEXEC_CORE is not set\n"))
        (self.root / "proc/sys/kernel/kexec_load_disabled").unlink()
        r = self.run_check()
        self.status(r, "Lockdown", "PASS")
        self.status(r, "Kexec", "PASS")

    def test_kexec_config_handles_valid_absent_flags(self):
        self.put("proc/cmdline", "quiet\n")
        for path in ("proc/sys/kernel/kexec_load_disabled", "sys/kernel/kexec_loaded",
                     "sys/kernel/kexec_crash_loaded"):
            (self.root / path).unlink()
        cases = (
            ("# CONFIG_KEXEC is not set\n# CONFIG_KEXEC_FILE is not set\n", "PASS"),
            ("CONFIG_KEXEC=n\nCONFIG_KEXEC_FILE=n\n", "PASS"),
            ("# CONFIG_KEXEC_CORE is not set\n", "PASS"),
            ("CONFIG_KEXEC_CORE=n\n", "PASS"),
            ("CONFIG_BPF_LSM=y\n", "UNKNOWN"),
            ("# CONFIG_KEXEC is not set\n", "UNKNOWN"),
            ("CONFIG_KEXEC=y\n# CONFIG_KEXEC_FILE is not set\n", "UNKNOWN"),
            ("# CONFIG_KEXEC is not set\nCONFIG_KEXEC_FILE=y\n", "UNKNOWN"),
            ("CONFIG_KEXEC_CORE=n\nCONFIG_KEXEC=y\n", "UNKNOWN"),
            ("CONFIG_KEXEC_CORE=n\nCONFIG_KEXEC_FILE=y\n", "UNKNOWN"),
        )
        for config, expected in cases:
            with self.subTest(config=config):
                self.put("proc/config.gz", gzip.compress(config.encode()))
                self.status(self.run_check(), "Kexec", expected)

    def test_kexec_runtime_blockers_override_compiled_out_interfaces(self):
        self.put("proc/config.gz", gzip.compress(
            b"# CONFIG_KEXEC is not set\n# CONFIG_KEXEC_FILE is not set\n"))
        for path, value in (("sys/kernel/kexec_loaded", "1\n"),
                            ("sys/kernel/kexec_crash_loaded", "1\n"),
                            ("proc/sys/kernel/kexec_load_disabled", "0\n")):
            with self.subTest(path=path):
                previous = (self.root / path).read_bytes()
                self.put(path, value)
                self.status(self.run_check(), "Kexec", "FAIL")
                self.put(path, previous)

    def test_arguments_after_double_dash_do_not_count(self):
        self.put("proc/cmdline", "-- lockdown=integrity sysctl.kernel.kexec_load_disabled=1\n")
        r = self.run_check()
        self.status(r, "Lockdown", "UNKNOWN")
        self.status(r, "Kexec", "UNKNOWN")

    def test_quoted_boot_values_and_hyphenated_names(self):
        self.put("proc/cmdline", 'lockdown="integrity" sysctl.kernel.kexec-load-disabled="1"\n')
        r = self.run_check()
        self.status(r, "Lockdown", "PASS")
        self.status(r, "Kexec", "PASS")

    def test_handheld_exception_is_explicit(self):
        self.put("sys/kernel/iommu_groups/0/type", "identity\n")
        self.status(self.run_check("--handheld"), "IOMMU", "SKIP")

    def test_snapshot_does_not_execute_os_release(self):
        marker = self.root / "executed"
        self.put("etc/os-release", f'PRETTY_NAME="$(touch {marker})"\n')
        self.run_check()
        self.assertFalse(marker.exists())

    def test_help_and_invalid_arguments(self):
        r = self.run_check("--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("Usage:", r.stdout)
        self.assertEqual(self.run_check("--bogus").returncode, 64)

    def test_missing_explicit_kernel_image_is_not_silently_ignored(self):
        r = self.run_check("--kernel", str(self.root / "missing-image"))
        self.assertEqual(r.returncode, 64)

    def test_missing_snapshot_files_never_fall_back_to_live_host(self):
        for path in self.root.rglob("*"):
            if path.is_file():
                path.unlink()
        r = self.run_check()
        self.status(r, "BPF LSM", "UNKNOWN")
        self.status(r, "Secure Boot", "UNKNOWN")
        self.assertIn("Kernel: unknown", r.stdout)

    def test_other_cpu_vendor_iommu_switch_is_not_a_blocker_by_itself(self):
        self.put("proc/cmdline", "intel_iommu=off\n")
        self.status(self.run_check(), "IOMMU", "PASS")

    def test_confidentiality_is_not_assumed_to_support_eac_bpf(self):
        self.put("sys/kernel/security/lockdown", "none integrity [confidentiality]\n")
        self.status(self.run_check(), "Lockdown", "UNKNOWN")

    def test_truncated_efi_variable_is_unknown(self):
        self.put(f"sys/firmware/efi/efivars/SecureBoot-{GUID}", b"\x07\0\0\0")
        self.status(self.run_check(), "Secure Boot", "UNKNOWN")

    def test_present_but_unreadable_tpm_version_is_unknown(self):
        (self.root / "sys/class/tpm/tpm0/tpm_version_major").unlink()
        self.status(self.run_check(), "TPM 2.0", "UNKNOWN")

    def test_disk_config_does_not_prove_running_kernel_boot_policy(self):
        self.put("proc/cmdline", "quiet\n")
        self.put("boot/config-6.18-test", "CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y\n"
                 "# CONFIG_KEXEC_CORE is not set\n# CONFIG_KEXEC is not set\n"
                 "# CONFIG_KEXEC_FILE is not set\n")
        (self.root / "proc/sys/kernel/kexec_load_disabled").unlink()
        r = self.run_check()
        self.status(r, "Lockdown", "UNKNOWN")
        self.status(r, "Kexec", "UNKNOWN")

    def test_snapshot_outside_symlinks_are_not_accepted(self):
        outside = self.root.parent / (self.root.name + "-outside")
        outside.mkdir()
        self.addCleanup(shutil.rmtree, outside)
        (outside / "config.gz").write_bytes(gzip.compress(
            b"CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y\n"))
        (outside / "cmdline").write_text("lockdown=integrity\n")
        (self.root / "proc/cmdline").unlink()
        (self.root / "proc/cmdline").symlink_to(outside / "cmdline")
        (self.root / "proc/config.gz").symlink_to(outside / "config.gz")
        self.status(self.run_check(), "Lockdown", "UNKNOWN")

    def test_embedded_quotes_do_not_create_a_recognized_parameter_name(self):
        self.put("proc/cmdline", 'lock"down"=integrity\n')
        self.status(self.run_check(), "Lockdown", "UNKNOWN")


@unittest.skipUnless(shutil.which("openssl"), "optional openssl not installed")
class SigningReferenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        shutil.copyfile(SCRIPT, self.root / SCRIPT.name)
        (self.root / "certs").mkdir()
        (self.root / "bin").mkdir()
        cert = self.root / "certs/test.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(self.root / "private.pem"), "-out", str(cert),
                        "-subj", "/CN=Test signing CA", "-days", "1"],
                       check=True, capture_output=True)
        fp = subprocess.check_output(["openssl", "x509", "-in", str(cert), "-noout",
                                      "-fingerprint", "-sha256"], text=True)
        self.fingerprint = fp.strip().split("=")[1].replace(":", "").lower()
        self.registry = self.root / "certs/keys.tsv"
        self.registry.write_text(f"test.pem\tTest vendor\t{self.fingerprint}\t-\tkernel\thttps://example.org/cert\t2026-11-06\n")
        self.image = self.root / "kernel.efi"
        self.image.write_bytes(b"example image")
        self.env = os.environ.copy()
        self.env["PATH"] = str(self.root / "bin") + os.pathsep + self.env["PATH"]

    def run_check(self, *args):
        return subprocess.run(["bash", str(self.root / SCRIPT.name), "--root", str(self.root),
                               *args], text=True, capture_output=True, env=self.env, timeout=15)

    def verifier(self, exit_code):
        # Double only the optional external verifier boundary; openssl and
        # certificate fingerprint checks run for real. Wrong arguments fail.
        path = self.root / "bin/sbverify"
        path.write_text(f'''#!/usr/bin/env bash
[[ $# == 3 && $1 == --cert && $2 == "${{0%/bin/sbverify}}/certs/test.pem" && $3 == "${{0%/bin/sbverify}}/kernel.efi" ]] || exit 99
exit {exit_code}
''')
        path.chmod(0o755)

    def test_kernel_match_requires_successful_external_verification(self):
        self.verifier(0)
        r = self.run_check("--kernel", str(self.image))
        self.assertIn("Kernel signature verifies against inferred Test vendor key", r.stdout)
        self.assertIn("[UNKNOWN] Signed kernel and modules:", r.stdout)
        self.verifier(1)
        r = self.run_check("--kernel", str(self.image))
        self.assertNotIn("signature verifies against", r.stdout)
        self.assertIn("no verification against bundled keys", r.stdout)

    def test_mismatched_certificate_pin_is_never_a_match(self):
        self.verifier(0)
        self.registry.write_text(self.registry.read_text().replace(self.fingerprint, "0" * 64))
        r = self.run_check("--kernel", str(self.image))
        self.assertNotIn("signature verifies against", r.stdout)
        self.assertIn(f"current={self.fingerprint}; expected=" + "0" * 64, r.stdout)

    def test_failed_kernel_verification_lists_attempted_certificate(self):
        self.verifier(1)
        r = self.run_check("--kernel", str(self.image))
        self.assertIn("Test vendor / test.pem", r.stdout)
        self.assertIn("current=verification exit 1; expected=exit 0 for at least one candidate", r.stdout)

    def test_unmatched_module_key_evidence_lists_affected_loaded_modules(self):
        modules_file = Path("/proc/modules")
        if not modules_file.exists() or not modules_file.read_text().strip():
            self.skipTest("requires loaded modules for live modinfo boundary test")
        first_module = modules_file.read_text().split()[0]
        modinfo = self.root / "bin/modinfo"
        modinfo.write_text('''#!/usr/bin/env bash
[[ $# == 5 && $1 == -k && $3 == -F && $4 == sig_key ]] || exit 99
printf 'AA:BB:CC:DD\\n'
''')
        modinfo.chmod(0o755)
        r = subprocess.run(["bash", str(self.root / SCRIPT.name)], text=True,
                           capture_output=True, env=self.env, timeout=15)
        self.assertIn("Module signing-key ID: current=aabbccdd; expected=SKI in preliminary certs/keys.tsv", r.stdout)
        self.assertIn(first_module, r.stdout.split("Affected modules:")[1])

    def test_list_keys_is_explicitly_inferred(self):
        r = self.run_check("--list-keys")
        self.assertEqual(r.returncode, 0)
        self.assertIn("INFERRED", r.stdout)
        self.assertIn(self.fingerprint, r.stdout)


@unittest.skipUnless(shutil.which("openssl"), "optional openssl not installed")
class BundledCertificatesTests(unittest.TestCase):
    def test_registry_fingerprints_and_key_ids_match_real_certificates(self):
        certs = SCRIPT.parent / "certs"
        entries = [line.split("\t") for line in (certs / "keys.tsv").read_text().splitlines()
                   if line and not line.startswith("#")]
        self.assertTrue(entries)
        for entry in entries:
            self.assertEqual(len(entry), 7, entry)
            filename, vendor, fingerprint, ski, role, source, date = entry
            with self.subTest(certificate=filename):
                self.assertNotIn("/", filename)
                self.assertRegex(fingerprint, r"^[0-9a-f]{64}$")
                actual = subprocess.check_output(["openssl", "x509", "-in", str(certs / filename),
                    "-noout", "-fingerprint", "-sha256"], text=True)
                self.assertEqual(actual.strip().split("=")[1].replace(":", "").lower(), fingerprint)
                actual_ski = subprocess.check_output(["openssl", "x509", "-in", str(certs / filename),
                    "-noout", "-ext", "subjectKeyIdentifier"], text=True)
                self.assertEqual(actual_ski.splitlines()[-1].strip().replace(":", "").lower(), ski)
                self.assertTrue(vendor and role and date)
                self.assertTrue(source.startswith("https://"))


if __name__ == "__main__":
    unittest.main()
