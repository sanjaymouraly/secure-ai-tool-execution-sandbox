#!/usr/bin/env python3
"""Generate the hardened seccomp profile used by the sandbox broker.

The profile is derived from Docker's official default profile so that it stays
compatible with the runtime, and then hardened further:

* every networking syscall is removed (``connect``/``bind``/``listen``/...),
  and ``socket`` is only allowed for non-INET families;
* namespace, mount, tracing, eBPF and kernel module primitives are removed;
* ``clone`` is only allowed for thread creation (no new namespaces).

Usage::

    python scripts/build_seccomp_profile.py \
        --source docker/seccomp/upstream-default.json \
        --output docker/seccomp/sandbox.json

The upstream profile is vendored at ``docker/seccomp/upstream-default.json``
(Apache-2.0, from the moby project) so the build is reproducible offline.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

#: Syscalls that must never be available inside the sandbox.
BLOCKED = {
    # namespace / mount
    "mount",
    "umount",
    "umount2",
    "pivot_root",
    "chroot",
    "setns",
    "unshare",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    "move_mount",
    "open_tree",
    "mount_setattr",
    "statmount",
    "listmount",
    "open_by_handle_at",
    "name_to_handle_at",
    # tracing / process inspection
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "process_madvise",
    "process_mrelease",
    "pidfd_getfd",
    "pidfd_open",
    "pidfd_send_signal",
    "kcmp",
    "lookup_dcookie",
    # kernel modules / eBPF / perf
    "init_module",
    "finit_module",
    "delete_module",
    "kexec_load",
    "kexec_file_load",
    "bpf",
    "perf_event_open",
    "userfaultfd",
    "memfd_secret",
    "landlock_add_rule",
    "landlock_create_ruleset",
    "landlock_restrict_self",
    # privileged host operations
    "reboot",
    "settimeofday",
    "stime",
    "clock_settime",
    "clock_settime64",
    "syslog",
    "quotactl",
    "quotactl_fd",
    "iopl",
    "ioperm",
    "vhangup",
    "acct",
    "get_mempolicy",
    "mbind",
    "set_mempolicy",
    "add_key",
    "keyctl",
    "request_key",
    "setdomainname",
    "sethostname",
    "personality",
    "fanotify_init",
    "fanotify_mark",
    # networking
    "connect",
    "bind",
    "listen",
    "accept",
    "accept4",
    "sendto",
    "sendmsg",
    "sendmmsg",
    "recvfrom",
    "recvmsg",
    "recvmmsg",
    "send",
    "recv",
    "getpeername",
    "getsockname",
    "setsockopt",
    "getsockopt",
    "socketcall",
    "socket",
}

#: ``clone`` is allowed only when it does not create a new namespace.
CLONE_NEWNS = 0x00020000
CLONE_NEWCGROUP = 0x02000000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000
NAMESPACE_MASK = (
    CLONE_NEWNS
    | CLONE_NEWCGROUP
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWUSER
    | CLONE_NEWPID
    | CLONE_NEWNET
)


def build(source: Path) -> dict:
    upstream = json.loads(source.read_text(encoding="utf-8"))
    allow_names: list[str] = []
    for group in upstream.get("syscalls", []):
        if group.get("action") != "SCMP_ACT_ALLOW":
            continue
        includes = group.get("includes") or {}
        if "caps" in includes:
            # Capability gated groups are irrelevant: every capability is
            # dropped for the sandbox container.
            continue
        for name in group.get("names", []):
            if name in BLOCKED or name in {"clone", "clone3", "socket"}:
                continue
            allow_names.append(name)

    allow_names = sorted(set(allow_names))

    profile = {
        "defaultAction": "SCMP_ACT_ERRNO",
        "defaultErrnoRet": 1,
        "archMap": upstream.get(
            "archMap",
            [
                {
                    "architecture": "SCMP_ARCH_X86_64",
                    "subArchitectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"],
                },
                {
                    "architecture": "SCMP_ARCH_AARCH64",
                    "subArchitectures": ["SCMP_ARCH_ARM"],
                },
            ],
        ),
        "syscalls": [
            {
                "names": allow_names,
                "action": "SCMP_ACT_ALLOW",
                "comment": "Baseline: Docker default profile minus networking, "
                "namespace, tracing and eBPF primitives",
            },
            {
                "names": ["clone"],
                "action": "SCMP_ACT_ALLOW",
                "args": [
                    {
                        "index": 0,
                        "value": NAMESPACE_MASK,
                        "op": "SCMP_CMP_MASKED_EQ",
                    }
                ],
                "comment": "clone() is allowed only when no new namespace is requested",
            },
            {
                "names": ["clone3"],
                "action": "SCMP_ACT_ERRNO",
                "errnoRet": 38,
                "comment": "clone3() is not available; glibc falls back to clone()",
            },
            {
                "names": sorted(BLOCKED),
                "action": "SCMP_ACT_ERRNO",
                "errnoRet": 1,
                "comment": "Blocked: networking, namespace, tracing, eBPF and kernel module primitives",
            },
        ],
    }
    return profile


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "docker"
        / "seccomp"
        / "upstream-default.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "docker"
        / "seccomp"
        / "sandbox.json",
    )
    args = parser.parse_args()

    profile = build(args.source)
    args.output.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    allowed = len(profile["syscalls"][0]["names"])
    print(f"wrote {args.output} ({allowed} allowed syscalls, {len(BLOCKED)} blocked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
