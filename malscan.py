# This file is part of malscan, a Volatility plugin developed at the
# RME-DisCo Research Group, University of Zaragoza (Spain).
#
# malscan detects hidden and injected code in a Windows memory image, similar
# to the official malfind plugin, but it leverages ClamAV to reduce false
# positives.
#
# This is the Volatility 3 port of the original Volatility 2 plugin.
#
# Authors:
#     Daniel Uroz (original author)
#     Ricardo J. Rodriguez
#
# Licensed under the GNU AGPLv3 license.

import io
import logging
import os
import re
import struct
import sys
from typing import List

from volatility3.framework import exceptions, interfaces, renderers, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, vadinfo

# Volatility 3 loads this file as volatility3.plugins.malscan, so the vendored
# clamav client (a sibling file) is not importable by its bare name. Make the
# plugin's own directory importable so "import clamav" resolves regardless of
# how this module is loaded.
_PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
if _PLUGIN_DIR not in sys.path:
    sys.path.append(_PLUGIN_DIR)

import clamav

vollog = logging.getLogger(__name__)

# Default clamd Unix socket (see /etc/clamav/clamd.conf -> LocalSocket).
DEFAULT_CLAMD_SOCKET = "/run/clamav/clamd.ctl"
PAGE_SIZE = 0x1000

# Function prologue (push base pointer, set up the stack frame):
#   55 89 e5     push ebp ; mov ebp, esp        (32-bit)
#   55 8b ec     push ebp ; mov ebp, esp        (32-bit)
#   55 48 ..     push rbp ; <REX.W frame setup> (x64, e.g. mov/lea rbp, rsp)
# The x64 form is matched loosely on the "push rbp + REX.W" pair (as the
# modern malfind does), since the frame setup that follows varies
# (mov rbp,rsp / lea rbp,[rsp] / sub rsp,N). ClamAV remains the primary
# false-positive filter.
FUNCTION_PROLOGUE = re.compile(b"\x55(\x89\xe5|\x8b\xec|\x48)", re.DOTALL)


class MalScan(interfaces.plugins.PluginInterface):
    """Scan with ClamAV for hidden and injected code."""

    _required_framework_version = (2, 22, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="vadinfo", component=vadinfo.VadInfo, version=(2, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to include (all other processes are excluded)",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="full-scan",
                description="Scan every VAD marked as executable",
                default=False,
                optional=True,
            ),
            requirements.StringRequirement(
                name="clamd-socket",
                description="Path to the clamd Unix socket (default: {})".format(
                    DEFAULT_CLAMD_SOCKET
                ),
                default=DEFAULT_CLAMD_SOCKET,
                optional=True,
            ),
        ]

    def _setup_clamav(self) -> None:
        """Connect to clamd and probe it once. If it is unreachable, disable
        ClamAV scanning and rely solely on the byte-based heuristics instead of
        failing (and warning) on every single VAD during the scan."""

        self._av = clamav.ClamdUnixSocket(path=self.config["clamd-socket"])
        try:
            self._av.ping()
            self._av_available = True
        except clamav.ClamdError as exc:
            vollog.warning(
                "ClamAV unavailable at %s, using heuristics only: %s",
                self.config["clamd-socket"],
                exc,
            )
            self._av_available = False

    @staticmethod
    def _file_name(vad) -> object:
        """Return the file name backing a VAD, or None if it has none.

        get_file_name() returns a NotApplicableValue for short VADs (no mapped
        file) and never raises (it suppresses InvalidAddressException)."""

        name = vad.get_file_name()
        return name if isinstance(name, str) else None

    @staticmethod
    def _is_vad_empty(proc_layer, vad) -> bool:
        """Check if a VAD region is either entirely unavailable due to paging,
        entirely consisting of zeros, or a combination of the two. This helps
        ignore false positives whose VAD flags match the injection filter but
        there's no data and thus not worth reporting it."""

        all_zero_page = b"\x00" * PAGE_SIZE
        offset = 0
        vad_length = vad.get_size()
        while offset < vad_length:
            next_addr = vad.get_start() + offset
            if proc_layer.is_valid(next_addr, PAGE_SIZE) and (
                proc_layer.read(next_addr, PAGE_SIZE) != all_zero_page
            ):
                return False
            offset += PAGE_SIZE
        return True

    def _vad_filter(self, vad, protection: str) -> bool:
        """Looks for committed, memory-resident allocations whose original
        protection includes write and execute (or just execute under
        --full-scan) and that match a known injection pattern.

        @param vad: an MMVAD object
        @param protection: the VAD's protection string (e.g. PAGE_EXECUTE_READWRITE)

        @returns True if the MMVAD looks like it might contain injected code."""

        # Check section executable if --full-scan
        if self.config["full-scan"]:
            return "EXECUTE" in protection

        write_exec = "EXECUTE" in protection and "WRITE" in protection

        # Write/Execute check applies to everything
        if not write_exec:
            return False

        # Typical VirtualAlloc injection
        if vad.get_private_memory() == 1 and vad.get_tag() == "VadS":
            return True

        # Stuxnet-style injection
        if vad.get_private_memory() == 0 and protection != "PAGE_EXECUTE_WRITECOPY":
            return True

        # Main executable module to check it is not process hollowed
        file_name = self._file_name(vad)
        if file_name is not None and file_name.lower().endswith(".exe"):
            return True

        return False

    @staticmethod
    def _is_pe(data: bytes) -> bool:
        if data[:0x2] == b"\x4d\x5a" and len(data) >= 0x40:  # MZ
            pe_offset = struct.unpack("<I", data[0x3c:0x40])[0]  # e_lfanew is a 4-byte DWORD
            if data[pe_offset:pe_offset + 0x2] == b"\x50\x45":  # PE
                return True
        return False

    def is_malicious(self, vad, data: bytes):
        """Scan bytes with ClamAV to find malicious code. If none found, it
        tries to search by special bytes construction.

        @param vad: Vad object
        @param data: Vad content

        @returns tuple of (message, offset)"""

        # Scan with ClamAV. On any clamd communication error (daemon down,
        # wrong socket path, buffer > StreamMaxLength, ...) degrade gracefully
        # to the byte-based heuristics instead of crashing the whole plugin.
        status, result = "ERROR", None
        if self._av_available:
            try:
                _, status, result = self._av.instream(io.BytesIO(data))
            except clamav.ClamdError as exc:
                vollog.warning("ClamAV scan failed, using heuristics only: %s", exc)
                self._av_available = False

        # ClamAV match
        if status == "FOUND":
            return result, 0

        # Search for PE header if it doesn't have any file object associated
        if self._file_name(vad) is None and self._is_pe(data):
            return "Suspicious PE header", 0

        # Function prologue
        match = FUNCTION_PROLOGUE.search(data[:0x20])
        if match:
            return "Suspicious function prologue", match.start(0)

        # First page filled with all-zeros and a function prologue at the
        # beginning of the next one possibly indicates wiped PE headers
        if data[:0x1000].count(0) == 0x1000:
            next_page = data[0x1000:0x2000]
            match = FUNCTION_PROLOGUE.search(next_page[:0x4])
            if match:
                return "Possible wiped PE header at base", 0x1000

        return None, None

    def _generator(self, procs):
        kernel = self.context.modules[self.config["kernel"]]

        # Cache the protection values table once for the whole run.
        protect_values = vadinfo.VadInfo.protect_values(
            self.context, kernel.layer_name, kernel.symbol_table_name
        )
        is_32bit_arch = not symbols.symbol_table_is_64bit(
            context=self.context, symbol_table_name=kernel.symbol_table_name
        )

        for proc in procs:
            proc_id = proc.UniqueProcessId
            proc_name = utility.array_to_string(proc.ImageFileName)
            try:
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException:
                vollog.debug("Unable to access layer for process %s", proc_id)
                continue
            proc_layer = self.context.layers[proc_layer_name]

            for vad in proc.get_vad_root().traverse():
                protection = vad.get_protection(
                    protect_values, vadinfo.winnt_protections
                )
                if not self._vad_filter(vad, protection):
                    continue
                if self._is_vad_empty(proc_layer, vad):
                    continue

                vad_bytes = proc_layer.read(
                    vad.get_start(), vad.get_size(), pad=True
                )

                scan_result, where = self.is_malicious(vad, vad_bytes)
                if not scan_result:
                    continue

                shown = vad_bytes[where:where + 64]

                # Disassemble opcodes if it is not a PE header. wow64 processes
                # on a 64-bit kernel still need 32-bit disassembly.
                if self._is_pe(vad_bytes):
                    disasm = renderers.NotApplicableValue()
                else:
                    architecture = (
                        "intel"
                        if (is_32bit_arch or proc.get_is_wow64())
                        else "intel64"
                    )
                    disasm = renderers.Disassembly(
                        shown, vad.get_start() + where, architecture
                    )

                yield (
                    0,
                    (
                        proc_id,
                        proc_name,
                        format_hints.Hex(vad.get_start()),
                        format_hints.Hex(vad.get_end()),
                        vad.get_tag(),
                        protection,
                        vad.get_commit_charge(),
                        vad.get_private_memory(),
                        scan_result,
                        format_hints.HexBytes(shown),
                        disasm,
                    ),
                )

    def run(self):
        self._setup_clamav()

        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Start", format_hints.Hex),
                ("End", format_hints.Hex),
                ("Tag", str),
                ("Protection", str),
                ("CommitCharge", int),
                ("PrivateMemory", int),
                ("Result", str),
                ("Hexdump", format_hints.HexBytes),
                ("Disasm", renderers.Disassembly),
            ],
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    kernel_module_name=self.config["kernel"],
                    filter_func=filter_func,
                )
            ),
        )
