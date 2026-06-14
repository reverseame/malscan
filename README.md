# MalScan — Volatility 3 Plugin

`MalScan` is a [Volatility 3](https://github.com/volatilityfoundation/volatility3) plugin that detects **hidden and injected code** in a Windows memory dump. It works similarly to the official [`malfind`](https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html#module-volatility3.plugins.windows.malfind) plugin, but it leverages **ClamAV** to reduce false positives.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

> This is the Volatility 3 port. The original Volatility 2.6 version is preserved on the [`volatility2-latest`](../../tree/volatility2-latest) branch.

## How it works

For every process, `MalScan` walks the VAD tree and selects regions that look like
they might contain injected code (the same criteria as the original plugin):

- With `--full-scan`: every VAD whose original protection is executable.
- By default: VADs with `EXECUTE`+`WRITE` protection matching a known injection
  pattern (private `VadS` from `VirtualAlloc`, Stuxnet-style mapped regions, or the
  main `.exe` module to catch process hollowing).

Each candidate region is scanned with **ClamAV** (over its Unix socket). If ClamAV
does not flag it, a set of byte-based heuristics is applied: suspicious PE header,
function prologue (`push ebp ; mov ebp, esp`), or a wiped PE header at the base.
If ClamAV is unavailable, the plugin transparently falls back to the heuristics only.

## Installation

[Volatility 3](https://github.com/volatilityfoundation/volatility3) and ClamAV must be
installed. You can install the dependencies with [setup.sh](setup.sh):

- System: `clamav`, `clamav-daemon`
- Python: `volatility3`

After installing ClamAV, make sure the daemon is running and exposes its Unix socket
(default path: `/run/clamav/clamd.ctl`). You may need to reboot your system.

Then either pass the plugin directory at runtime with `-p` / `--plugin-dirs`, or copy
`malscan.py` and `clamav.py` together under `volatility3/framework/plugins/windows/`.

## Usage

```
usage: vol.py malscan.MalScan [-h] [--pid [PID ...]] [--full-scan]
                              [--clamd-socket CLAMD-SOCKET]

Scan with ClamAV for hidden and injected code.

  --pid [PID ...]               Process IDs to include (all other processes are excluded)
  --full-scan                   Scan every VAD marked as executable
  --clamd-socket CLAMD-SOCKET   Path to the clamd Unix socket (default: /run/clamav/clamd.ctl)
```

Example:

```
$ vol.py -p /path/to/malscan -f /path/to/memory.dump malscan.MalScan
Volatility 3 Framework

PID   Process         Start     End       Tag   Protection              CommitCharge  PrivateMemory  Result              Hexdump   Disasm
108   ALINA_HQWLKC.e  0xb30000  0xb54fff   VadS  PAGE_EXECUTE_WRITECOPY  5             1              Win.Trojan.Alina-4  ...       ...
```

## License

Licensed under the [GNU AGPLv3](LICENSE) license.

(c) RME-DisCo Research Group, University of Zaragoza (Spain). Visit our website to know more about us! https://www.reversea.me
