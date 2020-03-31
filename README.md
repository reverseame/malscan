# MalScan - Volatility Plugin

`MalScan` for Volatility 2.6 aims to detect hidden and injected code, it works similar to [`malfind`](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference-Mal#malfind) official plugin, but it takes advantage of ClamAV to reduce false positives.

## Installation

You can install all dependencies with [setup.sh](setup.sh):

- System: `python-dev`, `clamav`, `clamav-daemon`
- Python 2.7: `distorm3`

After installing ClamAV, you may need to reboot your system to start ClamAV daemon. All communication is done by Unix socket (default path: `/run/clamav/clamd.ctl`)

## Usage

```
---------------------------------
Module MalScan
---------------------------------

Scan with ClamAV for hidden and injected code
    
    Options:
        --ful-scan: scan every VAD marked as executable
```

You need to provide this project path as [first parameter to Volatility](https://github.com/volatilityfoundation/volatility/wiki/Volatility-Usage#specifying-additional-plugin-directories):

```
$ vol.py --plugins /path/to/malscan --profile WinProfile -f /path/to/memory.dump malscan
Volatility Foundation Volatility Framework 2.6.1

Process: ALINA_HQWLKC.e Pid: 108 Space Address: 0xb30000-0xb54fff
Vad Tag: Vad  Protection: PAGE_EXECUTE_WRITECOPY
Flags: CommitCharge: 5, Protection: 7, VadType: 2
Scan result: Win.Trojan.Alina-4

0x00b30000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
0x00b30010  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
0x00b30020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x00b30030  00 00 00 00 00 00 00 00 00 00 00 00 f0 00 00 00   ................
```

## License

Licensed under the [GNU AGPLv3](LICENSE) license.
