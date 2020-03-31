'''
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
'''

import re
import StringIO

import clamav

import volatility.utils as utils
import volatility.debug as debug
import volatility.win32.tasks as tasks
import volatility.plugins.vadinfo as vadinfo

from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address, Bytes
from volatility.plugins.common import AbstractWindowsCommand

try:
    import distorm3
    has_distorm3 = True
except ImportError:
    has_distorm3 = False

class MalScan(AbstractWindowsCommand):
    """
    Scan with ClamAV for hidden and injected code
    
    Options:
        --ful-scan: scan every VAD marked as executable
    """

    def __init__(self, config, *args, **kwargs):
        AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('FULL-SCAN', help='Scan every VAD marked as executable', action='store_true')
        self.addr_space = utils.load_as(self._config)
        self.av = clamav.ClamdUnixSocket()

    def _is_vad_empty(self, vad, address_space):
        """
        Check if a VAD region is either entirely unavailable 
        due to paging, entirely consiting of zeros, or a 
        combination of the two. This helps ignore false positives
        whose VAD flags match task._injection_filter requirements
        but there's no data and thus not worth reporting it. 

        @param vad: an MMVAD object in kernel AS
        @param address_space: the process address space 
        """
        
        PAGE_SIZE = 0x1000
        all_zero_page = '\x00' * PAGE_SIZE

        offset = 0
        while offset < vad.Length:
            next_addr = vad.Start + offset
            if (address_space.is_valid_address(next_addr) and (address_space.read(next_addr, PAGE_SIZE) != all_zero_page)):
                return False
            offset += PAGE_SIZE

        return True

    def calculate(self):
        for task in tasks.pslist(self.addr_space):
            for vad, address_space in task.get_vads(vad_filter=self._vad_filter):
                if self._is_vad_empty(vad, address_space):
                    continue

                vad_bytes = address_space.zread(vad.Start, vad.Length)

                yield (task.ImageFileName,
                       task.UniqueProcessId,
                       vad,
                       vad_bytes)

    def _vad_filter(self, vad):
        """
        This looks for private allocations that are committed, 
        memory-resident, non-empty (not all zeros) and with an 
        original protection that includes write and execute or
        just execute if FULL_SCAN option.

        It is important to note that protections are applied at 
        the allocation granularity (page level). Thus the original
        protection might not be the current protection, and it
        also might not apply to all pages in the VAD range. 

        @param vad: an MMVAD object.

        @returns: True if the MMVAD looks like it might
        contain injected code. 
        """
        protect = vadinfo.PROTECT_FLAGS.get(vad.VadFlags.Protection.v(), "")

        """Check section executable if FULL_SCAN"""
        if self._config.FULL_SCAN:
            return "EXECUTE" in protect
        else:
            write_exec = "EXECUTE" in protect and "WRITE" in protect

            """Write/Execute check applies to everything"""
            if not write_exec:
                return False

            """Typical VirtualAlloc injection"""
            if vad.VadFlags.PrivateMemory == 1 and vad.Tag == "VadS":
                return True

            """Stuxnet-style injection"""
            if (vad.VadFlags.PrivateMemory == 0 and
                    protect != "PAGE_EXECUTE_WRITECOPY"):
                return True

            """Main executable module to check it is not process hollowed"""
            try:
                vad_file_name = vad.FileObject.file_name_with_device().lower()
                if vad_file_name.endswith('.exe'):
                    return True
            except AttributeError:
                pass

        return False

    def unified_output(self, data):
        return TreeGrid([("Process", str),
                       ("Pid", int),
                       ("VadStart", Address),
                       ("VadEnd", Address),
                       ("VadTag", str),
                       ("Protection", str),
                       ("Flags", str),
                       ("Result", str),
                       ("Data", Bytes)],
                        self.generator(data))

    def generator(self, data):
        for process_name, pid, vad, vad_bytes in data:
            scan_result, where = self.is_malicious(vad, vad_bytes)
            if scan_result:
                vad_protection = vadinfo.PROTECT_FLAGS.get(vad.VadFlags.Protection.v(), '')
                yield (0, [str(process_name), 
                           int(pid),
                           Address(vad.Start),
                           Address(vad.End),
                           str(vad.Tag),
                           str(vad_protection),
                           str(vad.VadFlags),
                           str(scan_result),
                           Bytes(vad_bytes[where:where+64])])   

    def render_text(self, outfd, data):
        if not has_distorm3:
            debug.warning("For best results please install distorm3")

        for process_name, pid, vad, vad_bytes in data:
            scan_result, where = self.is_malicious(vad, vad_bytes)

            if scan_result:
                outfd.write('\n')
                outfd.write('Process: {0} Pid: {1} Space Address: {2:#x}-{3:#x}\n'.format(process_name, pid, vad.Start, vad.End))
                vad_protection = vadinfo.PROTECT_FLAGS.get(vad.VadFlags.Protection.v(), '')
                outfd.write('Vad Tag: {0} Protection: {1}\n'.format(vad.Tag, vad_protection))
                outfd.write('Flags: {0}\n'.format(str(vad.VadFlags)))
                outfd.write('Scan result: {0}\n'.format(scan_result))
                outfd.write('\n')

                outfd.write("{0}\n".format("\n".join(
                    ["{0:#010x}  {1:<48}  {2}".format(vad.Start + where + o, h, ''.join(c))
                    for o, h, c in utils.Hexdump(vad_bytes[where:where+64])
                    ])))

                """Dissassemble opcodes if it is not a PE header"""
                if has_distorm3 and not self._is_pe(vad_bytes): # MZ
                    outfd.write('\n')
                    outfd.write("\n".join(
                        ["{0:#010x}  {1:<30}  {2}".format(o, h, i)
                        for o, i, h in Disassemble(vad_bytes[where:where+64], vad.Start + where)
                        ]))
                outfd.write('\n')

    def is_malicious(self, vad, data):
        """
        Scan bytes with ClamAV to find malicious code. If none found, it tries to
        search by special bytes construction.

        @param vad: Vad object
        @param data: Vad content

        @returns tuple of (message, offset)
        """
        _, status, result = self.av.instream(StringIO.StringIO(data))

        """ClamAV match"""
        if status == 'FOUND':
            return result, 0
        else:
            """Search for PE header if it doesn't has any FileObject associated"""
            try:
                vad.FileObject
            except AttributeError:
                if self._is_pe(data):
                    return 'Suspicious PE header', 0

            """Function prologue"""
            match = re.search('\x55(\x89\xe5|\x8b\xec)', data[:0x20], re.DOTALL) # push ebp ; mov ebp, esp
            if match:
                return 'Suspicious function prologue', match.start(0)

            """
            First page filled with all-zeros and a function prologue
            at the beggining of the next one possible indicates wiped
            PE headers
            """
            if data[:0x1000].count(chr(0)) == 0x1000:
                next_page = data[0x1000:0x2000]
                match = re.search( '\x55(\x89\xe5|\x8b\xec)', next_page[:0x3], re.DOTALL) # push ebp ; mov ebp, esp
                if match:
                    return 'Possible wiped PE header at base', 0x1000

        return None, None

    def _is_pe(self, data):
        if data[:0x2] == '\x4d\x5a': # MZ
            pe_offset = ord(data[0x3c])
            if data[pe_offset:pe_offset+0x2] == '\x50\x45': # PE
                return True

        return False

def Disassemble(data, start, bits='32bit'):
    """
    Dissassemble code with distorm3. 

    @param data: python byte str to decode
    @param start: address where `data` is found in memory
    @param bits: use 32bit or 64bit decoding 
    
    @returns: tuple of (offset, instruction, hex bytes)
    """
    if bits == '32bit':
        mode = distorm3.Decode32Bits
    else:
        mode = distorm3.Decode64Bits

    for o, _, i, h in distorm3.DecodeGenerator(start, data, mode):
        yield o, i, h
