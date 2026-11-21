"""Lower supported user x18 instructions for the native macOS checkpoint."""
import argparse
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from kernel_source_verify import Elf

SLOT = 'flat_macos_user_x18'
INSTRUCTION = re.compile(r'^\s*([0-9a-f]+):\s+(\S+)(.*)$')
REGISTER = re.compile(r'\b[wx]18\b')


def replacements(user_elf, objdump):
    elf = Elf(user_elf)
    disassembly = subprocess.run([objdump, '-d', '--no-show-raw-insn', str(user_elf)],
                                 check=True, capture_output=True, text=True).stdout
    changes = {}
    for line in disassembly.splitlines():
        instruction = INSTRUCTION.match(line)
        if not instruction or not REGISTER.search(re.sub(r'<[^>]*>', '', instruction[3].split('//', 1)[0])):
            continue
        pc = int(instruction[1], 16)
        word, = struct.unpack('<I', elf.read(pc, 4))
        if word & 0x7f80001f == 0x52800012:  # MOVZ W/X18
            body = ('stp x16,x17,[sp,#-16]!', f'.inst {word & ~31 | 16:#010x}',
                    f'adrp x17,{SLOT}', f'str x16,[x17,:lo12:{SLOT}]', 'ldp x16,x17,[sp],#16')
        else:
            other = {word & 31, word >> 5 & 31, word >> 10 & 31}
            if word & 0x7fe00000 != 0x1b000000 or word >> 16 & 31 != 18 or 18 in other:
                raise ValueError(f'unsupported native user x18 instruction at {pc:#x}: {line.strip()}')
            # MADD/MSUB with x18 as Rm. Preserve the other source and destination registers.
            temp = next(reg for reg in (16, 17, 15, 14) if reg not in other)
            reg = f'x{temp}'
            body = (f'str {reg},[sp,#-16]!', f'adrp {reg},{SLOT}', f'ldr {reg},[{reg},:lo12:{SLOT}]',
                    f'.inst {(word & ~(31 << 16)) | (temp << 16):#010x}', f'ldr {reg},[sp],#16')
        changes[f'.Lp{pc:x}:\n'] = (word, body)
    return changes


def adapt(image, output, objdump):
    manifest = json.loads((image / 'manifest.json').read_text())
    changes = replacements(Path(manifest['user_elf']), objdump)
    source = (image / 'program.S').resolve()
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        staged = Path(temporary) / 'program.S'
        if not changes:
            staged.write_text(f'#include "{source}"\n')
        else:
            with source.open() as original, staged.open('w') as generated:
                for line in original:
                    generated.write(line)
                    change = changes.pop(line, None) if line.startswith('.Lp') else None
                    if change is None:
                        continue
                    word, body = change
                    opcode = next(original, '').split()
                    if len(opcode) != 2 or opcode[0] != '.inst' or int(opcode[1], 0) != word:
                        raise ValueError(f'native x18 instruction is not emitted as expected at {line.strip()}')
                    generated.writelines(f'    {instruction}\n' for instruction in body)
                if changes:
                    raise ValueError(f'native x18 instruction is missing from the export at {next(iter(changes)).strip()}')
                initial, = struct.unpack_from('<Q', (image / 'initial.bin').read_bytes(), 18 * 8)
                generated.write(f'\n.pushsection .data,"aw"\n.balign 8\n{SLOT}: .quad {initial:#x}\n.popsection\n')
        staged.replace(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--objdump', default='llvm-objdump')
    args = parser.parse_args()
    try:
        adapt(args.image, args.out, args.objdump)
    except (OSError, ValueError, struct.error, subprocess.CalledProcessError) as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    main()
