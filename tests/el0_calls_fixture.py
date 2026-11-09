"""Emit native arm64 fixtures comparing generated veneers to the shared C core.

Run this on any host, then compile emitted fixtures.S with el0_calls_host.c and
runtime/el0/emulate.c on arm64 Linux (-mgeneral-regs-only). Each reference saves
every GPR and NZCV before calling the core. The fast path uses the real emitter.
"""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from source_image_calls import FIELDS, analyse_sites, assembly


def save_context():
    lines = ['sub sp, sp, #272']
    lines += [f'stp x{i}, x{i+1}, [sp, #{i*8}]' for i in range(0, 30, 2)]
    return lines + ['str x30, [sp, #240]', 'add x9, sp, #272',
                    'str x9, [sp, #248]', 'str xzr, [sp, #256]',
                    'mrs x9, nzcv', 'str x9, [sp, #264]']


def restore_context():
    return (['ldr x9, [sp, #264]', 'msr nzcv, x9'] +
            [f'ldp x{i}, x{i+1}, [sp, #{i*8}]' for i in range(0, 30, 2)] +
            ['ldr x30, [sp, #240]', 'add sp, sp, #272'])


def emit(directory):
    directory.mkdir(parents=True, exist_ok=True)
    cases = []
    for key in FIELDS:
        for read in (True, False):
            for rt in (0, 16, 30, 31):
                word = (0xd5200000 if read else 0xd5000000) | key << 5 | rt
                # This continuation proves x16 and x17 dead. At the capture
                # boundary all state is observed, as for an unknown exit.
                for kills in ([], [0xd2800010], [0xd2800010, 0xd2800031]):
                    words = {4*(i+1): w for i, w in enumerate(kills + [0])}
                    veneers = analyse_sites([(0, word, 0)], words)
                    if veneers:
                        cases.append((word, kills, veneers[0]))
    lines = ['.text']
    header = []
    for i, (word, kills, v) in enumerate(cases):
        for mode in ('fast', 'reference'):
            name = f'test_{mode}_{i}'
            header.append(f'extern void {name}(const struct osrec_context *, struct osrec_context *);')
            body = [f'.global {name}', f'.type {name}, %function', f'{name}:',
                    'sub sp, sp, #96']
            body += [f'stp x{r}, x{r+1}, [sp, #{(r-19)*8}]' for r in range(19, 31, 2)]
            body += ['adrp x9, test_host_sp', 'mov x10, sp',
                     'str x10, [x9, :lo12:test_host_sp]',
                     'adrp x9, test_after', 'str x1, [x9, :lo12:test_after]',
                     'mov x30, x0', 'ldr x9, [x30, #264]', 'msr nzcv, x9',
                     'ldr x9, [x30, #248]', 'mov sp, x9']
            body += [f'ldp x{r}, x{r+1}, [x30, #{r*8}]' for r in range(0, 30, 2)]
            body += ['ldr x30, [x30, #240]', f'b {name}_site', f'{name}_site:']
            if mode == 'fast':
                body += [f'b test_veneer_{i}']
            else:
                body += [f'b {name}_emulate', f'{name}_emulate:'] + save_context()
                body += ['adrp x0, osrec_shadow', 'add x0, x0, :lo12:osrec_shadow',
                         'mov x1, sp', f'movz w2, #{word & 0xffff}',
                         f'movk w2, #{word >> 16}, lsl #16', 'bl osrec_emulate_site']
                body += restore_context()
                body += [f'b {name}_continuation']
            body += [f'{name}_continuation:']
            body += [f'.inst 0x{w:08x}' for w in kills]
            body += save_context()
            body += ['mov x0, sp', 'adrp x1, test_after',
                     'ldr x1, [x1, :lo12:test_after]', 'mov x2, #34',
                     '1: ldr x3, [x0], #8', 'str x3, [x1], #8',
                     'subs x2, x2, #1', 'b.ne 1b',
                     'adrp x9, test_host_sp', 'ldr x9, [x9, :lo12:test_host_sp]',
                     'mov sp, x9']
            body += [f'ldp x{r}, x{r+1}, [sp, #{(r-19)*8}]' for r in range(19, 31, 2)]
            body += ['add sp, sp, #96', 'ret', f'.size {name}, .-{name}']
            lines += body
        source = assembly([v]).replace('osrec_call_0', f'test_veneer_{i}')
        source = source.replace('osrec_call_return_0', f'test_fast_{i}_continuation')
        lines.append(source)
    lines += ['.bss', '.balign 16', 'test_host_sp: .zero 8', 'test_after: .zero 8',
              '.balign 16', '.global osrec_branch_state', 'osrec_branch_state: .zero 16',
              '.global osrec_shadow', 'osrec_shadow: .zero 532584',
              '.section .note.GNU-stack,"",%progbits']
    header.append('static const struct fixture fixtures[] = {')
    for i, (word, kills, v) in enumerate(cases):
        header.append(f'{{"{word:08x}/{len(kills)}/saves={v.saves:x}", test_fast_{i}, test_reference_{i}}},')
    header.append('};')
    (directory / 'fixtures.S').write_text('\n'.join(lines) + '\n')
    (directory / 'cases.h').write_text('\n'.join(header) + '\n')
    print(f'{len(cases)} native veneer/reference fixtures emitted')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('out', type=Path)
    emit(parser.parse_args().out)
