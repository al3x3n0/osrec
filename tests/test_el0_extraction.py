"""Check actual IR deletion and native behavior on LLVM 16 and 22."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

OPT, PLUGIN = sys.argv[1:3]
sys.argv = sys.argv[:1]
COMPILER = Path(OPT).resolve().parent / "clang"
FIXTURE = Path(__file__).resolve().parents[1] / "examples/el0_callback_slice.c"


class ExtractionTests(unittest.TestCase):
    def run_tool(self, command, success=True):
        result = subprocess.run([str(v) for v in command], text=True, capture_output=True)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        return result

    def test_actual_extraction_and_native_boundary_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            module = stage / "input.bc"
            self.run_tool([COMPILER, "-O0", "-g", "-fno-builtin", "-emit-llvm", "-c", FIXTURE, "-o", module])
            stats = {}
            for mode in ("reference", "extract"):
                output = stage / f"{mode}.bc"
                result = self.run_tool([OPT, "-load-pass-plugin", PLUGIN,
                                       f"-passes=osrec-el0-{mode}<callback_scenario>", module, "-o", output])
                stats[mode] = json.loads(result.stderr)
                self.assertTrue(stats[mode]["ir_verified"])
                self.run_tool([OPT, "-passes=verify", "-disable-output", output])
            self.assertGreater(stats["extract"]["removed"], 0)
            self.assertEqual(stats["reference"]["removed"], 0)
            self.assertLess(stats["extract"]["after"], stats["reference"]["after"])
            main = stage / "main.c"
            main.write_text('''#include <stdint.h>
uint32_t osrec_reference_entry(uint32_t, uint32_t);
uint32_t osrec_extracted_entry(uint32_t, uint32_t);
int main(void) {
    uint32_t values[] = {0, 1, 7, 0x7fffffffU, 0x80000000U, 0xffffffffU};
    uint32_t choices[] = {0, 1, 2, 0xffffffffU};
    for (unsigned i = 0; i < 6; ++i)
        for (unsigned c = 0; c < 4; ++c) {
            uint32_t expected = choices[c] ? values[i] + 7U : values[i] * 3U;
            if (osrec_reference_entry(values[i], choices[c]) != expected ||
                osrec_extracted_entry(values[i], choices[c]) != expected) return 1;
        }
    return 0;
}
''')
            binary = stage / "pair"
            self.run_tool([COMPILER, "-O0", "-fno-lto", stage / "reference.bc", stage / "extract.bc",
                           main, "-o", binary])
            self.run_tool([binary])

    def test_module_initialization_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "constructors.c"
            source.write_text('''unsigned state;
__attribute__((constructor)) static void setup(void) { state = 7; }
unsigned root(unsigned value) { return value + 1; }
''')
            module = Path(directory) / "input.bc"
            self.run_tool([COMPILER, "-O0", "-emit-llvm", "-c", source, "-o", module])
            result = self.run_tool([OPT, "-load-pass-plugin", PLUGIN, "-passes=osrec-el0-extract<root>",
                                   module, "-o", Path(directory) / "out.bc"], success=False)
            self.assertIn("module initialization", result.stderr)


if __name__ == "__main__":
    unittest.main()
