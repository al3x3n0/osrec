This fixture is the forwarded native 32-call LiteOS-A file session captured by
`tools/liteos_qemu_demo.py --file-operations`, retained originally in
`build/live-file-operations-native-verified`. It is not a synthetic dependency
transcript. The manifest binds all four blobs, source/ABI identity and native
kernel-image hash. The kernel image itself is kept in the build evidence rather
than duplicated here. Regenerate into a fresh directory and validate/export
before replacing the fixture. `test_live_files_replay.py` independently builds
and captures a new native session; it does not use this fixture.
