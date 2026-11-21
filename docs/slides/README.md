# Presentations

## Customer engineering presentation

[Checkpoint replay on Linux and Android](output/osrec-customer-linux-android-readv-handoff.pptx) diagrams the post-boot Linux capture in QEMU, the application entry snapshot, checkpoint construction, host startup, the runtime handoff at Linux vectors+0x400, syscall dispatch, return and completion through a six-byte pipe read, with original AArch64 disassembly, replay assembly and the linked gateway instructions, then walks through the verified Linux trial and the proposed Android device test. The [authoring source](.build/current-flow/customer-linux-android.mjs) generates the fourteen-slide deck.

## Detailed EL0 checkpoint flow

[Current executor presentation](output/osrec-current-el0-flow-linux-android.pptx) covers AArch64 Linux execution and Android device validation. The clustered IPC checkpoint ran on Linux 6.10.14 with 4 KiB pages, recorded 16 of 16 expected events and 16 UART bytes, and exited with status 0. Android device execution is pending.

The [authoring source](.build/current-flow/update-linux-android.mjs) generates rendered slides and validation reports in `.build/current-flow-linux-android/`.

The appendix retains the [November 17 QEMU profile](output/osrec-current-el0-flow-20261117.pptx), including the editable execution-flow diagrams, gateway-count table and instruction-count chart. That workload used guest page tables, native user and kernel stacks, live user-memory checks, syscall context gateways, generated user returns and UART buffering. Its [authoring source](.build/current-flow/update-20261117.mjs) generates renders in `.build/current-flow-20261117/`.

Checked evidence uses `el0-next-slices-measurement-20261117a` and its instruction profile: 2,381 gateways, all 2,272 events matching and 4,465,783 runtime/adaptation instructions. Trusted production uses `el0-production-profile-20261117c`: 4,116,488 runtime instructions with validation and profiling disabled. Production establishes execution completion, with actual UART compared by the host. These are QEMU instruction counts, not cycles; the 0.20:1 runtime ceiling remains unmet.

The [November 13 deck](output/osrec-current-el0-flow-final.pptx) is retained as the earlier revision.

## Stage presentation

The current authoring source is [.build/explained-stages.mjs](.build/explained-stages.mjs). It exports the fourteen-slide deck to [output/osrec-stages-explained-final.pptx](output/osrec-stages-explained-final.pptx).

The authoring script requires `@oai/artifact-tool` and the presentation utility paths configured in its header. Its generated render and validation files and local dependency link are ignored by Git.

Final decks, the preview and source images are retained. Superseded draft generators were removed; earlier versions remain available in Git history through commit `bf670da`.
