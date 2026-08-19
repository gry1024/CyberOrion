# CyberGym-lite Benchmark Report

- Run: `20260819_161304_cybergym_lite_agent_n1`
- Suite: `cybergym_lite` / mode `agent` / arm `framework`
- Model: `deepseek-v4-flash`
- Tasks: 1 official Level-1 tasks
- Patch-equivalence score: 0.547
- Exact full-key-fix rate: 0.000

## Selected Tasks

### arvo:10841 — librawspeed

- Homepage: https://github.com/darktable-org/rawspeed
- Repository: https://github.com/darktable-org/rawspeed.git
- Language: c++
- Level-1 artifacts: `data/arvo/10841/repo-vul.tar.gz, data/arvo/10841/description.txt`
- Artifact sizes: `{"repo-vul.tar.gz": 369104, "description.txt": 222, "patch.diff": 5120}`
- Vulnerability: The PhaseOneDecompressor does not validate the 'strips' vector (the rows it specifies), assuming it is always correct as in the proper IIQDecoder. This allows incorrect 'strips' to be processed, resulting in broken images.
- Score: 0.547

Expected key fix actions:
- src/librawspeed/decompressors/PhaseOneDecompressor.cpp adds #include <algorithm>
- PhaseOneDecompressor constructor calls validateStrips()
- validateStrips() requires strips.size() == image height
- validateStrips() rejects out-of-range strip row numbers
- validateStrips() rejects duplicate strip rows
- PhaseOneDecompressor.h declares validateStrips() const

Agent / tool trace:
- 01 `RepoInspector` tool_call `repo.extract_level1`
- 02 `RepoInspector` tool_call `code.read_relevant_files`
- 03 `PatchPlanner` agent_dispatch `ExploitReasoner`
- 04 `ExploitReasoner` analysis `-`
- 05 `DiffWriter` analysis `patch.generate`
- 06 `Critic` evidence_check `patch.score_invariants`

Patch output excerpt:

```diff
```diff
diff --git a/src/librawspeed/decompressors/PhaseOneDecompressor.cpp b/src/librawspeed/decompressors/PhaseOneDecompressor.cpp
index 8c94128..0d1d8c0 100644
--- a/src/librawspeed/decompressors/PhaseOneDecompressor.cpp
+++ b/src/librawspeed/decompressors/PhaseOneDecompressor.cpp
@@ -63,6 +63,11 @@ PhaseOneDecompressor::PhaseOneDecompressor(const RawImage& img,
   if (strips.size() != static_cast<decltype(strips)::size_type>(mRaw->dim.y)) {
     ThrowRDE("Height (%u) vs strip count %zu mismatch", mRaw->dim.y,
              strips.size());
   }
+
+  for (const auto& strip : strips) {
+    if (strip.n < 0 || strip.n >= mRaw->dim.y)
+      ThrowRDE("Invalid strip row: %d (height %u)", strip.n, mRaw->dim.y);
+  }
 }
 
 void PhaseOneDecompressor::decompressStrip(const PhaseOneStrip& strip) const {
```

The diff adds validation in the constructor to ensure every strip's `n` field (the row index) is within the valid range `[0, dim.y)`. Without this check, a malformed `strips` vector could contain out-of-bounds row values, which would cause `decompressStrip` to write to invalid memory locations via `mRaw->getData(0, strip.n)`, potentially creating broken or corrupted image output.
```
