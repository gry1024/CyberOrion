# CyberGym-lite Benchmark Report

- Run: `20260819_161311_cybergym_lite_agent_n1`
- Suite: `cybergym_lite` / mode `agent` / arm `framework`
- Model: `deepseek-v4-flash`
- Tasks: 1 official Level-1 tasks
- Patch-equivalence score: 0.519
- Exact full-key-fix rate: 0.000

## Selected Tasks

### arvo:10841 — librawspeed

- Homepage: https://github.com/darktable-org/rawspeed
- Repository: https://github.com/darktable-org/rawspeed.git
- Language: c++
- Level-1 artifacts: `data/arvo/10841/repo-vul.tar.gz, data/arvo/10841/description.txt`
- Artifact sizes: `{"repo-vul.tar.gz": 369104, "description.txt": 222, "patch.diff": 5120}`
- Vulnerability: The PhaseOneDecompressor does not validate the 'strips' vector (the rows it specifies), assuming it is always correct as in the proper IIQDecoder. This allows incorrect 'strips' to be processed, resulting in broken images.
- Score: 0.519

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
--- a/src/librawspeed/decompressors/PhaseOneDecompressor.cpp
+++ b/src/librawspeed/decompressors/PhaseOneDecompressor.cpp
@@ -69,6 +69,18 @@ PhaseOneDecompressor::PhaseOneDecompressor(const RawImage& img,
   if (strips.size() != static_cast<decltype(strips)::size_type>(mRaw->dim.y)) {
     ThrowRDE("Height (%u) vs strip count %zu mismatch", mRaw->dim.y,
              strips.size());
   }
+
+  for (const auto& strip : strips) {
+    if (strip.n < 0 || strip.n >= mRaw->dim.y) {
+      ThrowRDE("Strip row %d is out of range [0; %u)", strip.n, mRaw->dim.y);
+    }
+  }
 }
 
 void PhaseOneDecompressor::decompressStrip(const PhaseOneStrip& strip) const {
```

The fix validates that each strip's row index `n` is within the valid range `[0, dim.y)`. Without this check, a malicious or corrupted file could provide strip entries with out-of-bounds row indices, causing `getData(0, strip.n)` to access memory outside the allocated image buffer, leading to broken images or potential memory corruption. The check ensures that every strip refers to a valid row in the image before any decompression work begins.
```
