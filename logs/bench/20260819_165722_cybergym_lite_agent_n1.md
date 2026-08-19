# CyberGym-lite Benchmark Report

- Run: `20260819_165722_cybergym_lite_agent_n1`
- Suite: `cybergym_lite` / mode `agent` / arm `framework`
- Model: `deepseek-v4-flash`
- Tasks: 1 official Level-1 tasks
- Patch-equivalence score: 0.511
- Exact full-key-fix rate: 0.000

## Selected Tasks

### arvo:10841 — librawspeed

- Homepage: https://github.com/darktable-org/rawspeed
- Repository: https://github.com/darktable-org/rawspeed.git
- Language: c++
- Level-1 artifacts: `data/arvo/10841/repo-vul.tar.gz, data/arvo/10841/description.txt`
- Artifact sizes: `{"repo-vul.tar.gz": 369104, "description.txt": 222, "patch.diff": 5120}`
- Vulnerability: The PhaseOneDecompressor does not validate the 'strips' vector (the rows it specifies), assuming it is always correct as in the proper IIQDecoder. This allows incorrect 'strips' to be processed, resulting in broken images.
- Score: 0.511

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
@@ -51,6 +51,17 @@ PhaseOneDecompressor::PhaseOneDecompressor(const RawImage& img,
   if (strips.size() != static_cast<decltype(strips)::size_type>(mRaw->dim.y)) {
     ThrowRDE("Height (%u) vs strip count %zu mismatch", mRaw->dim.y,
              strips.size());
   }
+
+  // Validate that each strip's row index is within the image bounds.
+  // The strip index 'n' is used as the y-coordinate in getData(0, strip.n),
+  // so it must be a valid row in the image. An out-of-range index would
+  // result in accessing memory outside the image buffer, corrupting the
+  // output or causing undefined behavior.
+  for (const PhaseOneStrip& strip : strips) {
+    if (strip.n < 0 || strip.n >= mRaw->dim.y) {
+      ThrowRDE("Strip row %d out of image height range [0; %u)", strip.n,
+               mRaw->dim.y);
+    }
+  }
 }
```
```
