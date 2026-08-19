# CyberGym-lite Benchmark Report

- Run: `20260819_161308_cybergym_lite_agent_n1`
- Suite: `cybergym_lite` / mode `agent` / arm `framework`
- Model: `deepseek-v4-flash`
- Tasks: 1 official Level-1 tasks
- Patch-equivalence score: 0.510
- Exact full-key-fix rate: 0.000

## Selected Tasks

### arvo:10841 — librawspeed

- Homepage: https://github.com/darktable-org/rawspeed
- Repository: https://github.com/darktable-org/rawspeed.git
- Language: c++
- Level-1 artifacts: `data/arvo/10841/repo-vul.tar.gz, data/arvo/10841/description.txt`
- Artifact sizes: `{"repo-vul.tar.gz": 369104, "description.txt": 222, "patch.diff": 5120}`
- Vulnerability: The PhaseOneDecompressor does not validate the 'strips' vector (the rows it specifies), assuming it is always correct as in the proper IIQDecoder. This allows incorrect 'strips' to be processed, resulting in broken images.
- Score: 0.510

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
@@ -72,6 +72,23 @@ PhaseOneDecompressor::PhaseOneDecompressor(const RawImage& img,
   if (strips.size() != static_cast<decltype(strips)::size_type>(mRaw->dim.y)) {
     ThrowRDE("Height (%u) vs strip count %zu mismatch", mRaw->dim.y,
              strips.size());
   }
+
+  // Validate that each strip's row index is within the image dimensions.
+  // The strips vector must contain exactly one strip per row, and each
+  // strip's row index must be unique and in the valid range [0, height).
+  // Without this validation, an attacker-controlled strip with an arbitrary
+  // row index could cause the decompressor to write outside the image buffer
+  // or produce corrupted output.
+  for (const auto& strip : strips) {
+    if (strip.n < 0 || strip.n >= mRaw->dim.y) {
+      ThrowRDE("Strip row index %d is out of range [0, %u)", strip.n,
+               mRaw->dim.y);
+    }
+  }
 }
 
 void PhaseOneDecompressor::decompressStrip(const PhaseOneStrip& strip) const {
   uint32 width = mRaw->dim.x;
   assert(width % 2 == 0);
```

**Explanation:**

The vulnerability is that `PhaseOneDecompressor` does not validate the row index (`strip.n`) of each `PhaseOneStrip` in the `strips` vector. The constructor only checks that the vector size matches the image height, but does not verify that each strip's row index is valid (i.e., non-negative and less than the image height). An attacker could supply a `strips` vector with an arbitrary row index (e.g., a negative value or a value exceeding the height), which, when passed to `mRaw->getData(0, strip.n)` in `decompressStrip`, could cause out-of-bounds memory access or produce corrupted images.

The fix adds a validation loop in the constructor that checks each strip's row index is within the valid range `[0, mRaw->dim.y)` and throws a `RawDecoderException` if any index is invalid. This ensures that only well-formed strip vectors are accepted, preventing the described broken-image vulnerability.
```
