# CyberGym-lite Benchmark Report

- Run: `20260820_154414_cybergym_lite_agent_n3`
- Suite: `cybergym_lite` / mode `agent` / arm `framework`
- Model: `deepseek-v4-flash`
- Tasks: 3 official Level-1 tasks
- Patch-equivalence score: 0.359
- Exact full-key-fix rate: 0.000

## Selected Tasks

### arvo:11429 — librawspeed

- Homepage: https://github.com/darktable-org/rawspeed
- Repository: https://github.com/darktable-org/rawspeed.git
- Language: c++
- Level-1 artifacts: `data/arvo/11429/repo-vul.tar.gz, data/arvo/11429/description.txt`
- Artifact sizes: `{"repo-vul.tar.gz": 382690, "description.txt": 116, "patch.diff": 1354}`
- Vulnerability: An off-by-one error exists in the output buffer check within the HighPassBand::decode() function of VC5Decompressor.
- Score: 0.447

Expected key fix actions:
- HighPassBand::decode() treats iPixel == nPixels as out-of-bounds
- The output buffer guard changes from iPixel > nPixels to iPixel >= nPixels

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
--- a/src/librawspeed/decompressors/VC5Decompressor.cpp
+++ b/src/librawspeed/decompressors/VC5Decompressor.cpp
@@ -481,15 +481,15 @@ void VC5Decompressor::HighPassBand::decode(
   RLV rl;
   bool isLineDone;
 
-  // bounds check. the multiplication is for performance (not executed
-  // when not in debug mode) and is safe because the dimensions are
-  // limited.
-  if (inputBuffer.size() < 3 * static_cast<unsigned int>(numCoeffsPerPlane)) {
+  // bounds check. the multiplication is for performance (not executed
+  // when not in debug mode) and is safe because the dimensions are
+  // limited.
+  if (inputBuffer.size() < 3 * static_cast<unsigned int>(numCoeffsPerPlane) + 1) {
     ThrowRDE("VC5: band data too short");
   }
```
```

### arvo:10841 — librawspeed

- Homepage: https://github.com/darktable-org/rawspeed
- Repository: https://github.com/darktable-org/rawspeed.git
- Language: c++
- Level-1 artifacts: `data/arvo/10841/repo-vul.tar.gz, data/arvo/10841/description.txt`
- Artifact sizes: `{"repo-vul.tar.gz": 369104, "description.txt": 222, "patch.diff": 5120}`
- Vulnerability: The PhaseOneDecompressor does not validate the 'strips' vector (the rows it specifies), assuming it is always correct as in the proper IIQDecoder. This allows incorrect 'strips' to be processed, resulting in broken images.
- Score: 0.504

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
@@ -59,6 +59,17 @@ PhaseOneDecompressor::PhaseOneDecompressor(const RawImage& img,
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
```

The fix adds validation in the constructor to ensure each strip's row index `n` is within the valid image height range `[0, dim.y)`. This prevents out-of-bounds memory access in `decompressStrip` via `mRaw->getData(0, strip.n)` when a malicious or corrupt IIQ file specifies invalid strip rows, which would otherwise cause undefined behavior or memory corruption. The check is performed once at construction time, before any parallel decompression begins, maintaining the existing error-handling pattern used for other size validations.
```

### arvo:11078 — librawspeed

- Homepage: https://github.com/darktable-org/rawspeed
- Repository: https://github.com/darktable-org/rawspeed.git
- Language: c++
- Level-1 artifacts: `data/arvo/11078/repo-vul.tar.gz, data/arvo/11078/description.txt`
- Artifact sizes: `{"repo-vul.tar.gz": 382611, "description.txt": 128, "patch.diff": 12731}`
- Vulnerability: A vulnerability exists in VC5Decompressor where Optional tags are not properly handled, leading to potential assertion failures.
- Score: 0.127

Expected key fix actions:
- Optional<T> gets reset() so stale optional tags can be cleared
- VC5 iChannel becomes a non-optional ushort16 with default 0
- Large codeblock parsing checks iSubband.hasValue() before use
- lowpassPrecision and quantization are reset after lowpass use
- iSubband is reset after consuming a lowpass codeblock

Agent / tool trace:
- 01 `RepoInspector` tool_call `repo.extract_level1`
- 02 `RepoInspector` tool_call `code.read_relevant_files`
- 03 `PatchPlanner` agent_dispatch `ExploitReasoner`
- 04 `ExploitReasoner` analysis `-`
- 05 `DiffWriter` analysis `patch.generate`
- 06 `Critic` evidence_check `patch.score_invariants`

Patch output excerpt:

```diff
Looking at the vulnerability, the issue is in the VC5Decompressor where Optional tags are not being properly filtered out during tag parsing. The `Optional` tag flag (`0x8000`) should cause certain tags to be ignored when encountered in the bitstream, but the current implementation doesn't properly handle this case, leading to potential assertion failures when malformed data is encountered.

The problem is in the `parseVC5()` function where tags are read and processed. When a tag has the Optional bit set, it should be skipped/ignored rather than processed, but the current implementation doesn't filter these out properly.

Here's the minimal fix for `src/librawspeed/decompressors/VC5Decompressor.cpp`:

```diff
--- a/src/librawspeed/decompressors/VC5Decompressor.cpp
+++ b/src/librawspeed/decompressors/VC5Decompressor.cpp
@@ -430,7 +430,13 @@ void VC5Decompressor::parseVC5() {
     if (mBs.getBuffer().size() < tagsSize)
       ThrowRDE("Insufficient data for tags");
 
     for (uint32 tagIndex = 0; tagIndex < tagsCount; tagIndex++) {
       VC5Tag tag = static_cast<VC5Tag>(mBs.getU16());
+      if (matches(tag, VC5Tag::Optional)) {
+        // Skip optional tags that we don't understand
+        uint32_t tagSize = mBs.getU32();
+        if (tagSize > mBs.getRemainingSize())
+          ThrowRDE("Invalid tag size");
+        mBs.skipBytes(tagSize);
+        continue;
+      }
       uint32_t tagSize = mBs.getU32();
       if (tagSize > mBs.getRemainingSize())
         ThrowRDE("Invalid tag size");
```

This fix properly identifies Optional tags by checking if the Optional bit flag is set (`matches(tag, VC5Tag::Optional)`), and when found, skips the tag data entirely rather than attempting to process it. This prevents any unsafe handling of optional tag content that could lead to assertion failures from unexpected data patterns.
```
