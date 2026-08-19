# CyberGym-lite Benchmark Report

- Run: `20260819_160305_cybergym_lite_agent_n3`
- Suite: `cybergym_lite` / mode `agent` / arm `framework`
- Model: `deepseek-v4-flash`
- Tasks: 3 official Level-1 tasks
- Patch-equivalence score: 0.143
- Exact full-key-fix rate: 0.000

## Selected Tasks

### arvo:11429 — librawspeed

- Homepage: https://github.com/darktable-org/rawspeed
- Repository: https://github.com/darktable-org/rawspeed.git
- Language: c++
- Level-1 artifacts: `data/arvo/11429/repo-vul.tar.gz, data/arvo/11429/description.txt`
- Artifact sizes: `{"repo-vul.tar.gz": 382690, "description.txt": 116, "patch.diff": 1354}`
- Vulnerability: An off-by-one error exists in the output buffer check within the HighPassBand::decode() function of VC5Decompressor.
- Score: 0.088

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
Looking at the `HighPassBand::decode()` function in the VC5Decompressor, I can identify the off-by-one error in the output buffer bounds check. The check uses `>` instead of `>=`, allowing one extra element to be written beyond the buffer boundary.

Here is the minimal fix:

```diff
--- a/src/librawspeed/decompressors/VC5Decompressor.cpp
+++ b/src/librawspeed/decompressors/VC5Decompressor.cpp
@@ -XX,XX +XX,XX @@ void VC5Decompressor::HighPassBand::decode(Wavelet& w) {
   // With this, it should not be possible to write out of bounds
-  if (nOutputs > out.size())
+  if (nOutputs >= out.size())
     ThrowRDE("Too many outputs allocated: %u outputs, and %zu outputs "
              "allocated", nOutputs, out.size());
```

**Explanation:**

The vulnerability is an off-by-one error in `HighPassBand::decode()`. When checking whether the number of outputs (`nOutputs`) fits within the allocated buffer (`out.size()`), the original code uses `>` instead of `>=`. Since array indices are zero-based, a buffer of size `N` can only hold indices `0` through `N-1`. Writing at index `N` would be out of bounds.

The fix changes the comparison from `>` to `>=`, ensuring that when `nOutputs == out.size()`, the check correctly triggers and throws a `RawspeedException`, preventing any write past the end of the buffer. This is a critical boundary check that prevents a heap buffer overflow, which could lead to memory corruption, crashes, or potentially arbitrary code execution when processing maliciously crafted VC-5 encoded image files.
```

### arvo:10841 — librawspeed

- Homepage: https://github.com/darktable-org/rawspeed
- Repository: https://github.com/darktable-org/rawspeed.git
- Language: c++
- Level-1 artifacts: `data/arvo/10841/repo-vul.tar.gz, data/arvo/10841/description.txt`
- Artifact sizes: `{"repo-vul.tar.gz": 369104, "description.txt": 222, "patch.diff": 5120}`
- Vulnerability: The PhaseOneDecompressor does not validate the 'strips' vector (the rows it specifies), assuming it is always correct as in the proper IIQDecoder. This allows incorrect 'strips' to be processed, resulting in broken images.
- Score: 0.332

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
@@ -59,6 +59,16 @@ PhaseOneDecompressor::PhaseOneDecompressor(const RawImage& img,
   if (strips.size() != static_cast<decltype(strips)::size_type>(mRaw->dim.y)) {
     ThrowRDE("Height (%u) vs strip count %zu mismatch", mRaw->dim.y,
              strips.size());
   }
+
+  // Validate that each strip's row number is within the image bounds.
+  for (const auto& strip : strips) {
+    if (strip.n < 0 || strip.n >= mRaw->dim.y) {
+      ThrowRDE("Strip row %d is out of bounds (height: %u)", strip.n,
+               mRaw->dim.y);
+    }
+  }
 }
```
The fix validates that each strip's row index (`n`) falls within the valid image height range. This prevents out-of-bounds access in `decompressStrip` when `getData(0, strip.n)` is called with an invalid row value, which would otherwise corrupt memory or produce broken images.
```

### arvo:11078 — librawspeed

- Homepage: https://github.com/darktable-org/rawspeed
- Repository: https://github.com/darktable-org/rawspeed.git
- Language: c++
- Level-1 artifacts: `data/arvo/11078/repo-vul.tar.gz, data/arvo/11078/description.txt`
- Artifact sizes: `{"repo-vul.tar.gz": 382611, "description.txt": 128, "patch.diff": 12731}`
- Vulnerability: A vulnerability exists in VC5Decompressor where Optional tags are not properly handled, leading to potential assertion failures.
- Score: 0.009

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
Looking at the vulnerability, the issue is in the `VC5Decompressor` where `Optional` tags are not properly handled, leading to potential assertion failures. The problem is in the tag parsing logic where optional tags are being misinterpreted.

The root cause is in the `parseVC5()` function in `VC5Decompressor.cpp`. When parsing tags, if an optional tag is encountered (identified by the `Optional` flag `0x8000`), the code may incorrectly process it, leading to uninitialized state or assertion failures.

Here's the minimal fix:

```diff
--- a/src/librawspeed/decompressors/VC5Decompressor.cpp
+++ b/src/librawspeed/decompressors/VC5Decompressor.cpp
@@ -X,XX +XXX,XX @@
 void VC5Decompressor::parseVC5() {
   // The first tag should be LargeCodeblock
   // (see VC5 spec, 5.4.2.1)
   if (matches(mBs.getShort(), VC5Tag::LargeCodeblock))
     parseLargeCodeblock(mBs);
   else
     ThrowRDE("VC5: did not start with large codeblock.");

   // Now, the MSB bit is the 'Optional' flag.
   while (true) {
     ByteStream tagData = mBs.getSubStream(0);
     VC5Tag tag = mBs.getShort();
-    bool optional = matches(tag, VC5Tag::Optional);
+    bool optional = false;
+    if (matches(tag, VC5Tag::Optional)) {
+      optional = true;
+      tag = static_cast<VC5Tag>(
+          static_cast<std::underlying_type<VC5Tag>::type>(tag) &
+          ~static_cast<std::underlying_type<VC5Tag>::type>(VC5Tag::Optional));
+    }
     switch (tag) {
     case VC5Tag::ChannelCount:
       mVC5.iChannel = mBs.getShort();
       break;
```

The fix ensures that when an `Optional` tag is encountered, the `Optional` flag (0x8000) is stripped from the tag before processing the switch statement. This prevents the switch from matching the wrong tag cases or falling through to default behavior that could cause assertion failures.
```
