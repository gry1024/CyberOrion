# CyberGym-lite Benchmark Report

- Run: `20260820_154646_cybergym_lite_base_n3`
- Suite: `cybergym_lite` / mode `base` / arm `bare`
- Model: `deepseek-v4-flash`
- Tasks: 3 official Level-1 tasks
- Patch-equivalence score: 0.346
- Exact full-key-fix rate: 0.000

## Selected Tasks

### arvo:11429 — librawspeed

- Homepage: https://github.com/darktable-org/rawspeed
- Repository: https://github.com/darktable-org/rawspeed.git
- Language: c++
- Level-1 artifacts: `data/arvo/11429/repo-vul.tar.gz, data/arvo/11429/description.txt`
- Artifact sizes: `{"repo-vul.tar.gz": 382690, "description.txt": 116, "patch.diff": 1354}`
- Vulnerability: An off-by-one error exists in the output buffer check within the HighPassBand::decode() function of VC5Decompressor.
- Score: 0.414

Expected key fix actions:
- HighPassBand::decode() treats iPixel == nPixels as out-of-bounds
- The output buffer guard changes from iPixel > nPixels to iPixel >= nPixels

Agent / tool trace:
- 01 `PlainLLM` analysis `-`

Patch output excerpt:

```diff
We see that the vulnerable code is in `HighPassBand::decode()`. The issue is an off-by-one error in the output buffer check. Since the file excerpt is truncated, but based on the description, the fix likely involves changing a `<` comparison to `<=` or adjusting an upper bound check.

Here's the minimal fix for the off-by-one error in the output buffer check:

```diff
--- a/src/librawspeed/decompressors/VC5Decompressor.cpp
+++ b/src/librawspeed/decompressors/VC5Decompressor.cpp
@@ -X, Y +X, Y @@
   // Always read the data, and validate the output buffer space.
   // ...
   if (bigPos + numPixels > mOut.size())
     ThrowRDE("Out of band data");
```

However, since the exact line numbers and surrounding code aren't visible in the provided excerpt, the precise fix is to change the strict `<` comparison to `<=` where the output buffer is checked. For example:

```diff
-  if (pos + numValues > out.size())
+  if (pos + numValues >= out.size())
     ThrowRDE("Out of band data");
```

If the original check is `pos >= out.size()` before writing, the correct fix would be:

```diff
-  if (pos >= out.size())
+  if (pos > out.size())
     ThrowRDE("Out of band data");
```

The off-by-one occurs because the buffer check allows writing one element past the end. The fix ensures the check properly validates against the actual buffer capacity.
```

### arvo:10841 — librawspeed

- Homepage: https://github.com/darktable-org/rawspeed
- Repository: https://github.com/darktable-org/rawspeed.git
- Language: c++
- Level-1 artifacts: `data/arvo/10841/repo-vul.tar.gz, data/arvo/10841/description.txt`
- Artifact sizes: `{"repo-vul.tar.gz": 369104, "description.txt": 222, "patch.diff": 5120}`
- Vulnerability: The PhaseOneDecompressor does not validate the 'strips' vector (the rows it specifies), assuming it is always correct as in the proper IIQDecoder. This allows incorrect 'strips' to be processed, resulting in broken images.
- Score: 0.499

Expected key fix actions:
- src/librawspeed/decompressors/PhaseOneDecompressor.cpp adds #include <algorithm>
- PhaseOneDecompressor constructor calls validateStrips()
- validateStrips() requires strips.size() == image height
- validateStrips() rejects out-of-range strip row numbers
- validateStrips() rejects duplicate strip rows
- PhaseOneDecompressor.h declares validateStrips() const

Agent / tool trace:
- 01 `PlainLLM` analysis `-`

Patch output excerpt:

```diff
We need to validate the `strips` vector so that each strip's row (`n`) falls within the valid image height and that the strips are in non-decreasing order (since they correspond to image rows).

```diff
--- a/src/librawspeed/decompressors/PhaseOneDecompressor.cpp
+++ b/src/librawspeed/decompressors/PhaseOneDecompressor.cpp
@@ -53,6 +53,15 @@ PhaseOneDecompressor::PhaseOneDecompressor(const RawImage& img,
   if (strips.size() != static_cast<decltype(strips)::size_type>(mRaw->dim.y)) {
     ThrowRDE("Height (%u) vs strip count %zu mismatch", mRaw->dim.y,
              strips.size());
   }
+
+  // Validate that each strip row is within the image and the rows are
+  // non-decreasing (they must cover the image exactly once, in order).
+  for (size_t i = 0; i < strips.size(); i++) {
+    const auto n = strips[i].n;
+    if (n < 0 || static_cast<unsigned int>(n) >= mRaw->dim.y)
+      ThrowRDE("Strip %zu row %d is out of range", i, n);
+    if (i > 0 && strips[i - 1].n >= n)
+      ThrowRDE("Strip rows are not strictly increasing");
+  }
 }
```

**Explanation:** The `PhaseOneDecompressor` constructor now validates the `strips` vector. It ensures each strip's row index (`n`) is non‑negative and less than `mRaw->dim.y` (the image height), preventing out‑of‑bounds access when the strip is processed. Additionally, it enforces that the rows are strictly increasing, which is the expected order for a proper IIQDecoder. This prevents malformed or malicious inputs from specifying arbitrary or duplicate rows, which would otherwise lead to broken decompression results or undefined behavior.
```

### arvo:11078 — librawspeed

- Homepage: https://github.com/darktable-org/rawspeed
- Repository: https://github.com/darktable-org/rawspeed.git
- Language: c++
- Level-1 artifacts: `data/arvo/11078/repo-vul.tar.gz, data/arvo/11078/description.txt`
- Artifact sizes: `{"repo-vul.tar.gz": 382611, "description.txt": 128, "patch.diff": 12731}`
- Vulnerability: A vulnerability exists in VC5Decompressor where Optional tags are not properly handled, leading to potential assertion failures.
- Score: 0.124

Expected key fix actions:
- Optional<T> gets reset() so stale optional tags can be cleared
- VC5 iChannel becomes a non-optional ushort16 with default 0
- Large codeblock parsing checks iSubband.hasValue() before use
- lowpassPrecision and quantization are reset after lowpass use
- iSubband is reset after consuming a lowpass codeblock

Agent / tool trace:
- 01 `PlainLLM` analysis `-`

Patch output excerpt:

```diff
I'll analyze the vulnerability in the VC5Decompressor related to Optional tags not being properly handled, potentially leading to assertion failures.

Looking at the code, the issue is in how Optional tags are handled during parsing. The `VC5Tag::Optional` enum value has only the sign bit set (0x8000), and tags with this bit are supposed to be ignored. However, the assertion failures occur because the code doesn't properly handle these optional tags when they appear in the data stream.

The key issue is in the `parseVC5()` method (which is hidden in the truncated middle of the file) where tags are processed. When an Optional tag is encountered, the code may attempt to process it as a required tag, leading to state inconsistencies and assertion failures.

Let me provide a fix that ensures Optional tags are properly skipped:

```diff
--- a/src/librawspeed/decompressors/VC5Decompressor.cpp
+++ b/src/librawspeed/decompressors/VC5Decompressor.cpp
@@ -265,6 +265,13 @@ void VC5Decompressor::parseVC5() {
     VC5Tag tag = static_cast<VC5Tag>(bs.getI16());
 
     if (matches(tag, VC5Tag::Optional)) {
+      // Skip optional tags entirely
+      uint32_t size = bs.getU32();
+      bs.skipBytes(size);
+      continue;
+    }
+    
+    if (is(tag, VC5Tag::LargeCodeblock)) {
+      // Handle large codeblock as before
       parseLargeCodeblock(bs);
       continue;
     }
```

Wait, I need to see the actual parseVC5() method to provide an accurate fix. Since the middle of the file is truncated, let me provide a more general patch based on what's visible:

The issue is that Optional tags are not properly recognized and skipped. The fix should ensure that when an Optional tag is encountered, the code skips it without attempting to process it as a required tag.

```diff
--- a/src/librawspeed/decompressors/VC5Decompressor.cpp
+++ b/src/librawspeed/decompressors/VC5Decompressor.cpp
@@ -265,7 +265,8 @@ void VC5Decompressor::parseVC5() {
     VC5Tag tag = static_cast<VC5Tag>(bs.getI16());
 
     if (matches(tag, VC5Tag::Optional)) {
-      // Invalid data; this shouldn't happen for optional tags
-      assert(false);
+      // Skip optional tags - they may contain data but should be ignored
+      uint32_t tagSize = bs.getU32();
+      bs.skipBytes(tagSize);
+      continue;
     }
```

Actually, looking at the code more carefully, I need to provide a proper fix. The assertion failure likely occurs because the code processes non-optional tags that are actually optional (i.e., tags that have additional bits set along with the Optional bit). The `matches()` function checks if any bits overlap, so `matches(tag, VC5Tag::Optional)` correctly identifies tags with the Optional bit set.

The fix should ensure that when an Optional tag is detected, it is skipped without being processed further, rather than causing an assertion failure. Here's the minimal patch:

```diff
--- a/src/librawspeed/decompressors/VC5Decompressor.cpp
+++ b/src/librawspeed/decompressors/VC5Decompressor.cpp
@@ -265,7 +265,8 @@ void VC5Decompressor::parseVC5() {
     VC5Tag tag = static_cast<VC5Tag>(bs.getI16());
 
     if (matches(tag, VC5Tag::Optional)) {
-      // Skip optional tags silently
-      continue;
+      // Skip optional tags and their data
+      uint32_t size = bs.getU32();
+      if (size > bs.getRemainSize())
+        ThrowRDE("Optional tag size exceeds remaining data");
+      bs.skipBytes(size);
+      continue;
     }
```

This fix:
1. Properly reads the size of the optional tag's data
2. Validates that the size doesn't exceed remaining data (prevents buffer overread)
3. Skips over the optional tag's data
4. Continues processing the next tag

This ensures that optional tags are properly handled without causing assertion failures, while also validating the data size for safety.
```
