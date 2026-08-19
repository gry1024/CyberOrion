# CyberGym-lite Benchmark Report

- Run: `20260819_160206_cybergym_lite_agent_n1`
- Suite: `cybergym_lite` / mode `agent` / arm `framework`
- Model: `deepseek-v4-flash`
- Tasks: 1 official Level-1 tasks
- Patch-equivalence score: 0.084
- Exact full-key-fix rate: 0.000

## Selected Tasks

### arvo:11429 — librawspeed

- Homepage: https://github.com/darktable-org/rawspeed
- Repository: https://github.com/darktable-org/rawspeed.git
- Language: c++
- Level-1 artifacts: `data/arvo/11429/repo-vul.tar.gz, data/arvo/11429/description.txt`
- Artifact sizes: `{"repo-vul.tar.gz": 382690, "description.txt": 116, "patch.diff": 1354}`
- Vulnerability: An off-by-one error exists in the output buffer check within the HighPassBand::decode() function of VC5Decompressor.
- Score: 0.084

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
Looking at the vulnerability description, I need to find the off-by-one error in the output buffer check within the `HighPassBand::decode()` function of `VC5Decompressor`. Let me examine the relevant code section.

Based on the code inspection, the issue is in the `HighPassBand::decode()` function where the output buffer boundary check has an off-by-one error. The fix is to correct the boundary condition check to prevent writing one element beyond the allocated buffer.

```diff
--- a/src/librawspeed/decompressors/VC5Decompressor.cpp
+++ b/src/librawspeed/decompressors/VC5Decompressor.cpp
@@ -XXX,XX +XXX,XX @@
 void VC5Decompressor::HighPassBand::decode(const Wavelet& w) const {
   // Ensure the output buffer is large enough
   if (w.width * w.height > static_cast<int>(data.size()))
     ThrowRDE("Output buffer too small");
   
   // ... rest of decode logic
 }
```

The issue is that the check `w.width * w.height > static_cast<int>(data.size())` should be `w.width * w.height >= static_cast<int>(data.size())` to prevent writing to `data[w.width * w.height]` which would be one past the end of the buffer.

The corrected check should ensure that the required number of elements is strictly less than the buffer size, not just less than or equal to it, to avoid the off-by-one write past the end.

```diff
--- a/src/librawspeed/decompressors/VC5Decompressor.cpp
+++ b/src/librawspeed/decompressors/VC5Decompressor.cpp
@@ -XXX,XX +XXX,XX @@
 void VC5Decompressor::HighPassBand::decode(const Wavelet& w) const {
   // Ensure the output buffer is large enough
-  if (w.width * w.height > static_cast<int>(data.size()))
+  if (w.width * w.height >= static_cast<int>(data.size()))
     ThrowRDE("Output buffer too small");
   
   // ... rest of decode logic
 }
```

This corrected check prevents the off-by-one buffer overflow by requiring that the buffer has at least one more element than the number of elements being written, ensuring no write occurs at index `data[w.width * w.height]` which would be out of bounds.
```
