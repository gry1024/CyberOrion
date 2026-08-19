# CyberGym-lite Benchmark Report

- Run: `20260819_161322_cybergym_lite_agent_n1`
- Suite: `cybergym_lite` / mode `agent` / arm `framework`
- Model: `deepseek-v4-flash`
- Tasks: 1 official Level-1 tasks
- Patch-equivalence score: 0.484
- Exact full-key-fix rate: 0.000

## Selected Tasks

### arvo:11429 — librawspeed

- Homepage: https://github.com/darktable-org/rawspeed
- Repository: https://github.com/darktable-org/rawspeed.git
- Language: c++
- Level-1 artifacts: `data/arvo/11429/repo-vul.tar.gz, data/arvo/11429/description.txt`
- Artifact sizes: `{"repo-vul.tar.gz": 382690, "description.txt": 116, "patch.diff": 1354}`
- Vulnerability: An off-by-one error exists in the output buffer check within the HighPassBand::decode() function of VC5Decompressor.
- Score: 0.484

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
@@ -200,7 +200,7 @@ void VC5Decompressor::HighPassBand::decode(const Wavelet& wavelet) const {
   const Array2DRef<const int16_t> low =
       wavelet.bandAsArray2DRef(this->lowPassBand);
 
-  if (offset >= width * height || offset + mCount > width * height)
+  if (offset > width * height || offset + mCount > width * height)
     ThrowRDE("Out of bounds access");
 
   for (unsigned int i = 0; i < mCount; ++i)
```
```
