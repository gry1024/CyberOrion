# Benchmark 数据目录

这个目录是仓库内默认 benchmark 根目录，对应 `cyberorion.paths.BENCHMARKS_DIR`。

已随 GitHub 上传的内容：

- `cybersoceval/PurpleLlama/CybersecurityBenchmarks/datasets/crwd_meta/malware_analysis/questions.json`
- `cybersoceval/PurpleLlama/CybersecurityBenchmarks/datasets/crwd_meta/threat_intel_reasoning/report_questions.json`

不直接上传的内容：

- 第三方完整仓库 clone、`.git/`、venv、`.venv/`。
- 体积很大的原始数据或可重新下载的数据。

如果本地需要完整第三方数据镜像，把它放在任意目录后设置：

```bash
export CAI_BENCHMARKS=/path/to/full/benchmarks
```

没有设置 `CAI_BENCHMARKS` 时，benchmark 代码默认读取本目录中的随仓库题库。
