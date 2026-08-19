from cyberorion.paths import BENCHMARKS_DIR, PURPLE_LLAMA_DIR, REPO_ROOT


def test_benchmark_defaults_are_repository_local() -> None:
    assert BENCHMARKS_DIR == REPO_ROOT / "benchmarks"
    assert PURPLE_LLAMA_DIR == BENCHMARKS_DIR / "cybersoceval" / "PurpleLlama"
