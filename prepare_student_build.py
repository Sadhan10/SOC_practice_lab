from pathlib import Path
import shutil


PROJECT_ROOT = Path(__file__).resolve().parent

OUTPUT_DIR = (
    PROJECT_ROOT.parent
    / "black_falcon_student_build"
)


EXCLUDED_DIRECTORIES = {
    ".git",
    ".github",
    ".idea",
    ".vscode",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "tests",
    "private",
    "venv",
    ".venv",
    "env",
    "ENV",
    "build",
    "dist",
}


EXCLUDED_FILES = {
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    "prepare_student_build.py",
}


EXCLUDED_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".bak",
    ".tmp",
    ".temp",
    ".old",
    ".swp",
    ".swo",
}


def should_exclude(
    path: Path,
) -> bool:

    if any(
        part in EXCLUDED_DIRECTORIES
        for part in path.parts
    ):
        return True

    if path.name in EXCLUDED_FILES:
        return True

    if path.suffix.lower() in EXCLUDED_SUFFIXES:
        return True

    return False


def copy_project():
    if OUTPUT_DIR.exists():
        shutil.rmtree(
            OUTPUT_DIR
        )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    for source in PROJECT_ROOT.rglob("*"):

        relative = source.relative_to(
            PROJECT_ROOT
        )

        if should_exclude(relative):
            continue

        destination = (
            OUTPUT_DIR
            / relative
        )

        if source.is_dir():
            destination.mkdir(
                parents=True,
                exist_ok=True,
            )
            continue

        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        shutil.copy2(
            source,
            destination,
        )


def remove_runtime_state():

    runtime_files = [
        OUTPUT_DIR
        / "database"
        / "black_falcon.db",

        OUTPUT_DIR
        / "instance"
        / "soc_features.db",
    ]

    for file_path in runtime_files:
        if file_path.exists():
            file_path.unlink()

    log_directory = (
        OUTPUT_DIR
        / "logs"
    )

    if log_directory.exists():

        for log_file in log_directory.glob(
            "*.log"
        ):
            log_file.unlink()


def ensure_runtime_directories():

    directories = [
        OUTPUT_DIR / "database",
        OUTPUT_DIR / "instance",
        OUTPUT_DIR / "logs",
    ]

    for directory in directories:

        directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        gitkeep = (
            directory
            / ".gitkeep"
        )

        gitkeep.touch(
            exist_ok=True
        )


def audit_build():

    forbidden = []

    checks = [
        OUTPUT_DIR / ".git",
        OUTPUT_DIR / "tests",
        OUTPUT_DIR / "private",
        OUTPUT_DIR
        / "database"
        / "black_falcon.db",
        OUTPUT_DIR
        / "instance"
        / "soc_features.db",
    ]

    for path in checks:
        if path.exists():
            forbidden.append(
                str(path)
            )

    caches = list(
        OUTPUT_DIR.rglob(
            "__pycache__"
        )
    )

    caches += list(
        OUTPUT_DIR.rglob(
            "*.pyc"
        )
    )

    forbidden.extend(
        str(path)
        for path in caches
    )

    print()
    print("=" * 60)
    print(
        " BLACK FALCON STUDENT BUILD AUDIT"
    )
    print("=" * 60)

    if forbidden:

        print()
        print(
            "[FAILED] Forbidden files found:"
        )

        for path in forbidden:
            print(
                f"  - {path}"
            )

        raise SystemExit(1)

    print()
    print(
        "[PASS] No development-only files found."
    )

    print(
        "[PASS] Runtime databases removed."
    )

    print(
        "[PASS] Instructor solution store excluded."
    )

    print(
        "[PASS] Git metadata excluded."
    )

    print(
        "[PASS] Test suite excluded."
    )

    print()
    print(
        f"Student build created at:"
    )

    print(
        OUTPUT_DIR
    )


def main():

    print(
        "Preparing clean Black Falcon "
        "student deployment build..."
    )

    copy_project()

    remove_runtime_state()

    ensure_runtime_directories()

    audit_build()


if __name__ == "__main__":
    main()