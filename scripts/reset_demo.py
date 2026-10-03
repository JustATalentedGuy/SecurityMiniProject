"""Offline reset for a disposable local SQLite demonstration database."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app import models  # noqa: E402, F401
from app.core.config import Settings  # noqa: E402
from app.db.database import Base, create_database  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", required=True, choices=["DELETE_DEMO_DATA"])
    parser.parse_args()
    settings = Settings()
    if (
        not settings.enable_attack_demos
        or settings.app_env not in {"development", "test"}
        or not settings.database_url.startswith("sqlite")
    ):
        raise SystemExit(
            "Reset is restricted to demo-enabled development/test SQLite environments."
        )
    engine, _database = create_database(settings.database_url)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    root = settings.storage_path.resolve()
    # Only recognized encrypted objects and orphan temp files inside the configured root.
    for path in root.glob("*"):
        if path.is_file() and path.parent.resolve() == root and path.suffix in {".enc", ".tmp"}:
            path.unlink()
    engine.dispose()
    print(
        "Disposable database and encrypted objects reset. Existing client vaults may be reused when re-registering demo users."
    )


if __name__ == "__main__":
    main()
