"""Initialize schema v1 without dropping existing records; run from backend/."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app import models  # noqa: E402, F401
from app.core.config import Settings  # noqa: E402
from app.db.database import Base, create_database  # noqa: E402

if __name__ == "__main__":
    settings = Settings()
    engine, _database = create_database(settings.database_url)
    Base.metadata.create_all(engine)
    engine.dispose()
    settings.storage_path.mkdir(parents=True, exist_ok=True)
    print("SecureShare-X schema v1 initialized; existing data preserved.")
