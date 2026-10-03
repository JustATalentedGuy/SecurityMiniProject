import os
import subprocess
import sys
from pathlib import Path

from app.db.database import create_database
from app.models import User
from sqlalchemy import inspect, select

ROOT = Path(__file__).resolve().parents[2]


def test_schema_init_and_restricted_offline_demo_reset(tmp_path):
    database_path = tmp_path / "scripts.db"
    storage = tmp_path / "objects"
    environment = {
        **os.environ,
        "APP_ENV": "test",
        "DATABASE_URL": f"sqlite:///{database_path}",
        "STORAGE_PATH": str(storage),
        "ENABLE_ATTACK_DEMOS": "true",
    }
    initialized = subprocess.run(
        [sys.executable, str(ROOT / "scripts/init_db.py")],
        cwd=ROOT / "backend",
        env=environment,
        capture_output=True,
        text=True,
    )
    assert initialized.returncode == 0, initialized.stderr
    engine, database = create_database(environment["DATABASE_URL"])
    assert "users" in inspect(engine).get_table_names()
    with database() as db:
        db.add(
            User(
                username="sample",
                password_hash="test-only-hash",
                public_key_pem="test-only-public-placeholder",
            )
        )
        db.commit()
    subprocess.run(
        [sys.executable, str(ROOT / "scripts/init_db.py")],
        cwd=ROOT / "backend",
        env=environment,
        check=True,
        capture_output=True,
    )
    with database() as db:
        assert db.scalar(select(User).where(User.username == "sample"))
    encrypted = storage / ("a" * 32 + ".enc")
    encrypted.write_bytes(b"encrypted-only-object")
    sentinel = storage / "keep.txt"
    sentinel.write_text("Not an encrypted demo object")
    engine.dispose()
    blocked = subprocess.run(
        [sys.executable, str(ROOT / "scripts/reset_demo.py"), "--confirm", "DELETE_DEMO_DATA"],
        cwd=ROOT / "backend",
        env={**environment, "ENABLE_ATTACK_DEMOS": "false"},
        capture_output=True,
    )
    assert blocked.returncode != 0 and encrypted.exists()
    reset = subprocess.run(
        [sys.executable, str(ROOT / "scripts/reset_demo.py"), "--confirm", "DELETE_DEMO_DATA"],
        cwd=ROOT / "backend",
        env=environment,
        capture_output=True,
    )
    assert reset.returncode == 0, reset.stderr
    assert not encrypted.exists() and sentinel.exists()
    engine, database = create_database(environment["DATABASE_URL"])
    with database() as db:
        assert not db.scalar(select(User))
    engine.dispose()
