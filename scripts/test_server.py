"""Launch an isolated API for Playwright: no development data is modified."""

import argparse
import sys
import tempfile
from pathlib import Path

import uvicorn

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app.core.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8010)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="secureshare-e2e-") as folder:
        root = Path(folder)
        app = create_app(
            Settings(
                app_env="test",
                database_url=f"sqlite:///{root / 'test.db'}",
                storage_path=root / "storage",
                rate_limit_login=200,
                rate_limit_upload=200,
                rate_limit_verification=300,
                log_level="WARNING",
            )
        )
        uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
