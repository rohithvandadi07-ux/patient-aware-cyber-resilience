"""Process entrypoint.

Run locally with: uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
(from the backend/ directory, with PYTHONPATH including backend/).
"""

from app.core.app_factory import create_app

app = create_app()
