"""Phase 11 E2E fixtures: a real backend (FastAPI/uvicorn) and a real
frontend (Vite dev server) running as actual processes, so Playwright can
drive a real browser against them -- not `TestClient`, not jsdom.

Both servers bind to dynamically-chosen free ports (never a fixed port the
sandbox or a prior run might still hold), and the backend's CORS allowlist
is built from the frontend's *actual* chosen port rather than relying on the
default `http://localhost:5173` -- see `Settings.cors_allowed_origins`
(`app/core/config.py`) and `app/core/README.md`'s Phase 10 note on why this
exists at all (the browser enforces it regardless of what the backend
"trusts").
"""

from __future__ import annotations

import os
import socket
import subprocess
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

from app.api.detections import get_detection_service
from app.core.app_factory import create_app
from app.core.config import Settings
from app.cybersecurity.detection_service import DetectionService, load_model
from app.cybersecurity.synthetic_data import generate_synthetic_dataset
from app.cybersecurity.training import save_artifacts, train_baselines

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FRONTEND_DIR = _REPO_ROOT / "frontend"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_until_up(url: str, *, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            httpx.get(url, timeout=2.0)
            return
        except httpx.HTTPError as exc:  # connection refused while the server boots
            last_error = exc
            time.sleep(0.2)
    raise RuntimeError(f"{url} did not become reachable within {timeout}s") from last_error


@pytest.fixture(scope="session")
def trained_detection_service(tmp_path_factory):
    """Same real-but-quick training pattern as
    `backend/tests/test_lifecycle_integration.py` -- a real trained model,
    honestly labeled as trained on the synthetic stand-in dataset
    (`datasets/LICENSE_NOTES.md`), not a pre-trained artifact this suite
    would otherwise depend on existing on disk."""
    output_dir = tmp_path_factory.mktemp("e2e_models")
    df = generate_synthetic_dataset(seed=11)
    results = train_baselines(df, seed=11)
    save_artifacts(results, output_dir, data_source="synthetic (Phase 11 E2E fixture)", seed=11)
    model = load_model(output_dir / "random_forest.joblib")
    return DetectionService(model, confidence_threshold=0.0)


class _LiveBackend:
    def __init__(self, app, host: str, port: int):
        self.app = app
        self.base_url = f"http://{host}:{port}"
        config = uvicorn.Config(app, host=host, port=port, log_level="warning")
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def start(self, *, timeout: float = 15.0) -> None:
        self._thread.start()
        deadline = time.monotonic() + timeout
        while not self._server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("backend uvicorn server did not report started in time")
            time.sleep(0.05)
        _wait_until_up(f"{self.base_url}/health", timeout=timeout)

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10.0)


@pytest.fixture(scope="session")
def live_backend(trained_detection_service):
    """A real `create_app()` instance served by a real `uvicorn.Server`, in
    a background thread of this test process (so test code keeps a direct
    handle on `app.state` for seeding agent traces -- see `_seed_scenario.py`
    -- while Playwright's browser reaches it only over real HTTP, exactly
    like a genuine deployment's frontend would)."""
    frontend_port = _free_port()
    backend_port = _free_port()
    settings = Settings(
        cors_allowed_origins=[
            f"http://127.0.0.1:{frontend_port}",
            f"http://localhost:{frontend_port}",
        ]
    )
    app = create_app(settings)
    app.dependency_overrides[get_detection_service] = lambda: trained_detection_service

    backend = _LiveBackend(app, host="127.0.0.1", port=backend_port)
    backend.start()
    try:
        yield backend, frontend_port
    finally:
        backend.stop()


class _LiveFrontend:
    def __init__(self, process: subprocess.Popen, base_url: str):
        self.process = process
        self.base_url = base_url


@pytest.fixture(scope="session")
def live_frontend(live_backend):
    """The real Vite dev server (not a mock, not a static export) as a real
    subprocess, pointed at the real backend's actual base URL via
    `VITE_API_BASE_URL` (`frontend/src/api/client.ts`)."""
    backend, frontend_port = live_backend
    env = os.environ.copy()
    env["VITE_API_BASE_URL"] = backend.base_url

    process = subprocess.Popen(
        ["npm", "run", "dev", "--", "--host", "127.0.0.1", "--port", str(frontend_port), "--strictPort"],
        cwd=_FRONTEND_DIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    base_url = f"http://127.0.0.1:{frontend_port}"
    try:
        _wait_until_up(base_url, timeout=30.0)
    except RuntimeError:
        process.terminate()
        output = process.stdout.read() if process.stdout else ""
        raise RuntimeError(f"frontend dev server did not start:\n{output}") from None

    try:
        yield _LiveFrontend(process, base_url)
    finally:
        process.terminate()
        try:
            process.wait(timeout=10.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5.0)


@pytest.fixture
def backend_app(live_backend):
    """Just the `FastAPI` app object, for seeding code that needs
    `app.state` (see `_seed_scenario.py::build_toolkit`)."""
    backend, _ = live_backend
    return backend.app


@pytest.fixture
def backend_url(live_backend):
    backend, _ = live_backend
    return backend.base_url


@pytest.fixture
def frontend_url(live_frontend):
    return live_frontend.base_url
