import logging

from app.repositories.log_capture import install, uninstall


def test_install_captures_log_records_with_extras():
    handler = install()
    try:
        logger = logging.getLogger("app.test.log_capture")
        logger.setLevel(logging.INFO)
        logger.info("device connected", extra={"device_id": "ventilator-01", "incident_id": "incident-1"})

        results = handler.query(device_id="ventilator-01")
        assert len(results) == 1
        assert results[0].message == "device connected"
        assert results[0].device_id == "ventilator-01"
        assert results[0].incident_id == "incident-1"
    finally:
        uninstall(handler)


def test_query_filters_by_device_id():
    handler = install()
    try:
        logger = logging.getLogger("app.test.log_capture")
        logger.setLevel(logging.INFO)
        logger.info("a", extra={"device_id": "ventilator-01"})
        logger.info("b", extra={"device_id": "infusion-pump-01"})

        results = handler.query(device_id="ventilator-01")
        assert len(results) == 1
        assert results[0].message == "a"
    finally:
        uninstall(handler)


def test_records_without_device_id_extra_have_none():
    handler = install()
    try:
        logger = logging.getLogger("app.test.log_capture")
        logger.setLevel(logging.INFO)
        logger.info("no device context")

        results = handler.query()
        assert any(r.device_id is None for r in results)
    finally:
        uninstall(handler)


def test_uninstall_stops_further_capture():
    handler = install()
    logger = logging.getLogger("app.test.log_capture")
    logger.setLevel(logging.INFO)
    logger.info("before uninstall", extra={"device_id": "x"})
    uninstall(handler)
    logger.info("after uninstall", extra={"device_id": "x"})

    results = handler.query(device_id="x")
    assert len(results) == 1
    assert results[0].message == "before uninstall"


def test_capacity_bounds_the_buffer():
    handler = install(capacity=3)
    try:
        logger = logging.getLogger("app.test.log_capture")
        logger.setLevel(logging.INFO)
        for i in range(5):
            logger.info(f"line {i}", extra={"device_id": "x"})

        results = handler.query(device_id="x")
        assert len(results) == 3
        # Oldest records are dropped first (deque maxlen semantics).
        assert [r.message for r in results] == ["line 2", "line 3", "line 4"]
    finally:
        uninstall(handler)
