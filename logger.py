#!/usr/bin/env python3
"""Shared stdout logging for umadump."""
from __future__ import annotations

import logging
import sys

logger = logging.getLogger("umadump")


def configure_logging(verbose: bool) -> None:
    logger.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False
