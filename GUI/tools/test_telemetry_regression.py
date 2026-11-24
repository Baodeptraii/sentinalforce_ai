#!/usr/bin/env python3
"""Isolate audit/report side effects while running pre-existing GUI regression tests."""
import sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from engine import audit_stream,execution_telemetry

def flatten(suite):
    for item in suite:
        if isinstance(item,unittest.TestSuite):yield from flatten(item)
        elif not item.id().startswith('test_execution_telemetry.'):yield item

if __name__=='__main__':
    with tempfile.TemporaryDirectory() as tmp,patch.object(audit_stream,'ROOT',Path(tmp)),patch.object(execution_telemetry,'ROOT',Path(tmp)),patch.object(execution_telemetry,'enqueue',return_value={'status':'mocked'}):
        suite=unittest.TestSuite(flatten(unittest.defaultTestLoader.discover(str(ROOT/'tests'))))
        result=unittest.TextTestRunner(verbosity=1).run(suite)
        raise SystemExit(not result.wasSuccessful())
