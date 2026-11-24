#!/usr/bin/env python3
"""Private SSH credential helper: its stdout is consumed only by ssh."""
import json
import os
from pathlib import Path

print(json.loads(Path(os.environ['SURVEY_SSH_CREDENTIAL_FILE']).read_text())['password'])
