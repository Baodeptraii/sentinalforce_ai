# Legacy replay fixture

This is sanitized offline test data, not a new survey.

The two probe JSON files contain eight HTTP response records (six unique
observations). Replay also needs the three historical HTTPS failures described
in `../web_web_evidence.json`: the saved requests reference `execution.log` at
lines 15, 20 and 21. Together these yield the existing assertions of 11 requests
and nine observations.

`execution.log` is a reconstructed **test excerpt**, not a byte-for-byte copy of
the original execution log. Its three URLs, exception class and line positions
come from that existing evidence fixture. Unavailable lines are blank; no event
time, TLS cause, successful request or session data has been invented. The
normalizer must retain `legacy_unknown` for the errors.

The explicit exception in `GUI/.gitignore` keeps this test dependency trackable
even though ordinary runtime `*.log` files remain ignored. Do not remove the
excerpt or relax the replay counts. The test also verifies the error URLs/line
numbers against the saved evidence and confirms that replay preserves source
bytes and copies the referenced log to its separate review directory.
