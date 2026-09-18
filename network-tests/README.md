# Storage server testnet test suite

This directory contains a Python/pytest-based test repository to perform tests against the live Oxen
testnet.

Usage:

- Install python3-pytest, python3-nacl, python3-oxenc and python3-requests, if not already
  installed.

- Run `py.test-3` to run the test suite.  By default requests go to the storage servers over HTTPS,
  which is what Session clients use.

- `py.test-3 --transport=omq` sends them over oxenmq instead.  This needs the
  [oxenmq Python module](https://ci.oxen.rocks/oxen-io/oxen-pyoxenmq), which you can build from
  source or install as the python3-oxenmq deb package from https://deb.oxen.io.  A few tests
  exercise oxenmq-only features (message monitoring, bt-encoded requests) and are skipped under
  any other transport.

- `--exclude=<ed25519 pubkey>` keeps the tests away from a particular node.

`transport.py` is where a new transport (e.g. QUIC) would be added.
