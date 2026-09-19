# Storage server testnet test suite

This directory contains a Python/pytest-based test repository to perform tests against the live Oxen
testnet.

Usage:

- Install python3-pytest, python3-nacl, python3-oxenc and python3-requests, if not already
  installed.

- Run `py.test-3` to run the test suite.  By default requests go to the storage servers over HTTPS,
  which is what Session clients use.

- `py.test-3 --transport=quic` sends them over QUIC, which needs the `seshquic` Python bindings
  from libquic's `python/` directory (`pip install --user .` there).

- `py.test-3 --transport=omq` sends them over oxenmq instead.  This needs the
  [oxenmq Python module](https://ci.oxen.rocks/oxen-io/oxen-pyoxenmq), which you can build from
  source or install as the python3-oxenmq deb package from https://deb.oxen.io.  The message
  monitoring tests and the bt-encoded batch test run under oxenmq and QUIC, which can push
  notifications and carry bt bodies, and are skipped over HTTPS.

- `--exclude=<ed25519 pubkey>` keeps the tests away from a particular node.

- `--node=<ed25519 pubkey>` (or `ip:port` of either listener) does the opposite: that node becomes
  the entry point, test accounts are generated inside its swarm, and it is used first whenever a
  swarm member is picked, so that a run can be followed in that node's logs.

`transport.py` is where a new transport would be added.
