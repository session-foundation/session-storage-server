"""
How the tests talk to storage servers (and to oxend, for the node list).

Tests get a transport from the `rpc` fixture, selected with `--transport`, and use it as:

    conn = rpc.connect(snode)                   # snode: a dict with the ip/port_*/pubkey_* keys
                                                # that get_swarm returns in its `snodes` list
    fut = rpc.request(conn, 'store', payload)   # payload: bytes (json, or bt where supported)
    parts = fut.get()                           # [body] on success, [b'<code>', body] on error

Every transport delivers replies in that same shape, the shape of oxenmq's `storage.*` replies,
so that the tests do not care which transport carried them.  `payload` may also be given as a
list of message parts, which is how the tests historically passed it to oxenmq; a storage RPC
takes at most one.
"""

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

DEFAULT_TIMEOUT = timedelta(seconds=15)

# The testnet oxend the node list comes from.
OXEND_OMQ = "curve://public.session.foundation:38161/9c5201e30957cd44e3dcc8ad7f94f48e6914deef77390f77a439a2d7e7f4cb5c"
OXEND_HTTP = "http://public.session.foundation:38157/json_rpc"


def _payload_bytes(payload):
    if isinstance(payload, (list, tuple)):
        assert len(payload) <= 1, "storage RPC requests take at most one message part"
        payload = payload[0] if payload else b''
    if isinstance(payload, str):
        payload = payload.encode()
    return payload


def normalize_oxend_snode(sn):
    """Reshapes a get_service_nodes record into the dict shape get_swarm uses for `snodes`."""
    return {
        'ip': sn['public_ip'],
        'port_https': sn['storage_port'],
        'port_omq': sn['storage_lmq_port'],
        'port_quic': sn['storage_lmq_port'],
        'pubkey_ed25519': sn['pubkey_ed25519'],
        'pubkey_x25519': sn['pubkey_x25519'],
        'pubkey_legacy': sn['service_node_pubkey'],
    }


class OMQ:
    """Storage RPC over oxenmq (`storage.*` commands).  Requires the oxenmq python module."""

    name = 'omq'
    bt = True

    def __init__(self):
        from oxenmq import OxenMQ

        self._omq = OxenMQ()
        self._omq.max_message_size = 10 * 1024 * 1024
        self._omq.start()

    def connect(self, sn):
        from oxenmq import Address

        return self._omq.connect_remote(
            Address(sn['ip'], sn['port_omq'], bytes.fromhex(sn['pubkey_x25519']))
        )

    def request(self, conn, method, payload=b'', *, timeout=DEFAULT_TIMEOUT):
        return self._omq.request_future(
            conn, f'storage.{method}', _payload_bytes(payload), request_timeout=timeout
        )

    def oxend(self, method, params):
        from oxenmq import Address

        remote = self._omq.connect_remote(Address(OXEND_OMQ))
        r = self._omq.request_future(remote, f'rpc.{method}', json.dumps(params).encode()).get()
        assert len(r) == 2 and r[0] == b'200', r
        return json.loads(r[1])


class _Future:
    def __init__(self, fut):
        self._fut = fut

    def get(self):
        return self._fut.result()


class HTTPS:
    """Storage RPC over HTTPS (`POST /storage_rpc/v1` with a json `method`/`params` body).  The
    storage server's certificate is self-signed, so it is not verified; the tests care about the
    RPC, not the transport security."""

    name = 'https'
    bt = False

    def __init__(self, workers=16):
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self._workers = workers
        self._pool = ThreadPoolExecutor(workers)

    def connect(self, sn):
        import requests

        session = requests.Session()
        session.verify = False
        # Tests fire batches of concurrent requests at one node; give the connection pool room.
        session.mount('https://', requests.adapters.HTTPAdapter(pool_maxsize=self._workers))
        return (session, f"https://{sn['ip']}:{sn['port_https']}/storage_rpc/v1")

    def request(self, conn, method, payload=b'', *, timeout=DEFAULT_TIMEOUT):
        payload = _payload_bytes(payload)
        body = {'method': method, 'params': json.loads(payload) if payload else {}}
        session, url = conn

        def post():
            r = session.post(url, json=body, timeout=timeout.total_seconds())
            if r.status_code == 200:
                return [r.content]
            return [str(r.status_code).encode(), r.content]

        return _Future(self._pool.submit(post))

    def oxend(self, method, params):
        import requests

        r = requests.post(
            OXEND_HTTP,
            json={'jsonrpc': '2.0', 'id': '0', 'method': method, 'params': params},
            timeout=DEFAULT_TIMEOUT.total_seconds(),
        )
        r.raise_for_status()
        return r.json()['result']


TRANSPORTS = {t.name: t for t in (OMQ, HTTPS)}
