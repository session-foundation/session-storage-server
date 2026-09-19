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
import re
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


def _oxend_http(method, params):
    import requests

    r = requests.post(
        OXEND_HTTP,
        json={'jsonrpc': '2.0', 'id': '0', 'method': method, 'params': params},
        timeout=DEFAULT_TIMEOUT.total_seconds(),
    )
    r.raise_for_status()
    return r.json()['result']


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


class _Future:
    def __init__(self, fut):
        self._fut = fut

    def get(self):
        return self._fut.result()


class OMQ:
    """Storage RPC over oxenmq (`storage.*` commands).  Requires the oxenmq python module."""

    name = 'omq'
    bt = True

    def __init__(self):
        from oxenmq import OxenMQ

        self._omq = OxenMQ()
        self._omq.max_message_size = 10 * 1024 * 1024
        self._omq.start()

    def close(self):
        pass

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

    def close(self):
        self._pool.shutdown(wait=False)

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

    oxend = staticmethod(_oxend_http)


# A QUIC reply to a json request is the json list [code, body]; to a bt request it is the bt list
# of the same.  These pull the body back out textually, so that it is byte-for-byte what the
# server produced rather than a re-serialisation.
_QUIC_JSON_WRAP = re.compile(rb'^\[(\d+),(.*)\]$', re.DOTALL)
_QUIC_BT_WRAP = re.compile(rb'^li(\d+)e(.*)e$', re.DOTALL)


def _quic_unwrap(body):
    """Returns (code, body) from a wrapped QUIC reply, or (None, body) for an unwrapped one (a
    plain-text error, or a raw binary response)."""
    for wrap in (_QUIC_JSON_WRAP, _QUIC_BT_WRAP):
        if m := wrap.match(body):
            return int(m.group(1)), m.group(2)
    return None, body


class QUIC:
    """Storage RPC over QUIC, via the seshquic bindings for libquic: a bt-request stream on a
    connection with the storage server's client ALPN, where the request name is the RPC method.
    The server is authenticated by its ed25519 key; the client presents a throwaway one."""

    name = 'quic'
    bt = True

    ALPN = "oxenstorage"

    def __init__(self):
        import seshquic
        from nacl.signing import SigningKey

        sk = SigningKey.generate()
        self._creds = seshquic.Credentials.from_ed_keys(sk.encode(), sk.verify_key.encode())
        self._endpoint = seshquic.Endpoint("0.0.0.0:0")

    def close(self):
        self._endpoint.close()

    def connect(self, sn):
        conn = self._endpoint.connect(
            (sn['ip'], sn['port_quic']),
            remote_pubkey=bytes.fromhex(sn['pubkey_ed25519']),
            creds=self._creds,
            alpns=[self.ALPN],
        )
        return conn.open_bt_stream()

    def request(self, conn, method, payload=b'', *, timeout=DEFAULT_TIMEOUT):
        import seshquic

        fut = conn.request(method, _payload_bytes(payload), timeout=timeout.total_seconds())

        class Reply:
            def get(self):
                try:
                    body = fut.result()
                except seshquic.RequestError as e:
                    # "<code> <reason>\n\n<body>", where <body> may itself be wrapped.
                    header, _, rest = e.body.partition(b'\n\n')
                    code = int(header.split(b' ', 1)[0])
                    inner_code, rest = _quic_unwrap(rest)
                    if inner_code is not None and rest.startswith(b'"'):
                        rest = json.loads(rest).encode()
                    return [str(code).encode(), rest]
                code, body = _quic_unwrap(body)
                return [body]

        return Reply()

    oxend = staticmethod(_oxend_http)


TRANSPORTS = {t.name: t for t in (OMQ, HTTPS, QUIC)}
