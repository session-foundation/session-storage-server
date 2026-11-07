import base64
import json
import time

import pytest
from oxenc import bt_deserialize, bt_serialize

import ss
from test_monitor import (
    MONITOR_EXPIRY,
    collect_notifications,
    notify_request,
    wait_for_notifications,
)

# Sessions, like the monitoring they extend, need a transport the node can push down.
pytestmark = pytest.mark.monitor


def start_session(rpc, conn, token=None, list_live=None, per_account=None, body_max=None):
    """Starts (or, given `token`, resumes) a monitor session on `conn`, sending `l` when
    `list_live` is given, `m` when `per_account` is and `b` when `body_max` is; returns the decoded
    reply.  Skips the test if the node predates sessions."""
    req = {} if token is None else {'t': token}
    if body_max is not None:
        req['b'] = body_max
    if list_live is not None:
        req['l'] = int(list_live)
    if per_account is not None:
        req['m'] = per_account
    reply = rpc.monitor_session(conn, bt_serialize(req)).get()
    if reply is None:
        pytest.skip("node does not support monitor sessions")
    r = bt_deserialize(reply)
    assert len(r[b't']) == 32
    return r


def subscribe(rpc, conn, sk, namespaces=(0,), data=True, extra={}):
    """Subscribes `conn` to sk's (netid 3) account in `namespaces`, adding `extra` keys to the
    request; returns the reply entry."""
    req = notify_request(sk, int(time.time()), data, list(namespaces), netid=3)
    req.update(extra)
    r = rpc.monitor(conn, bt_serialize(req)).get()
    assert len(r) == 1
    entry = bt_deserialize(r[0])
    assert entry[b'success'] == 1, entry
    return entry


def account(sk):
    return b'\x03' + sk.verify_key.encode()


def store(rpc, conn, sk, data, namespace=0):
    """Stores `data` for sk's (netid 3) account in `namespace` (which must be one that takes
    unauthenticated stores, i.e. a multiple of 10); returns the stored message's hash."""
    r = rpc.request(
        conn,
        'store',
        json.dumps(
            {
                "pubkey": account(sk).hex(),
                "timestamp": int(time.time() * 1000),
                "ttl": 3600_000,
                "namespace": namespace,
                "data": base64.b64encode(data).decode(),
            }
        ).encode(),
    ).get()
    assert len(r) == 1, r
    return next(iter(json.loads(r[0])['swarm'].values()))['hash'].encode()


@pytest.fixture
def node(rpc, random_sn, sk, exclude):
    """A member of sk's (netid 3) swarm: sessions are per node."""
    return ss.random_swarm_members(ss.get_swarm(rpc, random_sn, sk, netid=3), 1, exclude)[0]


def test_session_new(rpc, node, sk):
    conn = rpc.connect(node)
    r = start_session(rpc, conn)
    assert r[b'r'] == 0
    assert r[b's'] == []
    assert r[b'm'] == {}
    assert b'o' not in r

    # Subscribing on a session-bound connection works as ever, and reports the expiry.
    entry = subscribe(rpc, conn, sk)
    assert 0 < entry[b'x'] <= MONITOR_EXPIRY


def test_session_resume_replays_missed(rpc, node, sk):
    conn = rpc.connect(node)
    token = start_session(rpc, conn)[b't']
    subscribe(rpc, conn, sk)
    rpc.disconnect(conn)

    # Stored while no connection is bound, so recorded for the resume.
    store_conn = rpc.connect(node)
    hashes = [store(rpc, store_conn, sk, f"missed {i}".encode()) for i in range(3)]
    time.sleep(1)

    conn2 = rpc.connect(node)
    [got] = collect_notifications(rpc, [conn2])
    r = start_session(rpc, conn2, token)
    assert r[b'r'] == 1
    assert r[b't'] != token
    assert len(r[b's']) == 1
    mon = r[b's'][0]
    assert mon[b'@'] == account(sk)
    assert mon[b'd'] == 1
    assert mon[b'n'] == [0]
    assert 0 < mon[b'x'] <= MONITOR_EXPIRY
    assert b'errcode' not in mon

    for _ in range(20):
        if len(got) >= len(hashes):
            break
        time.sleep(0.25)
    assert [n[b'h'] for n in got] == hashes
    assert [n[b'~'] for n in got] == [f"missed {i}".encode() for i in range(3)]

    # The session's monitor delivers live to the resumed connection too.
    del got[:]
    live = store(rpc, store_conn, sk, b"live")
    wait_for_notifications([got])
    assert [n[b'h'] for n in got] == [live]


def test_session_token_rotates(rpc, node, sk):
    conn = rpc.connect(node)
    first = start_session(rpc, conn)[b't']
    subscribe(rpc, conn, sk)
    second = start_session(rpc, rpc.connect(node), first)
    assert second[b'r'] == 1

    # The old token is no longer valid, so presenting it starts a new, empty session.
    r = start_session(rpc, rpc.connect(node), first)
    assert r[b'r'] == 0
    assert r[b's'] == []

    assert start_session(rpc, rpc.connect(node), second[b't'])[b'r'] == 1


def test_session_clean_start(rpc, node, sk):
    conn = rpc.connect(node)
    start_session(rpc, conn)
    subscribe(rpc, conn, sk)

    # Without a token a new connection starts a new, empty session.
    r = start_session(rpc, rpc.connect(node))
    assert r[b'r'] == 0
    assert r[b's'] == []


def test_session_resumes_from_another_key(rpc, node, sk):
    """The token is the only credential: a client presenting a different QUIC key resumes."""
    conn = rpc.connect(node)
    token = start_session(rpc, conn)[b't']
    subscribe(rpc, conn, sk)
    rpc.disconnect(conn)

    # The same transport type, but with a client key of its own.
    other = type(rpc)()
    try:
        r = start_session(other, other.connect(node), token)
        assert r[b'r'] == 1
        assert len(r[b's']) == 1
    finally:
        other.close()


def test_monitor_body_limit(rpc, node, sk):
    """A session's `b` cuts (or, at 0, leaves out) the body with `L`; a connection's own monitors
    are never limited, and a `b` in a subscription is ignored."""
    cut, omitted, full, ignored = (rpc.connect(node) for _ in range(4))
    got_cut, got_omitted, got_full, got_ignored = collect_notifications(
        rpc, [cut, omitted, full, ignored]
    )
    start_session(rpc, cut, body_max=3)
    start_session(rpc, omitted, body_max=0)
    start_session(rpc, ignored)
    subscribe(rpc, cut, sk)
    subscribe(rpc, omitted, sk)
    subscribe(rpc, full, sk)
    subscribe(rpc, ignored, sk, extra={'b': 3})

    store_conn = rpc.connect(node)
    h = store(rpc, store_conn, sk, b"abcdefgh")
    wait_for_notifications([got_cut, got_omitted, got_full, got_ignored])

    assert [(n[b'h'], n[b'~'], n[b'L']) for n in got_cut] == [(h, b"abc", 8)]
    assert [(n[b'h'], b'~' in n, n[b'L']) for n in got_omitted] == [(h, False, 8)]
    assert [(n[b'h'], n[b'~'], b'L' in n) for n in got_full] == [(h, b"abcdefgh", False)]
    assert got_ignored == got_full

    # A body within the limit comes as it always has.
    for g in (got_cut, got_omitted, got_full, got_ignored):
        del g[:]
    h2 = store(rpc, store_conn, sk, b"ab")
    wait_for_notifications([got_cut, got_full])
    assert got_cut == got_full
    assert [(n[b'h'], n[b'~'], b'L' in n) for n in got_cut] == [(h2, b"ab", False)]


def test_session_replay_uses_resume_body_limit(rpc, node, sk):
    """A replayed notification is limited by the `b` of the resuming request."""
    conn = rpc.connect(node)
    token = start_session(rpc, conn, body_max=2)[b't']
    subscribe(rpc, conn, sk)
    rpc.disconnect(conn)

    h = store(rpc, rpc.connect(node), sk, b"abcdefgh")
    time.sleep(1)

    conn2 = rpc.connect(node)
    [got] = collect_notifications(rpc, [conn2])
    r = start_session(rpc, conn2, token, body_max=5)
    assert r[b'r'] == 1
    wait_for_notifications([got])
    assert [(n[b'h'], n[b'~'], n[b'L']) for n in got] == [(h, b"abcde", 8)]


def settle(got):
    """Waits for notifications to land in `got`, then a little longer in case of any duplicate."""
    wait_for_notifications([got])
    time.sleep(1)


def test_monitor_disjoint_namespaces(rpc, node, sk):
    # Nodes from before sessions merged an account's subscriptions on a connection.
    start_session(rpc, rpc.connect(node))

    conn = rpc.connect(node)
    [got] = collect_notifications(rpc, [conn])
    subscribe(rpc, conn, sk, namespaces=(10, 20), data=False)
    subscribe(rpc, conn, sk, namespaces=(30, 40), data=True)

    store_conn = rpc.connect(node)
    h20 = store(rpc, store_conn, sk, b"twenty", namespace=20)
    settle(got)
    assert [(n[b'h'], n[b'n'], b'~' in n) for n in got] == [(h20, 20, False)]

    del got[:]
    h30 = store(rpc, store_conn, sk, b"thirty", namespace=30)
    settle(got)
    assert [(n[b'h'], n[b'n'], n.get(b'~')) for n in got] == [(h30, 30, b"thirty")]


def test_monitor_overlapping_namespaces(rpc, node, sk):
    conn = rpc.connect(node)
    [got] = collect_notifications(rpc, [conn])
    start_session(rpc, conn, body_max=3)
    subscribe(rpc, conn, sk, namespaces=(10, 20), data=False)
    subscribe(rpc, conn, sk, namespaces=(20, 30), data=True)

    # One notification for the connection, with data because one of its monitors wants it, cut to
    # the session's limit.
    h = store(rpc, rpc.connect(node), sk, b"abcdef", namespace=20)
    settle(got)
    assert [(n[b'h'], n[b'~'], n[b'L']) for n in got] == [(h, b"abc", 6)]


def test_session_lists_each_monitor(rpc, node, sk):
    conn = rpc.connect(node)
    token = start_session(rpc, conn)[b't']
    subscribe(rpc, conn, sk, namespaces=(10, 20), data=False)
    subscribe(rpc, conn, sk, namespaces=(30,), data=True)
    rpc.disconnect(conn)

    r = start_session(rpc, rpc.connect(node), token)
    assert r[b'r'] == 1
    listed = sorted(r[b's'], key=lambda m: m[b'n'])
    assert [m[b'@'] for m in listed] == [account(sk)] * 2
    assert [(m[b'n'], m[b'd']) for m in listed] == [([10, 20], 0), ([30], 1)]
    assert not any(b'b' in m for m in listed)
    assert all(0 < m[b'x'] <= MONITOR_EXPIRY for m in listed)


@pytest.mark.parametrize("list_live", [False, True, None])
def test_session_resume_listing(rpc, node, sk, list_live):
    """With l=0 a resume lists only ended monitors (which a test cannot cause on a live network, so
    none here), and the replay is unaffected; l=1 and no l list the live monitors too."""
    conn = rpc.connect(node)
    token = start_session(rpc, conn)[b't']
    subscribe(rpc, conn, sk, namespaces=(10, 20), data=False)
    subscribe(rpc, conn, sk, namespaces=(30,), data=True)
    rpc.disconnect(conn)

    h = store(rpc, rpc.connect(node), sk, b"while away", namespace=30)
    time.sleep(1)

    conn2 = rpc.connect(node)
    [got] = collect_notifications(rpc, [conn2])
    r = start_session(rpc, conn2, token, list_live=list_live)
    assert r[b'r'] == 1
    assert r[b't'] != token
    if list_live is False:
        assert r[b's'] == []
    else:
        listed = sorted(r[b's'], key=lambda m: m[b'n'])
        assert [(m[b'@'], m[b'n'], m[b'd']) for m in listed] == [
            (account(sk), [10, 20], 0),
            (account(sk), [30], 1),
        ]

    wait_for_notifications([got])
    assert [(n[b'h'], n[b'~']) for n in got] == [(h, b"while away")]


@pytest.mark.parametrize("per_account", [None, 2])
def test_session_missed_per_account(rpc, node, sk, per_account):
    """With `m` only each account's newest `m` missed notifications are replayed, and the reply
    counts the rest per account and namespace; without it all of them are."""
    conn = rpc.connect(node)
    r = start_session(rpc, conn, per_account=per_account)
    if per_account is not None and b'm' not in r:
        # `m` came after sessions themselves; an older node ignores it.
        pytest.skip("node does not support a per-account missed limit")
    token = r[b't']
    subscribe(rpc, conn, sk)
    rpc.disconnect(conn)

    store_conn = rpc.connect(node)
    hashes = [store(rpc, store_conn, sk, f"missed {i}".encode()) for i in range(3)]
    time.sleep(1)

    conn2 = rpc.connect(node)
    [got] = collect_notifications(rpc, [conn2])
    r = start_session(rpc, conn2, token, per_account=per_account)
    assert r[b'r'] == 1
    if per_account is None:
        assert r[b'm'] == {}
        kept = hashes
    else:
        assert r[b'm'] == {account(sk): [{b'n': 0, b'o': 1}]}
        kept = hashes[1:]

    for _ in range(20):
        if len(got) >= len(kept):
            break
        time.sleep(0.25)
    time.sleep(0.5)
    assert [n[b'h'] for n in got] == kept


def test_session_pipelined_monitor(rpc, node, sk):
    """A `monitor` sent right behind `monitor_session` on the same stream, without waiting for its
    reply, joins the session: it outlives the connection and is there on resuming."""
    conn = rpc.connect(node)
    session = rpc.monitor_session(conn, bt_serialize({}))
    sub = rpc.monitor(conn, bt_serialize(notify_request(sk, int(time.time()), True, [0], netid=3)))
    reply = session.get()
    if reply is None:
        pytest.skip("node does not support monitor sessions")
    token = bt_deserialize(reply)[b't']
    [entry] = sub.get()
    assert bt_deserialize(entry)[b'success'] == 1
    rpc.disconnect(conn)

    r = start_session(rpc, rpc.connect(node), token)
    assert r[b'r'] == 1
    assert [m[b'@'] for m in r[b's']] == [account(sk)]


def test_session_replays_everything(rpc, node, sk):
    """Everything a session missed is replayed, however much there is."""
    conn = rpc.connect(node)
    token = start_session(rpc, conn)[b't']
    subscribe(rpc, conn, sk, data=False)
    rpc.disconnect(conn)

    store_conn = rpc.connect(node)
    hashes = [store(rpc, store_conn, sk, f"m{i}".encode()) for i in range(300)]
    time.sleep(1)
    c = rpc.connect(node)
    [got] = collect_notifications(rpc, [c])
    start_session(rpc, c, token)
    for _ in range(40):
        if len(got) >= len(hashes):
            break
        time.sleep(0.25)
    assert [n[b'h'] for n in got] == hashes
