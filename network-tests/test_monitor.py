import pytest
import ss
import subaccount
import time
from nacl.hash import blake2b
from nacl.encoding import RawEncoder, Base64Encoder
from nacl.signing import SigningKey, VerifyKey
from typing import Optional, Union
import nacl.bindings as sodium
import json
import base64

from oxenc import bt_serialize, bt_deserialize

# Message monitoring needs the node to push notifications back down the connection, which HTTPS
# cannot do.
pytestmark = pytest.mark.monitor


def notify_request(
    sk: SigningKey,
    ts: int,
    data: bool,
    namespaces: list,
    *,
    netid: int = 0x05,
    sessionid: bool = False,
    account: Optional[Union[SigningKey, VerifyKey]] = None,  # For use with subaccounts
    subacc_token: bytes = b"",
    subacc_sig: bytes = b"",
):
    req = {'n': sorted(namespaces), 'd': int(data), 't': ts}

    if account is None:
        account = sk.verify_key
    elif isinstance(account, SigningKey):
        account = account.verify_key

    if sessionid:
        assert netid == 0x05
        req['P'] = account.encode()
        account = b'\x05' + account.to_curve25519_public_key().encode()
    else:
        account = netid.to_bytes(1, 'big') + account.encode()
        req['p'] = account

    # ( "MONITOR" || ACCOUNT || TS || D || NS[0] || ... || NS[n] )
    message = (
        f'MONITOR{account.hex()}{ts:d}{data:d}' + ','.join(f'{n}' for n in req['n'])
    ).encode()

    req['s'] = sk.sign(message).signature
    if subacc_token:
        assert type(subacc_token) == bytes and len(subacc_token) == 36
        assert type(subacc_sig) == bytes and len(subacc_sig) == 64
        req['S'] = subacc_sig
        req['T'] = subacc_token

    return req


def register_all(rpc, swarm, make_request):
    """Connects to every member of `swarm` and subscribes with `make_request()` on each; returns
    the connections (in swarm order) once every node has accepted."""
    conns = [rpc.connect(snode) for snode in swarm['snodes']]
    registered = [rpc.monitor(c, bt_serialize(make_request())) for c in conns]
    assert [r.get() for r in registered] == [[b'd7:successi1ee']] * len(conns)
    return conns


def test_monitor_reg_ed(rpc, random_sn, sk, exclude):
    swarm = ss.get_swarm(rpc, random_sn, sk)
    ts = int(time.time())
    register_all(rpc, swarm, lambda: notify_request(sk, ts, True, [-5, 0, 23], netid=3))


def test_monitor_reg_session(rpc, random_sn, sk, exclude):
    # A Session ID is 05 + the x25519 key derived from sk, so that is the account whose swarm we
    # need; the nodes check that the account is theirs before accepting the subscription.
    swarm = ss.get_swarm(rpc, random_sn, sk.to_curve25519_private_key())
    ts = int(time.time())
    register_all(
        rpc, swarm, lambda: notify_request(sk, ts, True, [-5, 0, 23], netid=5, sessionid=True)
    )


def test_monitor_reg_subaccount(rpc, random_sn, sk, exclude):
    swarm = ss.get_swarm(rpc, random_sn, sk)
    ts = int(time.time())

    def make_request():
        sub_sk, sub_token, sub_sig = subaccount.make_subaccount(2, sk)
        return notify_request(
            sub_sk,
            ts,
            True,
            [-5, 0, 23],
            netid=2,
            account=sk,
            subacc_token=sub_token,
            subacc_sig=sub_sig,
        )

    register_all(rpc, swarm, make_request)


def collect_notifications(rpc, conns):
    """Arranges for each connection's pushed notifications to land, decoded, in a list; returns
    the lists (one per connection)."""
    responses = [[] for _ in conns]
    for c, r in zip(conns, responses):
        rpc.on_notify(c, lambda body, r=r: r.append(bt_deserialize(body)))
    return responses


def wait_for_notifications(responses, tries=8):
    # It's pretty rare that the notifications don't beat the store response back to us (they
    # don't have to be onion-routed), but give them a couple seconds anyway.
    for _ in range(tries):
        if all(responses):
            break
        time.sleep(0.25)


def test_monitor_push(rpc, random_sn, sk, exclude):
    swarm = ss.get_swarm(rpc, random_sn, sk)

    ts = int(time.time())
    conns = [rpc.connect(snode) for snode in swarm['snodes']]
    responses = collect_notifications(rpc, conns)

    registered = []
    for i, c in enumerate(conns):
        # The first three are set up as full subscriptions; beyond that we use subaccounts:
        req_sk, sub_token, sub_sig = sk, None, None
        if i >= 3:
            req_sk, sub_token, sub_sig = subaccount.make_subaccount(3, sk)
        registered.append(
            rpc.monitor(
                c,
                bt_serialize(
                    notify_request(
                        req_sk,
                        ts,
                        True,
                        [-5, 0, 23],
                        netid=3,
                        account=sk,
                        subacc_token=sub_token,
                        subacc_sig=sub_sig,
                    )
                ),
            )
        )
    assert [r.get() for r in registered] == [[b'd7:successi1ee']] * len(conns)

    # Now go send a message:
    sn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = rpc.connect(sn)

    ts = int(time.time() * 1000)
    ttl = 86400000
    exp = ts + ttl
    # Store a message for myself
    s = rpc.request(
        conn,
        'store',
        json.dumps(
            {
                "pubkey": '03' + sk.verify_key.encode().hex(),
                "timestamp": ts,
                "ttl": ttl,
                "data": base64.b64encode("abc 123".encode()).decode(),
            }
        ).encode(),
    )

    # And another, but this one in a non-monitored namespace:
    s2 = rpc.request(
        conn,
        'store',
        json.dumps(
            {
                "pubkey": '03' + sk.verify_key.encode().hex(),
                "timestamp": ts,
                "namespace": 123,
                "ttl": ttl,
                "data": base64.b64encode("abc 123".encode()).decode(),
            }
        ).encode(),
    )

    s = s.get()
    assert len(s) == 1
    s = json.loads(s[0])
    hash = (
        blake2b(b'\x03' + sk.verify_key.encode() + b'abc 123', encoder=Base64Encoder)
        .decode()
        .rstrip('=')
    )
    assert [v['hash'] for v in s['swarm'].values()] == [hash] * len(s['swarm'])

    s2 = s2.get()

    wait_for_notifications(responses)

    expected_notify = {
        b'@': b'\x03' + sk.verify_key.encode(),
        b'h': hash.encode(),
        b'n': 0,
        b't': ts,
        b'z': exp,
        b'~': b'abc 123',
    }

    assert responses == [[expected_notify]] * len(conns)


def test_monitor_multi(rpc, random_sn, sk, exclude):
    swarm = ss.get_swarm(rpc, random_sn, sk, netid=3)

    # Both subscriptions in the combined request go to sk's swarm, and a node only accepts a
    # subscription for an account it stores, so sk2 has to land in the same swarm.
    while True:
        sk2 = SigningKey.generate()
        if ss.get_swarm(rpc, random_sn, sk2, netid=3)['swarm'] == swarm['swarm']:
            break

    ts = int(time.time())
    conns = [rpc.connect(snode) for snode in swarm['snodes']]
    responses = collect_notifications(rpc, conns)

    registered = [
        rpc.monitor(
            c,
            bt_serialize(
                [
                    notify_request(sk2, ts, True, [0], netid=3),
                    notify_request(sk, ts, True, [-5, 0, 23], netid=3),
                ]
            ),
        )
        for c in conns
    ]
    assert [r.get() for r in registered] == [[b'l' + b'd7:successi1ee' * 2 + b'e']] * len(conns)

    # Now go send a message:
    sn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = rpc.connect(sn)

    ts = int(time.time() * 1000)
    ttl = 86400000
    exp = ts + ttl
    # Store a message for myself
    s = rpc.request(
        conn,
        'store',
        json.dumps(
            {
                "pubkey": '03' + sk.verify_key.encode().hex(),
                "timestamp": ts,
                "ttl": ttl,
                "data": base64.b64encode("xyz 123".encode()).decode(),
            }
        ).encode(),
    ).get()
    assert len(s) == 1
    s = json.loads(s[0])

    wait_for_notifications(responses)

    hash = next(iter(s['swarm'].values()))['hash']

    expected_notify = {
        b'@': b'\x03' + sk.verify_key.encode(),
        b'h': hash.encode(),
        b'n': 0,
        b't': ts,
        b'z': exp,
        b'~': b'xyz 123',
    }

    assert responses == [[expected_notify]] * len(conns)
