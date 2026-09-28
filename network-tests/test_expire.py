import ss
from util import random_time_delta_ms
import time
import base64
import json
from nacl.encoding import HexEncoder, Base64Encoder
from nacl.signing import VerifyKey
import nacl.exceptions


def test_expire_all(rpc, random_sn, sk, exclude):
    swarm = ss.get_swarm(rpc, random_sn, sk)
    sns = ss.random_swarm_members(swarm, 2, exclude)
    conns = [rpc.connect(sn) for sn in sns]

    msgs = ss.store_n(rpc, conns[0], sk, b"omg123", 5)

    my_ss_id = '05' + sk.verify_key.encode().hex()

    ts = msgs[2]['req']['expiry']
    to_sign = "expire_all{}".format(ts).encode()
    sig = sk.sign(to_sign, encoder=Base64Encoder).signature.decode()
    params = json.dumps({"pubkey": my_ss_id, "expiry": ts, "signature": sig}).encode()

    resp = rpc.request(conns[1], 'expire_all', [params]).get()

    assert len(resp) == 1
    r = json.loads(resp[0])

    assert set(r['swarm'].keys()) == {x['pubkey_ed25519'] for x in swarm['snodes']}

    # 0 and 1 have later expiries than 2, so they should get updated; 2's expiry is already the
    # given value, and 3/4 are <= so shouldn't get updated.
    msg_hashes = sorted(msgs[i]['hash'] for i in (0, 1))

    # signature of ( PUBKEY_HEX || EXPIRY || UPDATED[0] || ... || UPDATED[N] )
    expected_signed = "".join((my_ss_id, str(ts), *msg_hashes)).encode()
    for k, v in r['swarm'].items():
        assert v['updated'] == msg_hashes
        edpk = VerifyKey(k, encoder=HexEncoder)
        edpk.verify(expected_signed, base64.b64decode(v['signature']))

    r = rpc.request(
        conns[0],
        'retrieve',
        [
            json.dumps(
                {
                    "pubkey": my_ss_id,
                    "timestamp": ts,
                    "signature": sk.sign(
                        f"retrieve{ts}".encode(), encoder=Base64Encoder
                    ).signature.decode(),
                }
            ).encode()
        ],
    ).get()
    assert len(r) == 1
    r = json.loads(r[0])
    assert len(r['messages']) == 5

    assert r['messages'][0]['expiration'] == ts
    assert r['messages'][1]['expiration'] == ts
    assert r['messages'][2]['expiration'] == ts
    assert r['messages'][3]['expiration'] == msgs[3]['req']['expiry']
    assert r['messages'][4]['expiration'] == msgs[4]['req']['expiry']


def test_stale_expire_all(rpc, random_sn, sk, exclude):
    swarm = ss.get_swarm(rpc, random_sn, sk)
    sn = ss.random_swarm_members(swarm, 2, exclude)[0]
    conn = rpc.connect(sn)

    msgs = ss.store_n(rpc, conn, sk, b"omg123", 5)

    my_ss_id = '05' + sk.verify_key.encode().hex()

    ts = int((time.time() - 120) * 1000)
    to_sign = "expire_all{}".format(ts).encode()
    sig = sk.sign(to_sign, encoder=Base64Encoder).signature.decode()
    params = {"pubkey": my_ss_id, "expiry": ts, "signature": sig}

    resp = rpc.request(conn, 'expire_all', [json.dumps(params).encode()]).get()
    assert resp == [b'406', b'expire_all timestamp should be >= current time']


def test_expire(rpc, random_sn, sk, exclude):
    swarm = ss.get_swarm(rpc, random_sn, sk)
    sns = ss.random_swarm_members(swarm, 2, exclude)
    conns = [rpc.connect(sn) for sn in sns]

    msgs = ss.store_n(rpc, conns[0], sk, b"omg123", 10)

    my_ss_id = '05' + sk.verify_key.encode().hex()

    ts = msgs[6]['req']['expiry']
    hashes = [msgs[i]['hash'] for i in (0, 1, 5, 6, 7, 9)] + [
        'bepQtTaYrzcuCXO3fZkmk/h3xkMQ3vCh94i5HzLmj3I'
    ]
    # Make sure `hashes` input isn't provided in sorted order:
    if hashes[0] < hashes[1]:
        hashes[0], hashes[1] = hashes[1], hashes[0]
    actual_update_msgs = sorted(msgs[i]['hash'] for i in (0, 1, 5, 6, 7, 9))
    assert hashes[0:2] != actual_update_msgs[0:2]

    hashes = sorted(hashes, reverse=True)
    to_sign = ("expire" + str(ts) + "".join(hashes)).encode()
    sig = sk.sign(to_sign, encoder=Base64Encoder).signature.decode()
    params = json.dumps(
        {"pubkey": my_ss_id, "messages": hashes, "expiry": ts, "signature": sig}
    ).encode()

    resp = rpc.request(conns[1], 'expire', [params]).get()

    assert len(resp) == 1
    r = json.loads(resp[0])

    assert set(r['swarm'].keys()) == {x['pubkey_ed25519'] for x in swarm['snodes']}

    # ( PUBKEY_HEX || EXPIRY || RMSG[0] || ... || RMSG[N] || UMSG[0] || ... || UMSG[M] )
    expected_signed = "".join((my_ss_id, str(ts), *hashes, *actual_update_msgs)).encode()
    for k, v in r['swarm'].items():
        assert v['updated'] == actual_update_msgs
        edpk = VerifyKey(k, encoder=HexEncoder)
        try:
            edpk.verify(expected_signed, base64.b64decode(v['signature']))
        except nacl.exceptions.BadSignatureError as e:
            print("Bad signature from swarm member {}".format(k))
            raise e

    r = rpc.request(
        conns[0],
        'retrieve',
        [
            json.dumps(
                {
                    "pubkey": my_ss_id,
                    "timestamp": ts,
                    "signature": sk.sign(
                        f"retrieve{ts}".encode(), encoder=Base64Encoder
                    ).signature.decode(),
                }
            ).encode()
        ],
    ).get()
    assert len(r) == 1
    r = json.loads(r[0])
    assert len(r['messages']) == 10

    for i in range(10):
        assert (
            r['messages'][i]['expiration'] == ts if i in (0, 1, 5, 6) else msgs[i]['req']['expiry']
        )

    # Also try with a *single* hash, which reportedly didn't return the right thing
    hashes = [msgs[4]['hash']]
    to_sign = ("expire" + str(ts) + hashes[0]).encode()
    sig = sk.sign(to_sign, encoder=Base64Encoder).signature.decode()
    params = json.dumps(
        {"pubkey": my_ss_id, "messages": hashes, "expiry": ts, "signature": sig}
    ).encode()

    resp = rpc.request(conns[1], 'expire', [params]).get()

    assert len(resp) == 1
    r = json.loads(resp[0])

    assert set(r['swarm'].keys()) == {x['pubkey_ed25519'] for x in swarm['snodes']}

    # ( PUBKEY_HEX || EXPIRY || RMSG[0] || ... || RMSG[N] || UMSG[0] || ... || UMSG[M] )
    expected_signed = "".join((my_ss_id, str(ts), hashes[0], hashes[0])).encode()
    for k, v in r['swarm'].items():
        assert v['updated'] == hashes
        edpk = VerifyKey(k, encoder=HexEncoder)
        try:
            edpk.verify(expected_signed, base64.b64decode(v['signature']))
        except nacl.exceptions.BadSignatureError as e:
            print("Bad signature from swarm member {}".format(k))
            raise e


def test_expire_extend(rpc, random_sn, sk, exclude):
    swarm = ss.get_swarm(rpc, random_sn, sk)

    sn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = rpc.connect(sn)

    msgs = ss.store_n(rpc, conn, sk, b"omg123", 10)

    now = int(time.time() * 1000)

    my_ss_id = '05' + sk.verify_key.encode().hex()

    for m in msgs:
        assert m["req"]["expiry"] < now + 60_000

    exp_5min = now + 5 * 60 * 1000
    exp_long = (
        now + 31 * 24 * 60 * 60 * 1000
    )  # Beyond max TTL, should get shortened to now + max TTL
    e = rpc.request(
        conn,
        'sequence',
        [
            json.dumps(
                {
                    'requests': [
                        {
                            'method': 'expire',
                            'params': {
                                "pubkey": my_ss_id,
                                "messages": [m["hash"] for m in msgs[0:8]],
                                "expiry": exp_5min,
                                "signature": sk.sign(
                                    f"expire{exp_5min}{''.join(m['hash'] for m in msgs[0:8])}".encode(),
                                    encoder=Base64Encoder,
                                ).signature.decode(),
                            },
                        },
                        {
                            'method': 'expire',
                            'params': {
                                "pubkey": my_ss_id,
                                "messages": [m["hash"] for m in msgs[8:]],
                                "expiry": exp_long,
                                "signature": sk.sign(
                                    f"expire{exp_long}{''.join(m['hash'] for m in msgs[8:])}".encode(),
                                    encoder=Base64Encoder,
                                ).signature.decode(),
                            },
                        },
                        {
                            'method': 'retrieve',
                            'params': {
                                'pubkey': my_ss_id,
                                'timestamp': now,
                                'signature': sk.sign(
                                    f"retrieve{now}".encode(), encoder=Base64Encoder
                                ).signature.decode(),
                            },
                        },
                    ]
                }
            )
        ],
    ).get()

    assert len(e) == 1
    e = json.loads(e[0])
    assert [x['code'] for x in e['results']] == [200, 200, 200]
    e = [x['body'] for x in e['results']]

    assert 5 <= len(e[0]['swarm']) <= 10
    for s in e[0]['swarm'].values():
        assert s['expiry'] == exp_5min
        assert s['updated'] == sorted([m["hash"] for m in msgs[0:8]])

    assert 5 <= len(e[1]['swarm']) <= 10
    for s in e[1]['swarm'].values():
        # expiry should have been shortened to now + max TTL:
        assert s['expiry'] < exp_long
        assert abs(s['expiry'] - 1000 * (time.time() + 30 * 24 * 60 * 60)) <= 5000
        assert s['updated'] == sorted([m["hash"] for m in msgs[8:]])

    assert set(m['hash'] for m in e[2]['messages']) == set(m['hash'] for m in msgs)
    exps = {m['hash']: m['expiration'] for m in e[2]['messages']}
    ts = {m['hash']: m['timestamp'] for m in e[2]['messages']}
    for m in msgs:
        assert ts[m['hash']] == m['req']['timestamp']
    for m in msgs[0:8]:
        assert exps[m['hash']] == exp_5min
    for m in msgs[8:]:
        assert abs(exps[m['hash']] - 1000 * (time.time() + 30 * 24 * 60 * 60)) <= 5000


def test_expire_shorten_extend(rpc, random_sn, sk, exclude):
    swarm = ss.get_swarm(rpc, random_sn, sk)

    sn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = rpc.connect(sn)

    now_s = time.time()
    now = int(now_s * 1000)

    msgs = ss.store_n(rpc, conn, sk, b"omg123", 10, now=now_s, ttl=60)

    my_ss_id = '05' + sk.verify_key.encode().hex()

    assert [m["req"]["expiry"] for m in msgs] == [now + x * 1000 for x in range(60, 50, -1)]

    do_not_exist = [
        '///////////////////////////////////////////',
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq',
        'rstuvwxyz0123456789+/ABCDEFGHIJKLMNOPQRSTUV',
    ]
    dne_sig = ''.join(do_not_exist)

    exp_20s = now + 20 * 1000
    exp_30s = now + 30 * 1000
    exp_45s = now + 45 * 1000
    exp_10m = now + 10 * 60 * 1000
    e = rpc.request(
        conn,
        'sequence',
        [
            json.dumps(
                {
                    'requests': [
                        {
                            # shorten 0-3 from 1min to 30s
                            'method': 'expire',
                            'params': {
                                "pubkey": my_ss_id,
                                "messages": [m["hash"] for m in msgs[0:4]] + do_not_exist,
                                "expiry": exp_30s,
                                "shorten": True,
                                "signature": sk.sign(
                                    f"expireshorten{exp_30s}{''.join(m['hash'] for m in msgs[0:4])}{dne_sig}".encode(),
                                    encoder=Base64Encoder,
                                ).signature.decode(),
                            },
                        },
                        {
                            'method': 'get_expiries',
                            'params': {
                                "pubkey": my_ss_id,
                                "messages": [m["hash"] for m in msgs] + do_not_exist,
                                "timestamp": now,
                                "signature": sk.sign(
                                    f"get_expiries{now}{''.join(m['hash'] for m in msgs)}{dne_sig}".encode(),
                                    encoder=Base64Encoder,
                                ).signature.decode(),
                            },
                        },
                        {
                            # shorten 4-7 from 1min to 20s
                            'method': 'expire',
                            'params': {
                                "pubkey": my_ss_id,
                                "messages": [m["hash"] for m in msgs[4:8]] + do_not_exist,
                                "expiry": exp_20s,
                                "shorten": True,
                                "signature": sk.sign(
                                    f"expireshorten{exp_20s}{''.join(m['hash'] for m in msgs[4:8])}{dne_sig}".encode(),
                                    encoder=Base64Encoder,
                                ).signature.decode(),
                            },
                        },
                        {
                            'method': 'get_expiries',
                            'params': {
                                "pubkey": my_ss_id,
                                "messages": [m["hash"] for m in msgs] + do_not_exist,
                                "timestamp": now,
                                "signature": sk.sign(
                                    f"get_expiries{now}{''.join(m['hash'] for m in msgs)}{dne_sig}".encode(),
                                    encoder=Base64Encoder,
                                ).signature.decode(),
                            },
                        },
                        {
                            # shorten 6-9 to 10min (from 1min); should all fail to shorten
                            'method': 'expire',
                            'params': {
                                "pubkey": my_ss_id,
                                "messages": [m["hash"] for m in msgs[6:]],
                                "expiry": exp_10m,
                                "shorten": True,
                                "signature": sk.sign(
                                    f"expireshorten{exp_10m}{''.join(m['hash'] for m in msgs[6:])}".encode(),
                                    encoder=Base64Encoder,
                                ).signature.decode(),
                            },
                        },
                        {
                            'method': 'get_expiries',
                            'params': {
                                "pubkey": my_ss_id,
                                "messages": [m["hash"] for m in msgs] + do_not_exist,
                                "timestamp": now,
                                "signature": sk.sign(
                                    f"get_expiries{now}{''.join(m['hash'] for m in msgs)}{dne_sig}".encode(),
                                    encoder=Base64Encoder,
                                ).signature.decode(),
                            },
                        },
                        {
                            # shorten 2-5 to 20s; should work for 2-3 (30s) but fail for 4-5
                            # (already <=20s).
                            'method': 'expire',
                            'params': {
                                "pubkey": my_ss_id,
                                "messages": [m["hash"] for m in msgs[2:6]] + do_not_exist,
                                "expiry": exp_20s,
                                "shorten": True,
                                "signature": sk.sign(
                                    f"expireshorten{exp_20s}{''.join(m['hash'] for m in msgs[2:6])}{dne_sig}".encode(),
                                    encoder=Base64Encoder,
                                ).signature.decode(),
                            },
                        },
                        {
                            'method': 'get_expiries',
                            'params': {
                                "pubkey": my_ss_id,
                                "messages": [m["hash"] for m in msgs] + do_not_exist,
                                "timestamp": now,
                                "signature": sk.sign(
                                    f"get_expiries{now}{''.join(m['hash'] for m in msgs)}{dne_sig}".encode(),
                                    encoder=Base64Encoder,
                                ).signature.decode(),
                            },
                        },
                        {
                            # length everything to 45s in extend-only mode; should fail for shorten
                            # 2-5 to 20s; should work for 0-7 (20s or 30s) but fail for 8-9 (1min)
                            'method': 'expire',
                            'params': {
                                "pubkey": my_ss_id,
                                "messages": [m["hash"] for m in msgs] + do_not_exist,
                                "expiry": exp_45s,
                                "extend": True,
                                "signature": sk.sign(
                                    f"expireextend{exp_45s}{''.join(m['hash'] for m in msgs)}{dne_sig}".encode(),
                                    encoder=Base64Encoder,
                                ).signature.decode(),
                            },
                        },
                        {
                            'method': 'retrieve',
                            'params': {
                                'pubkey': my_ss_id,
                                'timestamp': now,
                                'signature': sk.sign(
                                    f"retrieve{now}".encode(), encoder=Base64Encoder
                                ).signature.decode(),
                            },
                        },
                        {
                            'method': 'get_expiries',
                            'params': {
                                "pubkey": my_ss_id,
                                "messages": [msgs[0]["hash"]],
                                "timestamp": now,
                                "signature": sk.sign(
                                    f"get_expiries{now}{msgs[0]['hash']}".encode(),
                                    encoder=Base64Encoder,
                                ).signature.decode(),
                            },
                        },
                    ]
                }
            )
        ],
    ).get()

    assert len(e) == 1
    e = json.loads(e[0])
    assert [x['code'] for x in e['results']] == [200] * 11
    e = [x['body'] for x in e['results']]

    e0_exp = {'expiry': exp_30s, 'updated': sorted(m["hash"] for m in msgs[0:4]), 'unchanged': {}}

    assert 5 <= len(e[0]['swarm']) <= 10
    for snpk, s in e[0]['swarm'].items():
        assert s['expiry'] == exp_30s
        assert s['updated'] == sorted(m["hash"] for m in msgs[0:4])
        assert s['unchanged'] == {}
        # signature of ( PUBKEY_HEX || EXPIRY || RMSGs... || UMSGs... || CMSG_EXPs... )
        expected_signed = "".join(
            [my_ss_id, str(exp_30s)] + [m["hash"] for m in msgs[0:4]] + do_not_exist + s['updated']
        ).encode()
        edpk = VerifyKey(snpk, encoder=HexEncoder)
        edpk.verify(expected_signed, base64.b64decode(s['signature']))

    assert e[1] == {
        "expiries": {
            **{m["hash"]: exp_30s for m in msgs[0:4]},
            **{msgs[i]["hash"]: now + (60 - i) * 1000 for i in range(4, 10)},
        }
    }

    assert 5 <= len(e[2]['swarm']) <= 10
    for snpk, s in e[2]['swarm'].items():
        assert s['expiry'] == exp_20s
        assert s['updated'] == sorted(m["hash"] for m in msgs[4:8])
        assert s['unchanged'] == {}
        # signature of ( PUBKEY_HEX || EXPIRY || RMSGs... || UMSGs... || CMSG_EXPs... )
        expected_signed = "".join(
            [my_ss_id, str(exp_20s)] + [m["hash"] for m in msgs[4:8]] + do_not_exist + s['updated']
        ).encode()
        edpk = VerifyKey(snpk, encoder=HexEncoder)
        edpk.verify(expected_signed, base64.b64decode(s['signature']))

    assert e[3] == {
        "expiries": {
            **{m["hash"]: exp_30s for m in msgs[0:4]},
            **{m["hash"]: exp_20s for m in msgs[4:8]},
            **{msgs[i]["hash"]: now + (60 - i) * 1000 for i in range(8, 10)},
        }
    }

    assert 5 <= len(e[4]['swarm']) <= 10
    for snpk, s in e[4]['swarm'].items():
        assert s['expiry'] == exp_10m
        assert s['updated'] == []
        assert s['unchanged'] == {
            **{m["hash"]: exp_20s for m in msgs[6:8]},
            **{msgs[i]["hash"]: now + (60 - i) * 1000 for i in range(8, 10)},
        }
        # signature of ( PUBKEY_HEX || EXPIRY || RMSGs... || UMSGs... || CMSG_EXPs... )
        expected_signed = "".join(
            [my_ss_id, str(exp_10m)]
            + [m["hash"] for m in msgs[6:]]
            + sorted(
                [
                    f"{msgs[6]['hash']}{exp_20s}",
                    f"{msgs[7]['hash']}{exp_20s}",
                    f"{msgs[8]['hash']}{now + 52_000}",
                    f"{msgs[9]['hash']}{now + 51_000}",
                ]
            )
        ).encode()
        edpk = VerifyKey(snpk, encoder=HexEncoder)
        edpk.verify(expected_signed, base64.b64decode(s['signature']))

    assert e[5] == {
        "expiries": {
            **{m["hash"]: exp_30s for m in msgs[0:4]},
            **{m["hash"]: exp_20s for m in msgs[4:8]},
            **{msgs[i]["hash"]: now + (60 - i) * 1000 for i in range(8, 10)},
        }
    }

    assert 5 <= len(e[6]['swarm']) <= 10
    for snpk, s in e[6]['swarm'].items():
        assert s['expiry'] == exp_20s
        assert s['updated'] == sorted(m["hash"] for m in msgs[2:4])
        assert s['unchanged'] == {m["hash"]: exp_20s for m in msgs[4:6]}
        # signature of ( PUBKEY_HEX || EXPIRY || RMSGs... || UMSGs... || CMSG_EXPs... )
        expected_signed = "".join(
            [my_ss_id, str(exp_20s)]
            + [m["hash"] for m in msgs[2:6]]
            + do_not_exist
            + sorted(m["hash"] for m in msgs[2:4])
            + sorted([f"{msgs[4]['hash']}{exp_20s}", f"{msgs[5]['hash']}{exp_20s}"])
        ).encode()
        edpk = VerifyKey(snpk, encoder=HexEncoder)
        edpk.verify(expected_signed, base64.b64decode(s['signature']))

    assert e[7] == {
        "expiries": {
            **{m["hash"]: exp_30s for m in msgs[0:2]},
            **{m["hash"]: exp_20s for m in msgs[2:8]},
            **{msgs[i]["hash"]: now + (60 - i) * 1000 for i in range(8, 10)},
        }
    }

    assert 5 <= len(e[8]['swarm']) <= 10
    for snpk, s in e[8]['swarm'].items():
        assert s['expiry'] == exp_45s
        assert s['updated'] == sorted(m["hash"] for m in msgs[0:8])
        assert s['unchanged'] == {msgs[i]["hash"]: now + (60 - i) * 1000 for i in range(8, 10)}
        # signature of ( PUBKEY_HEX || EXPIRY || RMSGs... || UMSGs... || CMSG_EXPs... )
        expected_signed = "".join(
            [my_ss_id, str(exp_45s)]
            + [m["hash"] for m in msgs]
            + do_not_exist
            + s['updated']
            + sorted([f"{msgs[8]['hash']}{now + 52_000}", f"{msgs[9]['hash']}{now + 51_000}"])
        ).encode()
        edpk = VerifyKey(snpk, encoder=HexEncoder)
        edpk.verify(expected_signed, base64.b64decode(s['signature']))

    assert e[9]['hf'] >= [19, 3]
    assert now - 60_000 <= e[9]['t'] <= now + 60_000
    del e[9]['hf']
    del e[9]['t']
    expected_expiries = [exp_45s] * 8 + [now + 52_000, now + 51_000]
    assert e[9] == {
        "messages": [
            {
                'data': base64.b64encode(msgs[i]['data']).decode(),
                'expiration': expected_expiries[i],
                'hash': msgs[i]['hash'],
                'timestamp': msgs[i]['req']['timestamp'],
            }
            for i in range(len(msgs))
        ],
        "more": False,
    }

    # Test bug: get_expiries was not working properly when given just one hash.  (msgs[0] was
    # shortened to 30s in the first step, then extended to 45s along with everything else in the
    # extend-only step above.)
    assert e[10] == {"expiries": {msgs[0]["hash"]: exp_45s}}


def test_expire_multi(rpc, random_sn, sk, exclude):
    swarm = ss.get_swarm(rpc, random_sn, sk)
    sns = ss.random_swarm_members(swarm, 2, exclude)
    conns = [rpc.connect(sn) for sn in sns]

    msgs = ss.store_n(rpc, conns[0], sk, b"omg123", 10)

    my_ss_id = '05' + sk.verify_key.encode().hex()

    target_indices = [0, 1, 3, 6, 7, 9]
    ts_delta = [random_time_delta_ms(5) if i in target_indices else 0 for i in range(10)]
    ts = [msgs[i]['req']['expiry'] + ts_delta[i] for i in target_indices] + [
        int(time.time() * 1000) + 12345
    ]

    hashes = [msgs[i]['hash'] for i in target_indices] + [
        'bepQtTaYrzcuCXO3fZkmk/h3xkMQ3vCh94i5HzLmj3I'
    ]

    assert len(hashes) == len(target_indices) + 1
    assert len(ts) == len(target_indices) + 1

    # Make sure `hashes` input isn't provided in sorted order:
    if hashes[0] < hashes[1]:
        hashes[0], hashes[1] = hashes[1], hashes[0]
        ts[0], ts[1] = ts[1], ts[0]
    h_ts = [[hashes[i], ts[i]] for i in range(len(hashes) - 1)]
    h_ts.sort(key=lambda x: x[0])
    actual_update_msgs = [x[0] for x in h_ts]
    actual_update_exps = [x[1] for x in h_ts]

    assert hashes[0:2] != actual_update_msgs[0:2]

    to_sign = ("expire" + "".join(str(t) for t in ts) + "".join(hashes)).encode()
    sig = sk.sign(to_sign, encoder=Base64Encoder).signature.decode()
    params = json.dumps(
        {"pubkey": my_ss_id, "messages": hashes, "expiry": ts, "signature": sig}
    ).encode()

    resp = rpc.request(conns[1], 'expire', [params]).get()

    assert len(resp) == 1
    r = json.loads(resp[0])

    assert set(r['swarm'].keys()) == {x['pubkey_ed25519'] for x in swarm['snodes']}

    # ( PUBKEY_HEX || EXPIRY[0] || ... || EXPIRY[M] || RMSG[0] || ... || RMSG[N] || UMSG[0] || ... || UMSG[M] )
    expected_signed = "".join(
        (my_ss_id, "".join(str(t) for t in actual_update_exps), *hashes, *actual_update_msgs)
    ).encode()
    for k, v in r['swarm'].items():
        assert {kk: vv for kk, vv in v.items() if kk != 'signature'} == {
            'updated': actual_update_msgs,
            'expiry': actual_update_exps,
        }
        edpk = VerifyKey(k, encoder=HexEncoder)
        try:
            edpk.verify(expected_signed, base64.b64decode(v['signature']))
        except nacl.exceptions.BadSignatureError as e:
            print("Bad signature from swarm member {}".format(k))
            raise e

    now = int(time.time() * 1000)
    r = rpc.request(
        conns[0],
        'retrieve',
        [
            json.dumps(
                {
                    "pubkey": my_ss_id,
                    "timestamp": now,
                    "signature": sk.sign(
                        f"retrieve{now}".encode(), encoder=Base64Encoder
                    ).signature.decode(),
                }
            ).encode()
        ],
    ).get()
    expected_msgs = [
        {
            'data': base64.b64encode(msgs[i]['data']).decode(),
            'hash': msgs[i]['hash'],
            'timestamp': msgs[i]['req']['timestamp'],
            'expiration': msgs[i]['req']['expiry'] + ts_delta[i],
        }
        for i in range(10)
    ]

    assert len(r) == 1
    r = json.loads(r[0])
    assert r['messages'] == expected_msgs


def test_expire_max_refresh(rpc, random_sn, sk, exclude):
    """Repeated extensions to the maximum expiry, as clients make on every poll.  A 2.12 node
    holds these in memory rather than writing each one; from outside that must be invisible: every
    node applies the refresh, and a node's get_expiries and retrieve return exactly the expiry it
    signed.  A shorten after a refresh takes effect, and a delete followed by a re-store of the
    same hash does not bring the refreshed expiry back."""
    swarm = ss.get_swarm(rpc, random_sn, sk)
    sns = ss.random_swarm_members(swarm, 2, exclude)
    conns = [rpc.connect(sn) for sn in sns]
    node1 = sns[1]['pubkey_ed25519']

    my_ss_id = '05' + sk.verify_key.encode().hex()
    day = 24 * 60 * 60

    # The default namespace allows 14 days on a store; an expire may then take it to 30.
    msgs = ss.store_n(rpc, conns[0], sk, b"omg123", 3, ttl=14 * day - 60)
    hashes = [m['hash'] for m in msgs]
    hashes_str = ''.join(hashes)

    def extend(conn, exp):
        params = {
            "pubkey": my_ss_id,
            "messages": hashes,
            "expiry": exp,
            "extend": True,
            "signature": sk.sign(
                f"expireextend{exp}{hashes_str}".encode(), encoder=Base64Encoder
            ).signature.decode(),
        }
        r = rpc.request(conn, 'expire', [json.dumps(params).encode()]).get()
        assert len(r) == 1
        r = json.loads(r[0])
        assert set(r['swarm'].keys()) == {x['pubkey_ed25519'] for x in swarm['snodes']}
        return r['swarm']

    def shorten(conn, exp):
        params = {
            "pubkey": my_ss_id,
            "messages": hashes,
            "expiry": exp,
            "shorten": True,
            "signature": sk.sign(
                f"expireshorten{exp}{hashes_str}".encode(), encoder=Base64Encoder
            ).signature.decode(),
        }
        r = rpc.request(conn, 'expire', [json.dumps(params).encode()]).get()
        assert len(r) == 1
        return json.loads(r[0])['swarm']

    def expiries(conn):
        now = int(time.time() * 1000)
        params = {
            "pubkey": my_ss_id,
            "messages": hashes,
            "timestamp": now,
            "signature": sk.sign(
                f"get_expiries{now}{hashes_str}".encode(), encoder=Base64Encoder
            ).signature.decode(),
        }
        r = rpc.request(conn, 'get_expiries', [json.dumps(params).encode()]).get()
        assert len(r) == 1
        return json.loads(r[0])['expiries']

    def retrieved_expiries(conn):
        now = int(time.time() * 1000)
        params = {
            "pubkey": my_ss_id,
            "timestamp": now,
            "signature": sk.sign(
                f"retrieve{now}".encode(), encoder=Base64Encoder
            ).signature.decode(),
        }
        r = rpc.request(conn, 'retrieve', [json.dumps(params).encode()]).get()
        assert len(r) == 1
        return {m['hash']: m['expiration'] for m in json.loads(r[0])['messages']}

    def check_applied(res, near):
        """Every node applied the extension to all three, at its own clamp of the maximum."""
        for v in res.values():
            assert v['updated'] == sorted(hashes)
            assert v['unchanged'] == {}
            assert abs(v['expiry'] - near) <= 5000

    # A big extension, from 14 days to the maximum: written straight away.
    now = int(time.time() * 1000)
    first = extend(conns[0], now + 31 * day * 1000)
    check_applied(first, now + 30 * day * 1000)

    # Now the refreshes: a client re-extending to the maximum a little later each time.
    time.sleep(2)
    now = int(time.time() * 1000)
    second = extend(conns[0], now + 31 * day * 1000)
    check_applied(second, now + 30 * day * 1000)
    for k in second:
        assert second[k]['expiry'] > first[k]['expiry']

    # What a node reports is exactly what it signed, whether or not it has written it yet.
    assert expiries(conns[1]) == {h: second[node1]['expiry'] for h in hashes}
    assert retrieved_expiries(conns[1]) == {h: second[node1]['expiry'] for h in hashes}

    time.sleep(2)
    now = int(time.time() * 1000)
    third = extend(conns[1], now + 31 * day * 1000)
    check_applied(third, now + 30 * day * 1000)
    for k in third:
        assert third[k]['expiry'] > second[k]['expiry']
    assert expiries(conns[1]) == {h: third[node1]['expiry'] for h in hashes}

    # An extension to less than the current expiry does nothing
    res = extend(conns[0], now + 29 * day * 1000)
    for k, v in res.items():
        assert v['updated'] == []
        assert v['unchanged'] == {h: third[k]['expiry'] for h in hashes}
    assert expiries(conns[1]) == {h: third[node1]['expiry'] for h in hashes}

    # Shortening to below a refreshed value takes effect exactly
    shorter = now + 30 * day * 1000 - 10 * 60 * 1000
    res = shorten(conns[0], shorter)
    for v in res.values():
        assert v['updated'] == sorted(hashes)
        assert v['expiry'] == shorter
    assert expiries(conns[1]) == {h: shorter for h in hashes}
    assert retrieved_expiries(conns[1]) == {h: shorter for h in hashes}

    # and can be refreshed again afterwards
    now = int(time.time() * 1000)
    fourth = extend(conns[1], now + 31 * day * 1000)
    check_applied(fourth, now + 30 * day * 1000)
    assert expiries(conns[1]) == {h: fourth[node1]['expiry'] for h in hashes}

    # Delete, then store the same message again (same data, so the same hash): its expiry is the
    # fresh store's, not the deleted message's refreshed one.
    del_hashes = sorted(hashes)
    params = {
        "pubkey": my_ss_id,
        "messages": del_hashes,
        "signature": sk.sign(
            ("delete" + ''.join(del_hashes)).encode(), encoder=Base64Encoder
        ).signature.decode(),
    }
    r = rpc.request(conns[1], 'delete', [json.dumps(params).encode()]).get()
    assert len(r) == 1
    for v in json.loads(r[0])['swarm'].values():
        assert v['deleted'] == del_hashes
    assert expiries(conns[1]) == {}

    again = ss.store_n(rpc, conns[1], sk, b"omg123", 1)
    assert again[0]['hash'] == msgs[0]['hash']
    assert expiries(conns[1]) == {msgs[0]['hash']: again[0]['req']['expiry']}
    assert retrieved_expiries(conns[1]) == {msgs[0]['hash']: again[0]['req']['expiry']}
