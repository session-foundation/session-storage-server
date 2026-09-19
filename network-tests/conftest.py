import pytest
import random

import ss
import transport


def pytest_addoption(parser):
    parser.addoption(
        "--exclude",
        action="store",
        default="",
        metavar="PUBKEY",
        help="ed25519 pubkey of a node the tests should never pick as a swarm member",
    )
    parser.addoption(
        "--transport",
        action="store",
        default="https",
        choices=sorted(transport.TRANSPORTS),
        help="how to send storage RPC requests to the storage servers under test",
    )
    parser.addoption(
        "--node",
        action="store",
        default="",
        metavar="PUBKEY|IP:PORT",
        help="steer the tests at one node (ed25519 pubkey, or ip:port of either listener): it "
        "becomes the entry point, test accounts are generated inside its swarm, and it is "
        "preferred whenever a swarm member is picked -- so its logs show most of the run",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "monitor: the test subscribes to message notifications (skipped on transports without them)",
    )
    config.addinivalue_line(
        "markers", "bt: the test sends bt-encoded requests (skipped on json-only transports)"
    )


def pytest_collection_modifyitems(config, items):
    t = transport.TRANSPORTS[config.getoption("transport")]
    for item in items:
        if "monitor" in item.keywords and not t.monitor:
            item.add_marker(pytest.mark.skip(reason=f"{t.name} transport has no message monitoring"))
        if "bt" in item.keywords and not t.bt:
            item.add_marker(pytest.mark.skip(reason=f"{t.name} transport carries json only"))


@pytest.fixture(scope="module")
def rpc(pytestconfig):
    t = transport.TRANSPORTS[pytestconfig.getoption("transport")]()
    yield t
    t.close()


@pytest.fixture(scope="module")
def sns(rpc):
    fields = {
        f: True
        for f in (
            'public_ip',
            'storage_port',
            'storage_lmq_port',
            'pubkey_ed25519',
            'pubkey_x25519',
            'service_node_pubkey',
        )
    }
    r = rpc.oxend("get_service_nodes", {"active_only": True, "fields": fields})
    return [transport.normalize_oxend_snode(sn) for sn in r['service_node_states']]


@pytest.fixture(scope="module")
def pinned_node(pytestconfig, sns):
    want = pytestconfig.getoption("node")
    if not want:
        return None
    for sn in sns:
        if want in (sn['pubkey_ed25519'], f"{sn['ip']}:{sn['port_https']}", f"{sn['ip']}:{sn['port_omq']}"):
            return sn
    pytest.exit(f"--node={want} does not match any active service node")


@pytest.fixture(scope="module", autouse=True)
def _prefer_pinned_node(pinned_node):
    ss.preferred_node = pinned_node['pubkey_ed25519'] if pinned_node else None


@pytest.fixture(scope="module")
def random_sn(rpc, sns, pinned_node):
    return rpc.connect(pinned_node or random.choice(sns))


@pytest.fixture
def sk(rpc, random_sn, pinned_node):
    from nacl.signing import SigningKey

    # With a pinned node, keep generating until the account lands in its swarm (testnet has a
    # handful of swarms, so this takes a few tries at most).
    while True:
        sk = SigningKey.generate()
        if not pinned_node:
            return sk
        members = ss.get_swarm(rpc, random_sn, sk)['snodes']
        if any(m['pubkey_ed25519'] == pinned_node['pubkey_ed25519'] for m in members):
            return sk


@pytest.fixture(scope="module")
def exclude(pytestconfig):
    s = pytestconfig.getoption("exclude")
    return {s} if s and len(s) else {}
