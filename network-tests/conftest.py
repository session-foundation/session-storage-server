import pytest
import random

import transport


def pytest_addoption(parser):
    parser.addoption("--exclude", action="store", default="")
    parser.addoption(
        "--transport",
        action="store",
        default="https",
        choices=sorted(transport.TRANSPORTS),
        help="how to send storage RPC requests to the storage servers under test",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "omq: the test itself uses oxenmq features (skipped under other transports)"
    )
    config.addinivalue_line(
        "markers", "bt: the test sends bt-encoded requests (skipped on json-only transports)"
    )


def pytest_collection_modifyitems(config, items):
    t = transport.TRANSPORTS[config.getoption("transport")]
    for item in items:
        if "omq" in item.keywords and t is not transport.OMQ:
            item.add_marker(pytest.mark.skip(reason="requires --transport=omq"))
        if "bt" in item.keywords and not t.bt:
            item.add_marker(pytest.mark.skip(reason=f"{t.name} transport carries json only"))


@pytest.fixture(scope="module")
def rpc(pytestconfig):
    return transport.TRANSPORTS[pytestconfig.getoption("transport")]()


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
def random_sn(rpc, sns):
    return rpc.connect(random.choice(sns))


@pytest.fixture
def sk():
    from nacl.signing import SigningKey

    return SigningKey.generate()


@pytest.fixture(scope="module")
def exclude(pytestconfig):
    s = pytestconfig.getoption("exclude")
    return {s} if s and len(s) else {}
