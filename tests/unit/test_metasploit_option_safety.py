from types import SimpleNamespace

import pytest

from services.orchestration.exploit_executor import ExploitExecutor


def _exploit(options):
    return SimpleNamespace(
        id=1,
        module_name="multi/test/module",
        metadata_json={"module_type": "exploit", "options": options},
    )


def _twin(endpoint="172.18.0.5:3000", ip_address="172.18.0.5"):
    return SimpleNamespace(id=10, endpoint=endpoint, ip_address=ip_address, health="healthy")


def test_rejects_newline_in_option_value():
    target = ExploitExecutor._resolve_authorized_target(_twin())

    with pytest.raises(ValueError, match="control characters"):
        ExploitExecutor._build_options(
            _exploit({"HttpHeader": "ok\nrun post/windows/manage"}),
            _twin(),
            target,
            module_options={"HttpHeader"},
        )


def test_rejects_invalid_option_name():
    target = ExploitExecutor._resolve_authorized_target(_twin())

    with pytest.raises(ValueError, match="Invalid Metasploit option name"):
        ExploitExecutor._build_options(
            _exploit({"RPORT;run": 3000}),
            _twin(),
            target,
            module_options={"RPORT"},
        )


def test_rejects_option_not_supported_by_module():
    target = ExploitExecutor._resolve_authorized_target(_twin())

    with pytest.raises(ValueError, match="not supported"):
        ExploitExecutor._build_options(
            _exploit({"SSL": True}),
            _twin(),
            target,
            module_options={"RPORT"},
        )


def test_target_override_never_supersedes_twin():
    twin = _twin(endpoint="http://192.168.56.1:3000/")
    target = ExploitExecutor._resolve_authorized_target(twin)

    options = ExploitExecutor._build_options(
        _exploit({"RHOSTS": "8.8.8.8", "RHOST": "8.8.4.4", "RPORT": 9999}),
        twin,
        target,
        module_options={"RHOSTS", "RHOST", "RPORT"},
    )

    assert options["RHOSTS"] == "192.168.56.1"
    assert options["RHOST"] == "192.168.56.1"
    assert options["RPORT"] == 3000


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://192.168.56.1:3000/path",
        "http://user:pass@192.168.56.1:3000/",
        "192.168.56.1:notaport",
        "192.168.56.1:99999",
        "192.168.56.1\nset RHOSTS 8.8.8.8",
    ],
)
def test_rejects_malformed_endpoints(endpoint):
    with pytest.raises(ValueError):
        ExploitExecutor._resolve_authorized_target(_twin(endpoint=endpoint))


def test_valid_endpoint_extracts_host_and_port():
    target = ExploitExecutor._resolve_authorized_target(_twin(endpoint="http://192.168.56.1:3000/"))

    assert target.host == "192.168.56.1"
    assert target.port == 3000
