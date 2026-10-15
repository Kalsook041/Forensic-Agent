import io
from pathlib import Path
import tarfile

import pytest

from forensic_agent.evidence import Case, sha256_file
from forensic_agent.models import ToolRequest
from forensic_agent.tools.runner import run_tool


def make_tar(path, members):
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as package:
        for name, data in members:
            info = tarfile.TarInfo(name)
            if data is None:
                info.type = tarfile.DIRTYPE
                package.addfile(info)
            else:
                info.size = len(data)
                package.addfile(info, io.BytesIO(data))


@pytest.mark.parametrize("action", ["list", "extract"])
def test_tar_standard_dot_root_and_leading_prefix(tmp_path, settings, action):
    path = tmp_path / "dot.tar"
    make_tar(path, [(".", None), ("./中文目录", None), ("./中文目录/flag.txt", b"FLAG-TAR")])
    before = sha256_file(path)
    case = Case.create(path, settings)
    step = run_tool(case, ToolRequest(tool_id="archive", source_id="s00001", params={"action": action}))
    assert step["result"]["status"] == "ok", step["result"]
    assert all(record["data"]["safe_path"] for record in step["result"]["records"])
    if action == "extract":
        derived = case.sources[step["derived_source_ids"][0]]
        assert derived.member == "./中文目录/flag.txt"
        assert Path(derived.working_path).read_bytes() == b"FLAG-TAR"
    assert sha256_file(path) == before


@pytest.mark.parametrize("members", [
    [(".", None), ("./../escape", b"bad")],
    [("./a/../escape", b"bad")],
    [("./flag", b"one"), ("flag", b"two")],
    [("./A", b"one"), ("a", b"two")],
    [("./parent/child", b"one"), ("parent", b"two")],
    [(".", b"bad")],
    [("./", b"bad")],
    [("./CON.txt", b"bad")],
    [("./a:stream", b"bad")],
    [(".//absolute", b"bad")],
])
def test_tar_dot_normalization_preserves_rejections(tmp_path, settings, members):
    path = tmp_path / "unsafe.tar"
    make_tar(path, members)
    case = Case.create(path, settings)
    step = run_tool(case, ToolRequest(tool_id="archive", source_id="s00001", params={"action": "extract"}))
    assert step["result"]["status"] == "blocked", step["result"]
    assert not step.get("derived_source_ids")
    assert not (case.directory / "steps/step0001/extracted").exists()


@pytest.mark.parametrize("name", [".", "./", "./../escape", "./CON.txt"])
def test_tar_invalid_file_listing_stays_unsafe(tmp_path, settings, name):
    path = tmp_path / "unsafe-list.tar"
    make_tar(path, [(name, b"bad")])
    case = Case.create(path, settings)
    step = run_tool(case, ToolRequest(tool_id="archive", source_id="s00001", params={"action": "list"}))
    assert step["result"]["records"][0]["data"]["safe_path"] is False
