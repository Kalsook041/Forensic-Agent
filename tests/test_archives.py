import gzip
import io
from pathlib import Path
import tarfile
import zipfile

import pytest

from forensic_agent.evidence import Case, sha256_file
from forensic_agent.evidence.paths import safe_member
from forensic_agent.models import ToolRequest
from forensic_agent.tools.runner import run_tool


@pytest.mark.parametrize("name", ["../outside", "/absolute", "C:/file", "a:stream", "a/../../bad",
                                  "CON.txt", "a/NUL", "a/COM1", "a.", "a ", "a//b", "a\\..\\b"])
def test_unsafe_member_names(name):
    with pytest.raises(ValueError):
        safe_member(name)


def test_zip_safe_extract_and_lineage(tmp_path, settings):
    path = tmp_path / "检材.zip"
    with zipfile.ZipFile(path, "w") as package:
        package.writestr("中文目录/flag.txt", "FLAG-ZIP")
    before = sha256_file(path)
    case = Case.create(path, settings)
    step = run_tool(case, ToolRequest(tool_id="archive", source_id="s00001", params={"action": "extract"}))
    assert step["result"]["status"] == "ok", step["result"]
    derived = case.sources[step["derived_source_ids"][0]]
    assert derived.parent_id == "s00001"
    assert derived.member == "中文目录/flag.txt"
    assert Path(derived.working_path).read_text(encoding="utf-8") == "FLAG-ZIP"
    assert sha256_file(path) == before
    search = run_tool(case, ToolRequest(tool_id="search", source_id=derived.id, params={"keyword": "FLAG"}))
    assert search["evidence"][0]["source_id"] == derived.id


@pytest.mark.parametrize("members", [[("../outside.txt", b"bad")], [("A.txt", b"a"), ("a.txt", b"b")],
                                    [("parent", b"x"), ("parent/child", b"y")]])
def test_zip_traversal_collisions_blocked(tmp_path, settings, members):
    path = tmp_path / "恶意.zip"
    with zipfile.ZipFile(path, "w") as package:
        for name, data in members:
            package.writestr(name, data)
    before = sha256_file(path)
    case = Case.create(path, settings)
    step = run_tool(case, ToolRequest(tool_id="archive", source_id="s00001", params={"action": "extract"}))
    assert step["result"]["status"] == "blocked"
    assert not step.get("derived_source_ids")
    assert not (case.directory / "steps/step0001/extracted").exists()
    assert sha256_file(path) == before


def test_bomb_rejected_before_write(tmp_path, settings):
    path = tmp_path / "bomb.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as package:
        package.writestr("big", b"0" * 1024**2)
    case = Case.create(path, settings)
    step = run_tool(case, ToolRequest(tool_id="archive", source_id="s00001", params={"action": "extract"}))
    assert step["result"]["status"] == "blocked"
    assert any("压缩比" in warning for warning in step["result"]["warnings"])


def test_tar_and_gzip(tmp_path, settings):
    path = tmp_path / "sample.tar"
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as package:
        info = tarfile.TarInfo("flag.txt")
        info.size = 8
        package.addfile(info, io.BytesIO(b"FLAG-TAR"))
    case = Case.create(path, settings)
    tar_step = run_tool(case, ToolRequest(tool_id="archive", source_id="s00001", params={"action": "extract"}))
    assert tar_step["result"]["status"] == "ok", tar_step["result"]
    gz = tmp_path / "sample.txt.gz"
    gz.write_bytes(gzip.compress(b"FLAG-GZIP"))
    case = Case.create(gz, settings)
    gz_step = run_tool(case, ToolRequest(tool_id="archive", source_id="s00001", params={"action": "extract"}))
    assert gz_step["result"]["status"] == "ok", gz_step["result"]


def test_tar_link_refused(tmp_path, settings):
    path = tmp_path / "link.tar"
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as package:
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "../../original"
        package.addfile(info)
    case = Case.create(path, settings)
    step = run_tool(case, ToolRequest(tool_id="archive", source_id="s00001", params={"action": "extract"}))
    assert step["result"]["status"] == "blocked"
