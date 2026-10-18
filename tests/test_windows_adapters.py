import csv
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from forensic_agent.models import Source, ToolRequest
from forensic_agent.tools.context import Context
from forensic_agent.tools.params import ArtifactRowsParams, AutopsyParams, EmptyParams
from forensic_agent.tools.registry import validate_request
from forensic_agent.tools import desktop, windows_artifacts


def context(settings, tmp_path, content=b'FILE' + b'\x00'*64, name='input'):
    path = tmp_path / name
    path.write_bytes(content)
    step = tmp_path / 'step'
    step.mkdir()
    return Context(settings, [Source(id='s00001', original_path=str(path), working_path=str(path), kind='file')], step)


@pytest.mark.parametrize('tool', ['pecmd', 'mftecmd', 'recmd', 'sqlecmd', 'autopsy', 'veracrypt'])
def test_injection_rejected(tool):
    with pytest.raises(ValueError):
        validate_request(ToolRequest(tool_id=tool, source_id='s00001', params={'arguments': ['--sync']}))


def test_mft_fixed_args_literal_filter_and_partial(settings, tmp_path, monkeypatch):
    ctx = context(settings, tmp_path)
    seen = []
    def external(self, key, args, **kwargs):
        seen.append((key, args))
        with (kwargs['artifact_root'] / 'records.csv').open('w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerows([['Name','Size'],['--sync & X','1'],['--sync & X','2']])
        return b'OK', b''
    monkeypatch.setattr(Context, 'external', external)
    result = windows_artifacts.mft(ctx, ArtifactRowsParams(keyword='--sync & X', limit=1))
    assert result.status == 'partial' and result.truncated
    assert result.records[0].data == {'Name':'--sync & X', 'Size':'1'}
    assert seen[0][1] == ['-f', ctx.files()[0].working_path, '--csv', str(ctx.step_dir/'export'), '--csvf', 'records.csv']


def test_reject_format_and_dirty_hive_before_execution(settings, tmp_path):
    ctx = context(settings, tmp_path, b'not a hive')
    assert windows_artifacts.registry(ctx, ArtifactRowsParams()).status == 'unsupported'
    Path(ctx.files()[0].working_path).write_bytes(b'regf\x01\x00\x00\x00\x02\x00\x00\x00'+b'\x00'*24)
    assert windows_artifacts.registry(ctx, ArtifactRowsParams()).status == 'blocked'


def test_missing_export_is_not_zero_success(settings, tmp_path, monkeypatch):
    ctx = context(settings, tmp_path)
    monkeypatch.setattr(Context, 'external', lambda *a, **k: (b'failed to parse', b''))
    assert windows_artifacts.mft(ctx, ArtifactRowsParams()).status == 'unsupported'


def test_legacy_context_without_input_root(settings, tmp_path):
    ctx = context(settings, tmp_path, b'not supported')
    legacy = SimpleNamespace(files=ctx.files)
    assert windows_artifacts.mft(legacy, ArtifactRowsParams()).status == 'unsupported'


def test_recmd_fixed_batch_is_snapshotted(settings, tmp_path, monkeypatch):
    ctx = context(settings, tmp_path, b'regf' + b'\0'*60)
    home = tmp_path/'tool'
    (home/'BatchExamples').mkdir(parents=True)
    batch = home/'BatchExamples/BasicSystemInfo.reb'
    batch.write_text('fixed test batch', encoding='utf-8')
    settings.tools.recmd = str(home/'RECmd.exe')
    def external(self, key, args, **kwargs):
        assert key == 'recmd' and '--sync' not in args and '--nl' not in args
        snapshot = Path(args[args.index('--bn') + 1])
        assert snapshot != batch and snapshot.read_bytes() == batch.read_bytes()
        (kwargs['artifact_root']/'records.csv').write_text('ValueName,ValueData\nComputerName,TEST-PC\n', encoding='utf-8')
        return b'OK', b''
    monkeypatch.setattr(Context, 'external', external)
    result = windows_artifacts.registry(ctx, ArtifactRowsParams())
    assert result.records[0].data['ValueData'] == 'TEST-PC'
    assert (ctx.step_dir/'export/support-files.json').is_file()


def test_autopsy_read_only_typed_rows_and_partial(settings, tmp_path):
    ctx = context(settings, tmp_path, b'')
    path = Path(ctx.files()[0].working_path)
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE tsk_files(obj_id INTEGER,name TEXT,parent_path TEXT,size INTEGER,mtime INTEGER,ctime INTEGER,atime INTEGER,crtime INTEGER)')
        db.executemany('INSERT INTO tsk_files VALUES(?,?,?,?,?,?,?,?)', [(1,'目标','/',8,1,2,3,4),(2,'目标2','/',9,1,2,3,4)])
    before = path.read_bytes()
    result = desktop.autopsy(ctx, AutopsyParams(limit=1, keyword='目标'))
    assert result.status == 'partial' and result.records[0].data['size'] == 8
    assert path.read_bytes() == before
    assert desktop.autopsy(ctx, AutopsyParams(keyword="' OR 1=1 --")).records == []
    settings.limits.max_files = 1
    limited = desktop.autopsy(ctx, AutopsyParams(keyword='absent'))
    assert limited.status == 'partial' and limited.records == []


def test_autopsy_reject_views_and_wal(settings, tmp_path):
    ctx = context(settings, tmp_path, b'')
    path = Path(ctx.files()[0].working_path)
    with sqlite3.connect(path) as db:
        db.execute('CREATE VIEW tsk_files AS SELECT 1')
    with pytest.raises(ValueError, match='不执行视图'):
        desktop.autopsy(ctx, AutopsyParams())
    content = bytearray(path.read_bytes())
    content[18:20] = b'\x02\x02'
    path.write_bytes(content)
    assert desktop.autopsy(ctx, AutopsyParams()).status == 'blocked'


def test_veracrypt_does_not_execute_or_support_answers(settings, tmp_path):
    ctx = context(settings, tmp_path)
    settings.tools.veracrypt = ctx.files()[0].working_path
    result = desktop.veracrypt(ctx, EmptyParams())
    assert result.status == 'blocked' and ctx.command_number == 0
    assert result.records[0].grounding == 'exploratory'
    assert '只读' in result.records[0].data['steps'][1] or 'read-only' in result.records[0].data['steps'][1]


def test_gui_manual_uses_configured_desktop_paths(settings):
    from forensic_agent.manual import build_manual_guidance
    settings.tools.autopsy = 'E:/Forensics/Autopsy/4.23.1/bin/autopsy64.exe'
    settings.tools.veracrypt = 'D:/VeraCrypt/VeraCrypt.exe'
    assert build_manual_guidance(settings=settings)['workflows']
