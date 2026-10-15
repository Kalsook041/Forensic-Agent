from pathlib import Path
import tomllib

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class ModelSettings(StrictModel):
    base_url: str = "http://127.0.0.1:11434"
    name: str = "qwen3:4b"
    num_ctx: int = Field(default=4096, ge=1024, le=16384)
    num_predict: int = Field(default=1536, ge=128, le=4096)
    timeout_seconds: int = Field(default=120, ge=1, le=600)
    max_steps: int = Field(default=8, ge=1, le=20)

    @field_validator("base_url")
    @classmethod
    def loopback_only(cls, value):
        if value != "http://127.0.0.1:11434":
            raise ValueError("只允许 http://127.0.0.1:11434")
        return value

    @field_validator("name")
    @classmethod
    def local_model(cls, value):
        if not value or any(x in value.lower() for x in ("cloud", "://", "@")):
            raise ValueError("只允许已安装的本地模型标签")
        return value


class ToolPaths(StrictModel):
    tshark: str = ""
    capinfos: str = ""
    exiftool: str = ""
    seven_zip: str = ""
    ollama: str = ""
    evtxecmd: str = ""
    pecmd: str = ""
    mftecmd: str = ""
    recmd: str = ""
    sqlecmd: str = ""

    @field_validator("*")
    @classmethod
    def absolute_or_empty(cls, value):
        if value and not Path(value).is_absolute():
            raise ValueError("工具必须配置绝对路径")
        return value


class Limits(StrictModel):
    timeout_seconds: float = Field(default=60, gt=0, le=3600)
    pcap_timeout_seconds: float = Field(default=180, gt=0, le=3600)
    memory_bytes: int = Field(default=2 * 1024**3, ge=64 * 1024**2)
    cpu_percent: int = Field(default=50, ge=1, le=100)
    output_bytes: int = Field(default=16 * 1024**2, ge=1024)
    max_files: int = Field(default=10000, ge=1)
    snapshot_bytes: int = Field(default=10 * 1024**3, ge=1)
    text_file_bytes: int = Field(default=64 * 1024**2, ge=1)
    archive_member_bytes: int = Field(default=512 * 1024**2, ge=1)
    archive_total_bytes: int = Field(default=2 * 1024**3, ge=1)
    archive_members: int = Field(default=10000, ge=1)
    archive_ratio: int = Field(default=200, ge=1)
    reserve_disk_bytes: int = Field(default=1024**3, ge=0)


class Settings(StrictModel):
    work_dir: Path = Path("E:/ForensicWork")
    knowledge_dir: Path = Field(default_factory=lambda: Path.cwd() / "knowledge")
    model: ModelSettings = Field(default_factory=ModelSettings)
    tools: ToolPaths = Field(default_factory=ToolPaths)
    limits: Limits = Field(default_factory=Limits)

    @field_validator("work_dir")
    @classmethod
    def absolute_workdir(cls, value):
        if not value.is_absolute():
            raise ValueError("工作目录必须为绝对路径")
        return value


def load_settings(path: Path | None = None) -> Settings:
    path = path or Path("config/default.toml")
    if not path.is_file():
        if path != Path("config/default.toml"):
            raise FileNotFoundError(path)
        return Settings()
    with path.open("rb") as stream:
        settings = Settings.model_validate(tomllib.load(stream))
    settings.knowledge_dir = path.resolve().parent.parent / "knowledge"
    return settings
