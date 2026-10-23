from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import stat
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any

from . import __version__

BACKUP_FORMAT = 1
DB_NAME = "vulnscan.db"
SKIP_SUFFIXES = ("-wal", "-shm")


class BackupError(RuntimeError):
    pass


def create_backup(
    data_dir: Path,
    out: Path,
    *,
    overwrite: bool = False,
) -> dict[str, Any]:
    data_dir = data_dir.expanduser().resolve()
    out = out.expanduser().resolve()
    db_path = data_dir / DB_NAME
    if not db_path.is_file():
        raise BackupError(f"找不到資料庫：{db_path}")
    if out.exists() and not overwrite:
        raise BackupError(f"備份檔已存在：{out}（可使用 --overwrite）")
    out.parent.mkdir(parents=True, exist_ok=True)

    with TemporaryDirectory(prefix="vulnscan-backup-") as raw_tmp:
        tmp = Path(raw_tmp)
        snapshot = tmp / DB_NAME
        _snapshot_database(db_path, snapshot)
        _validate_database(snapshot)
        metadata = {
            "format": BACKUP_FORMAT,
            "tool": "VulnScan",
            "tool_version": __version__,
            "created_at": datetime.now(UTC).isoformat(),
            "database_sha256": _sha256(snapshot),
            "database_size": snapshot.stat().st_size,
            "source": data_dir.name,
        }
        file_count = 0
        with zipfile.ZipFile(
            out,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as archive:
            archive.write(snapshot, DB_NAME)
            for path in sorted(data_dir.rglob("*")):
                if path.is_dir() or path.is_symlink():
                    continue
                if path.resolve() == out:
                    continue
                name = path.relative_to(data_dir).as_posix()
                if name == DB_NAME or any(name.endswith(item) for item in SKIP_SUFFIXES):
                    continue
                archive.write(path, name)
                file_count += 1
            metadata["file_count"] = file_count
            archive.writestr(
                "backup.json",
                json.dumps(metadata, ensure_ascii=False, indent=2),
            )
    return {
        **metadata,
        "path": str(out),
        "size": out.stat().st_size,
    }


def restore_backup(
    archive_path: Path,
    data_dir: Path,
    *,
    force: bool = False,
) -> dict[str, Any]:
    archive_path = archive_path.expanduser().resolve()
    data_dir = data_dir.expanduser().resolve()
    if not archive_path.is_file():
        raise BackupError(f"找不到備份檔：{archive_path}")
    if data_dir.exists() and not data_dir.is_dir():
        raise BackupError(f"目標路徑不是目錄：{data_dir}")

    with TemporaryDirectory(prefix="vulnscan-restore-") as raw_tmp:
        tmp = Path(raw_tmp)
        _extract_validated(archive_path, tmp)
        restored_db = tmp / DB_NAME
        if not restored_db.is_file():
            raise BackupError("備份檔缺少 vulnscan.db")
        _validate_database(restored_db)

        if data_dir.exists() and any(data_dir.iterdir()):
            if not force:
                raise BackupError(
                    f"目標目錄不是空的：{data_dir}（可使用 --force）"
                )
            stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
            previous = data_dir.with_name(f"{data_dir.name}.pre-restore-{stamp}")
            counter = 1
            while previous.exists():
                previous = data_dir.with_name(
                    f"{data_dir.name}.pre-restore-{stamp}-{counter}"
                )
                counter += 1
            data_dir.rename(previous)
        else:
            previous = None
        data_dir.mkdir(parents=True, exist_ok=True)
        shutil.copytree(tmp, data_dir, dirs_exist_ok=True)

    with zipfile.ZipFile(archive_path) as archive:
        metadata: dict[str, Any] = {}
        if "backup.json" in archive.namelist():
            try:
                metadata = json.loads(archive.read("backup.json"))
            except (KeyError, json.JSONDecodeError):
                metadata = {}
    return {
        "path": str(data_dir),
        "previous": str(previous) if previous else None,
        "metadata": metadata,
    }


def _snapshot_database(source_path: Path, dest_path: Path) -> None:
    try:
        source = sqlite3.connect(
            f"file:{source_path.as_posix()}?mode=ro",
            uri=True,
        )
    except sqlite3.Error as exc:
        raise BackupError(f"無法開啟資料庫：{exc}") from exc
    dest = sqlite3.connect(dest_path)
    try:
        source.backup(dest)
    except sqlite3.Error as exc:
        raise BackupError(f"資料庫快照失敗：{exc}") from exc
    finally:
        dest.close()
        source.close()


def _validate_database(path: Path) -> None:
    conn = sqlite3.connect(path)
    try:
        integrity = conn.execute("PRAGMA integrity_check").fetchone()
        if not integrity or integrity[0] != "ok":
            raise BackupError("資料庫完整性檢查失敗")
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    except sqlite3.Error as exc:
        raise BackupError(f"資料庫驗證失敗：{exc}") from exc
    finally:
        conn.close()
    if "scans" not in tables:
        raise BackupError("資料庫缺少 scans 資料表，可能不是 VulnScan 備份")


def _extract_validated(archive_path: Path, target: Path) -> None:
    try:
        with zipfile.ZipFile(archive_path) as archive:
            total_size = 0
            for info in archive.infolist():
                name = info.filename
                if not name or "\\" in name:
                    raise BackupError(f"備份檔包含無效路徑：{name!r}")
                path = PurePosixPath(name)
                if path.is_absolute() or ".." in path.parts:
                    raise BackupError(f"備份檔包含不安全路徑：{name}")
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise BackupError(f"備份檔包含符號連結：{name}")
                total_size += info.file_size
                if total_size > 2 * 1024 * 1024 * 1024:
                    raise BackupError("備份檔解壓後超過 2 GB，已拒絕")
            for info in archive.infolist():
                if info.filename == "backup.json":
                    continue
                archive.extract(info, target)
    except zipfile.BadZipFile as exc:
        raise BackupError("備份檔不是有效的 ZIP") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
