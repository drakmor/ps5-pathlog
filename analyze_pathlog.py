#!/usr/bin/env python3

import argparse
import ftplib
import os
import posixpath
import sys
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import DefaultDict, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import unquote, urlparse


APP0_PREFIX = "/app0/"
FTP_TRACE_COMMANDS = False
UNLOGGED_CASE_SKIP_DIRS = {"sce_module", "sce_sys"}


@dataclass
class LogEntrySummary:
    variants: Counter = field(default_factory=Counter)
    variant_order: Dict[str, int] = field(default_factory=dict)


@dataclass
class Inventory:
    files_by_norm: Dict[str, str]
    dirs_by_norm: Dict[str, str]
    file_collisions: Dict[str, List[str]]
    dir_collisions: Dict[str, List[str]]


@dataclass
class CaseMismatch:
    path_type: str
    logged_path: str
    actual_path: str


@dataclass
class LogConflict:
    preferred_path: str
    variants: List[Tuple[str, int]]


@dataclass
class ReportData:
    matching: List[str]
    unlogged: List[str]
    unlogged_directories: List[str]
    file_mismatches: List[CaseMismatch]
    directory_mismatches: List[CaseMismatch]
    rename_targets: List[CaseMismatch]
    log_conflicts: List[LogConflict]
    directory_log_conflicts: List[LogConflict]
    actual_collisions: List[List[str]]
    ignored_directory_hits: List[str]
    parse_warnings: List[str]
    rename_actions: List[str]
    rename_errors: List[str]


@dataclass(frozen=True)
class FTPConfig:
    hostname: str
    port: int
    username: str
    password: str
    remote_root: str


class TracedFTP(ftplib.FTP):
    def putcmd(self, line: str) -> None:
        if FTP_TRACE_COMMANDS:
            display = line
            if line.upper().startswith("PASS "):
                display = "PASS ********"
            print(f"FTP >> {display}", file=sys.stderr, flush=True)
        super().putcmd(line)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare a pathlog file against a game directory and produce a Markdown report."
    )
    parser.add_argument("log_file", help="Path to the pathlog file")
    parser.add_argument(
        "game_root",
        help="Local game directory or FTP URL such as ftp://user:pass@host:port/path/to/game",
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--report",
        dest="mode",
        action="store_const",
        const="report",
        help="Generate a Markdown report",
    )
    mode_group.add_argument(
        "--rename-case",
        dest="mode",
        action="store_const",
        const="rename",
        help="Rename files/directories to match the preferred case from the log",
    )
    parser.set_defaults(mode="report")
    parser.add_argument(
        "-o",
        "--output",
        help="Output Markdown report path. Default: <log_file>.report.md. Only valid in report mode.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show planned renames without changing the filesystem. Only valid in rename mode.",
    )
    parser.add_argument(
        "--unlogged-files-case",
        choices=("lower", "upper"),
        help="In rename mode, rename files absent from the log to lower or upper case.",
    )
    parser.add_argument(
        "--unlogged-dirs-case",
        choices=("lower", "upper"),
        help="In rename mode, rename directories absent from the log to lower or upper case.",
    )
    parser.add_argument(
        "--ftp-user",
        help="Override FTP username when game_root is an ftp:// URL",
    )
    parser.add_argument(
        "--ftp-pass",
        help="Override FTP password when game_root is an ftp:// URL",
    )
    parser.add_argument(
        "--ftp-port",
        type=int,
        help="Override FTP port when game_root is an ftp:// URL",
    )
    return parser.parse_args()


def default_report_path(log_file: str) -> str:
    path = Path(log_file)
    return str(path.with_suffix(path.suffix + ".report.md"))


def unescape_payload_field(value: str) -> str:
    out: List[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch != "\\" or i + 1 >= len(value):
            out.append(ch)
            i += 1
            continue

        nxt = value[i + 1]
        if nxt == "n":
            out.append("\n")
        elif nxt == "r":
            out.append("\r")
        elif nxt == "t":
            out.append("\t")
        elif nxt == "\\":
            out.append("\\")
        else:
            out.append(nxt)
        i += 2
    return "".join(out)


def normalize_log_path(path: str) -> Optional[str]:
    path = path.strip()
    if not path or path in {"<null>", "<fault>"}:
        return None
    if path.startswith(APP0_PREFIX):
        path = path[len(APP0_PREFIX):]
    elif path == "/app0":
        return None
    else:
        path = path.lstrip("/")
    normalized = posixpath.normpath(path)
    if normalized in {"", "."}:
        return None
    return normalized


def normalize_case_key(path: str) -> str:
    return path.casefold()


def path_basename(path: str) -> str:
    return PurePosixPath(path).name


def path_dirname(path: str) -> str:
    parent = str(PurePosixPath(path).parent)
    return "" if parent == "." else parent


def parse_log(log_file: str) -> Tuple[Dict[str, LogEntrySummary], List[str]]:
    by_norm: Dict[str, LogEntrySummary] = {}
    warnings: List[str] = []
    line_no = 0

    with open(log_file, "r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line_no += 1
            line = raw_line.rstrip("\n")
            parts = line.split("\t", 2)
            if len(parts) != 3:
                warnings.append(f"Line {line_no}: expected 3 tab-separated columns")
                continue

            _, kind, raw_path = parts
            if kind != "open":
                continue

            decoded_path = unescape_payload_field(raw_path)
            normalized = normalize_log_path(decoded_path)
            if not normalized:
                continue

            norm_key = normalize_case_key(normalized)
            summary = by_norm.get(norm_key)
            if summary is None:
                summary = LogEntrySummary()
                by_norm[norm_key] = summary
            if normalized not in summary.variant_order:
                summary.variant_order[normalized] = len(summary.variant_order)
            summary.variants[normalized] += 1

    return by_norm, warnings


def add_collision(collisions: DefaultDict[str, List[str]], normalized: str, path: str) -> None:
    if path not in collisions[normalized]:
        collisions[normalized].append(path)


def build_unique_map(paths: Iterable[str]) -> Tuple[Dict[str, str], Dict[str, List[str]]]:
    unique: Dict[str, str] = {}
    collisions: DefaultDict[str, List[str]] = defaultdict(list)

    for path in paths:
        norm_key = normalize_case_key(path)
        prev = unique.get(norm_key)
        if prev is None:
            unique[norm_key] = path
            continue
        if prev != path:
            add_collision(collisions, norm_key, prev)
            add_collision(collisions, norm_key, path)

    for norm_key in collisions:
        unique.pop(norm_key, None)

    return unique, dict(collisions)


def collect_local_inventory(root: Path, excluded_relpaths: Set[str]) -> Inventory:
    file_paths: List[str] = []
    dir_paths: List[str] = []

    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        rel_dir = current.relative_to(root)
        if rel_dir != Path("."):
            dir_paths.append(rel_dir.as_posix())

        dirnames.sort()
        filenames.sort()
        for filename in filenames:
            rel_path = (current / filename).relative_to(root).as_posix()
            if rel_path in excluded_relpaths:
                continue
            file_paths.append(rel_path)

    files_by_norm, file_collisions = build_unique_map(file_paths)
    dirs_by_norm, dir_collisions = build_unique_map(dir_paths)
    return Inventory(files_by_norm, dirs_by_norm, file_collisions, dir_collisions)


def ftp_join(base: str, name: str) -> str:
    if name.startswith("/"):
        return posixpath.normpath(name)
    return posixpath.normpath(posixpath.join(base, name))


def ftp_list_dir(ftp: ftplib.FTP, directory: str) -> List[Tuple[str, str]]:
    entries: List[Tuple[str, str]] = []
    try:
        for name, facts in ftp.mlsd(directory):
            if name in {".", ".."}:
                continue
            entries.append((name, facts.get("type", "")))
        return entries
    except (ftplib.error_perm, AttributeError):
        pass

    old_pwd = ftp.pwd()
    try:
        ftp.cwd(directory)
        names = ftp.nlst()
    finally:
        ftp.cwd(old_pwd)

    results: List[Tuple[str, str]] = []
    for name in names:
        if name in {".", ".."}:
            continue
        child_name = name.rsplit("/", 1)[-1]
        child_path = ftp_join(directory, child_name)
        child_type = "dir" if ftp_is_dir(ftp, child_path) else "file"
        results.append((child_name, child_type))
    return results


def ftp_is_dir(ftp: ftplib.FTP, path: str) -> bool:
    old_pwd = ftp.pwd()
    try:
        ftp.cwd(path)
        return True
    except ftplib.all_errors:
        return False
    finally:
        try:
            ftp.cwd(old_pwd)
        except ftplib.all_errors:
            pass


def parse_ftp_config(url: str, ftp_user: Optional[str], ftp_pass: Optional[str], ftp_port: Optional[int]) -> FTPConfig:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "ftp":
        raise ValueError(f"Unsupported game_root scheme: {parsed.scheme}")
    if not parsed.hostname:
        raise ValueError("FTP URL must include a hostname")

    username = ftp_user if ftp_user is not None else (parsed.username or "anonymous")
    password = ftp_pass if ftp_pass is not None else (parsed.password or "anonymous@")
    port = ftp_port if ftp_port is not None else (parsed.port or 21)
    remote_root = unquote(parsed.path or "")
    if not remote_root:
        raise ValueError("FTP URL must include a remote directory path")

    return FTPConfig(
        hostname=parsed.hostname,
        port=port,
        username=username,
        password=password,
        remote_root=posixpath.normpath(remote_root),
    )


def ftp_connect(config: FTPConfig) -> ftplib.FTP:
    ftp = TracedFTP()
    ftp.connect(config.hostname, config.port, timeout=30)
    ftp.login(config.username, config.password)
    ftp.set_pasv(True)
    return ftp


def ftp_resolve_actual_path(
    ftp: ftplib.FTP,
    path: str,
    cache: Dict[str, Dict[str, List[str]]],
) -> str:
    normalized = posixpath.normpath(path)
    if normalized == "/":
        return "/"

    current = "/"
    for part in PurePosixPath(normalized).parts[1:]:
        actual_name = ftp_unique_casefold_match(ftp, current, part, cache)
        current = ftp_join(current, actual_name)
    return current


def collect_ftp_inventory(
    url: str,
    ftp_user: Optional[str],
    ftp_pass: Optional[str],
    ftp_port: Optional[int],
) -> Tuple[Inventory, FTPConfig, Dict[str, Dict[str, List[str]]]]:
    config = parse_ftp_config(url, ftp_user, ftp_pass, ftp_port)
    ftp = ftp_connect(config)

    file_paths: List[str] = []
    dir_paths: List[str] = []
    dir_cache: Dict[str, Dict[str, List[str]]] = {}

    try:
        actual_root = ftp_resolve_actual_path(ftp, config.remote_root, dir_cache)
        config = FTPConfig(
            hostname=config.hostname,
            port=config.port,
            username=config.username,
            password=config.password,
            remote_root=actual_root,
        )
        stack: List[str] = [config.remote_root]
        while stack:
            current = stack.pop()
            rel_dir = posixpath.relpath(current, config.remote_root)
            if rel_dir not in {".", ""}:
                dir_paths.append(rel_dir)

            entries = ftp_list_dir(ftp, current)
            dir_cache[current] = ftp_scan_dir_casefold_from_entries(entries)
            for name, entry_type in entries:
                child = ftp_join(current, name)
                rel_path = posixpath.relpath(child, config.remote_root)
                if entry_type == "dir":
                    stack.append(child)
                    continue
                file_paths.append(rel_path)
    finally:
        try:
            ftp.quit()
        except ftplib.all_errors:
            ftp.close()

    files_by_norm, file_collisions = build_unique_map(file_paths)
    dirs_by_norm, dir_collisions = build_unique_map(dir_paths)
    return Inventory(files_by_norm, dirs_by_norm, file_collisions, dir_collisions), config, dir_cache


def build_local_exclusions(root: Path, paths: Sequence[str]) -> Set[str]:
    excluded: Set[str] = set()
    root_resolved = root.resolve()

    for raw_path in paths:
        candidate = Path(raw_path)
        if not candidate.exists():
            continue
        try:
            rel = candidate.resolve().relative_to(root_resolved)
        except ValueError:
            continue
        excluded.add(rel.as_posix())

    return excluded


def load_inventory(
    game_root: str,
    ftp_user: Optional[str],
    ftp_pass: Optional[str],
    ftp_port: Optional[int],
    local_excluded_relpaths: Optional[Set[str]] = None,
) -> Tuple[Inventory, Optional[FTPConfig], Optional[Dict[str, Dict[str, List[str]]]]]:
    parsed = urlparse(game_root)
    if parsed.scheme.lower() == "ftp":
        inventory, config, dir_cache = collect_ftp_inventory(game_root, ftp_user, ftp_pass, ftp_port)
        return inventory, config, dir_cache

    root = Path(game_root)
    if not root.is_dir():
        raise FileNotFoundError(f"Local game directory not found: {game_root}")
    return collect_local_inventory(root, local_excluded_relpaths or set()), None, None


def collect_directory_log_conflicts(log_entries: Dict[str, LogEntrySummary]) -> List[LogConflict]:
    by_norm: Dict[str, LogEntrySummary] = {}

    for summary in log_entries.values():
        for path, count in summary.variants.items():
            parts = PurePosixPath(path).parts
            for depth in range(1, len(parts)):
                directory = PurePosixPath(*parts[:depth]).as_posix()
                norm_key = normalize_case_key(directory)
                dir_summary = by_norm.get(norm_key)
                if dir_summary is None:
                    dir_summary = LogEntrySummary()
                    by_norm[norm_key] = dir_summary
                if directory not in dir_summary.variant_order:
                    dir_summary.variant_order[directory] = len(dir_summary.variant_order)
                dir_summary.variants[directory] += count

    conflicts: List[LogConflict] = []
    for norm_key in sorted(by_norm.keys()):
        summary = by_norm[norm_key]
        if len(summary.variants) <= 1:
            continue
        variants = sorted(
            summary.variants.items(),
            key=lambda item: (-item[1], summary.variant_order[item[0]], item[0]),
        )
        conflicts.append(LogConflict(preferred_path=variants[0][0], variants=variants))

    return conflicts


def compare_log_to_inventory(log_entries: Dict[str, LogEntrySummary], inventory: Inventory) -> ReportData:
    matching: List[str] = []
    unlogged: List[str] = []
    unlogged_directories: List[str] = []
    file_mismatches: List[CaseMismatch] = []
    directory_mismatches: List[CaseMismatch] = []
    rename_targets: List[CaseMismatch] = []
    log_conflicts: List[LogConflict] = []
    directory_log_conflicts = collect_directory_log_conflicts(log_entries)
    actual_collisions: List[List[str]] = sorted(
        list(inventory.file_collisions.values()) + list(inventory.dir_collisions.values())
    )
    ignored_directory_hits: List[str] = []
    seen_dir_mismatches: Set[Tuple[str, str]] = set()
    seen_rename_targets: Set[Tuple[str, str, str]] = set()
    seen_log_dir_norms: Set[str] = set()

    def add_directory_mismatch(logged_dir: str, actual_dir: str) -> None:
        if logged_dir == actual_dir:
            return
        key = (normalize_case_key(logged_dir), normalize_case_key(actual_dir))
        if key in seen_dir_mismatches:
            return
        seen_dir_mismatches.add(key)
        directory_mismatches.append(CaseMismatch(path_type="dir", logged_path=logged_dir, actual_path=actual_dir))

    def add_rename_target(mismatch: CaseMismatch) -> None:
        key = (mismatch.path_type, normalize_case_key(mismatch.logged_path), normalize_case_key(mismatch.actual_path))
        if key in seen_rename_targets:
            return
        seen_rename_targets.add(key)
        rename_targets.append(mismatch)

    for norm_key in sorted(log_entries.keys()):
        summary = log_entries[norm_key]
        preferred = sorted(
            summary.variants.items(),
            key=lambda item: (-item[1], summary.variant_order[item[0]], item[0]),
        )[0][0]
        preferred_path = PurePosixPath(preferred)
        for depth in range(1, len(preferred_path.parts)):
            seen_log_dir_norms.add(normalize_case_key(PurePosixPath(*preferred_path.parts[:depth]).as_posix()))
        if len(summary.variants) > 1:
            variants = sorted(
                summary.variants.items(),
                key=lambda item: (-item[1], summary.variant_order[item[0]], item[0]),
            )
            log_conflicts.append(LogConflict(preferred_path=preferred, variants=variants))

        actual = inventory.files_by_norm.get(norm_key)
        if actual is not None:
            if actual != preferred:
                add_rename_target(CaseMismatch(path_type="file", logged_path=preferred, actual_path=actual))
            if actual == preferred or path_basename(actual) == path_basename(preferred):
                add_directory_mismatch(path_dirname(preferred), path_dirname(actual))
                matching.append(preferred)
            else:
                file_mismatches.append(CaseMismatch(path_type="file", logged_path=preferred, actual_path=actual))
            continue

        actual_dir = inventory.dirs_by_norm.get(norm_key)
        if actual_dir is not None:
            seen_log_dir_norms.add(norm_key)
            if actual_dir != preferred:
                add_rename_target(CaseMismatch(path_type="dir", logged_path=preferred, actual_path=actual_dir))
                add_directory_mismatch(preferred, actual_dir)
            ignored_directory_hits.append(preferred)
            continue

        if norm_key in inventory.dir_collisions:
            ignored_directory_hits.append(preferred)
            continue

    for norm_key, actual in sorted(inventory.files_by_norm.items(), key=lambda item: item[1].casefold()):
        if norm_key not in log_entries:
            unlogged.append(actual)

    for norm_key, actual in sorted(inventory.dirs_by_norm.items(), key=lambda item: item[1].casefold()):
        if norm_key not in seen_log_dir_norms:
            unlogged_directories.append(actual)

    return ReportData(
        matching=matching,
        unlogged=unlogged,
        unlogged_directories=unlogged_directories,
        file_mismatches=file_mismatches,
        directory_mismatches=directory_mismatches,
        rename_targets=rename_targets,
        log_conflicts=log_conflicts,
        directory_log_conflicts=directory_log_conflicts,
        actual_collisions=actual_collisions,
        ignored_directory_hits=ignored_directory_hits,
        parse_warnings=[],
        rename_actions=[],
        rename_errors=[],
    )


def scan_dir_casefold(directory: Path) -> Dict[str, List[str]]:
    matches: DefaultDict[str, List[str]] = defaultdict(list)
    for entry in os.scandir(directory):
        matches[entry.name.casefold()].append(entry.name)
    return dict(matches)


def unique_casefold_match(directory: Path, wanted_name: str, cache: Dict[Path, Dict[str, List[str]]]) -> str:
    if directory not in cache:
        cache[directory] = scan_dir_casefold(directory)
    matches = cache[directory].get(wanted_name.casefold(), [])
    if not matches:
        raise FileNotFoundError(f"No match for {wanted_name!r} in {directory}")
    if wanted_name in matches:
        return wanted_name
    if len(matches) > 1:
        raise RuntimeError(f"Ambiguous case-insensitive match for {wanted_name!r} in {directory}: {matches}")
    return matches[0]


def replace_cached_name(cache: Dict[Path, Dict[str, List[str]]], directory: Path, old_name: str, new_name: str) -> None:
    if directory not in cache:
        cache[directory] = scan_dir_casefold(directory) if directory.exists() else {}
    entries = cache[directory]
    old_key = old_name.casefold()
    old_matches = entries.get(old_key, [])
    if old_name in old_matches:
        old_matches.remove(old_name)
        if not old_matches:
            entries.pop(old_key, None)

    entries.setdefault(new_name.casefold(), []).append(new_name)
    entries[new_name.casefold()] = sorted(set(entries[new_name.casefold()]))


def rebase_cache_subtree(cache: Dict[Path, Dict[str, List[str]]], src: Path, dst: Path) -> None:
    moved: Dict[Path, Dict[str, List[str]]] = {}
    for path, entries in list(cache.items()):
        try:
            rel = path.relative_to(src)
        except ValueError:
            continue
        moved[dst / rel] = entries
        del cache[path]
    cache.update(moved)


def rel_display(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def rename_case_only(
    root: Path,
    src: Path,
    dst: Path,
    dry_run: bool,
    cache: Dict[Path, Dict[str, List[str]]],
    is_dir_hint: bool,
) -> List[str]:
    actions: List[str] = []
    if src.name == dst.name:
        return actions

    is_dir = is_dir_hint or src.is_dir()
    if is_dir:
        if src not in cache:
            cache[src] = scan_dir_casefold(src) if src.exists() else {}

    actions.append(f"{rel_display(src, root)} -> {rel_display(dst, root)}")

    if src.name.casefold() == dst.name.casefold():
        temp_name = f".__pathlog_tmp__{uuid.uuid4().hex}"
        temp_path = src.with_name(temp_name)
        if not dry_run:
            os.rename(src, temp_path)
            os.rename(temp_path, dst)
        replace_cached_name(cache, src.parent, src.name, dst.name)
        if is_dir:
            rebase_cache_subtree(cache, src, dst)
        return actions

    if not dry_run:
        os.rename(src, dst)
    replace_cached_name(cache, src.parent, src.name, dst.name)
    if is_dir:
        rebase_cache_subtree(cache, src, dst)
    return actions


def resolve_current_path(root: Path, rel_path: str, cache: Dict[Path, Dict[str, List[str]]]) -> Tuple[Path, str]:
    current = root
    actual_parts: List[str] = []
    for part in PurePosixPath(rel_path).parts:
        actual_name = unique_casefold_match(current, part, cache)
        actual_parts.append(actual_name)
        current = current / actual_name
    return current, PurePosixPath(*actual_parts).as_posix()


def normalize_name_case(name: str, case_mode: str) -> str:
    if case_mode == "lower":
        return name.lower()
    if case_mode == "upper":
        return name.upper()
    raise ValueError(f"Unsupported case mode: {case_mode}")


def should_skip_unlogged_case_path(rel_path: str) -> bool:
    parts = PurePosixPath(rel_path).parts
    if not parts:
        return False
    return parts[0].casefold() in UNLOGGED_CASE_SKIP_DIRS


def ftp_scan_dir_casefold_from_entries(entries: Sequence[Tuple[str, str]]) -> Dict[str, List[str]]:
    matches: DefaultDict[str, List[str]] = defaultdict(list)
    for name, _ in entries:
        matches[name.casefold()].append(name)
    return dict(matches)


def ftp_scan_dir_casefold(ftp: ftplib.FTP, directory: str) -> Dict[str, List[str]]:
    return ftp_scan_dir_casefold_from_entries(ftp_list_dir(ftp, directory))


def ftp_unique_casefold_match(
    ftp: ftplib.FTP,
    directory: str,
    wanted_name: str,
    cache: Dict[str, Dict[str, List[str]]],
) -> str:
    if directory not in cache:
        cache[directory] = ftp_scan_dir_casefold(ftp, directory)
    matches = cache[directory].get(wanted_name.casefold(), [])
    if not matches:
        raise FileNotFoundError(f"No match for {wanted_name!r} in {directory}")
    if wanted_name in matches:
        return wanted_name
    if len(matches) > 1:
        raise RuntimeError(f"Ambiguous case-insensitive match for {wanted_name!r} in {directory}: {matches}")
    return matches[0]


def ftp_replace_cached_name(
    ftp: ftplib.FTP,
    cache: Dict[str, Dict[str, List[str]]],
    directory: str,
    old_name: str,
    new_name: str,
) -> None:
    if directory not in cache:
        cache[directory] = ftp_scan_dir_casefold(ftp, directory)
    entries = cache[directory]
    old_key = old_name.casefold()
    old_matches = entries.get(old_key, [])
    if old_name in old_matches:
        old_matches.remove(old_name)
        if not old_matches:
            entries.pop(old_key, None)

    entries.setdefault(new_name.casefold(), []).append(new_name)
    entries[new_name.casefold()] = sorted(set(entries[new_name.casefold()]))


def ftp_rebase_cache_subtree(cache: Dict[str, Dict[str, List[str]]], src: str, dst: str) -> None:
    moved: Dict[str, Dict[str, List[str]]] = {}
    src_prefix = src.rstrip("/")
    for path, entries in list(cache.items()):
        if path != src and not path.startswith(src_prefix + "/"):
            continue
        suffix = path[len(src_prefix):]
        moved[dst + suffix] = entries
        del cache[path]
    cache.update(moved)


def ftp_rename_case_only(
    config: FTPConfig,
    ftp: ftplib.FTP,
    src: str,
    dst: str,
    dry_run: bool,
    cache: Dict[str, Dict[str, List[str]]],
    is_dir_hint: bool,
) -> List[str]:
    actions: List[str] = []
    if posixpath.basename(src) == posixpath.basename(dst):
        return actions

    if is_dir_hint and src not in cache:
        cache[src] = ftp_scan_dir_casefold(ftp, src)

    actions.append(f"{posixpath.relpath(src, config.remote_root)} -> {posixpath.relpath(dst, config.remote_root)}")

    old_pwd = ftp.pwd()
    parent_dir = posixpath.dirname(src) or "/"
    if posixpath.basename(src).casefold() == posixpath.basename(dst).casefold():
        temp_name = f"__pathlog_tmp__{uuid.uuid4().hex}"
        if not dry_run:
            try:
                ftp.cwd(parent_dir)
                ftp.rename(posixpath.basename(src), temp_name)
                ftp.rename(temp_name, posixpath.basename(dst))
            finally:
                ftp.cwd(old_pwd)
        ftp_replace_cached_name(ftp, cache, posixpath.dirname(src), posixpath.basename(src), posixpath.basename(dst))
        if is_dir_hint:
            ftp_rebase_cache_subtree(cache, src, dst)
        return actions

    if not dry_run:
        try:
            ftp.cwd(parent_dir)
            ftp.rename(posixpath.basename(src), posixpath.basename(dst))
        finally:
            ftp.cwd(old_pwd)
    ftp_replace_cached_name(ftp, cache, posixpath.dirname(src), posixpath.basename(src), posixpath.basename(dst))
    if is_dir_hint:
        ftp_rebase_cache_subtree(cache, src, dst)
    return actions


def ftp_resolve_current_path(
    config: FTPConfig,
    ftp: ftplib.FTP,
    rel_path: str,
    cache: Dict[str, Dict[str, List[str]]],
) -> Tuple[str, str]:
    current = config.remote_root
    actual_parts: List[str] = []
    for part in PurePosixPath(rel_path).parts:
        actual_name = ftp_unique_casefold_match(ftp, current, part, cache)
        actual_parts.append(actual_name)
        current = ftp_join(current, actual_name)
    return current, PurePosixPath(*actual_parts).as_posix()


def apply_case_renames(
    root: Path,
    mismatches: Sequence[CaseMismatch],
    dry_run: bool,
    dir_cache: Optional[Dict[Path, Dict[str, List[str]]]] = None,
) -> Tuple[List[str], List[str]]:
    actions: List[str] = []
    errors: List[str] = []
    if dir_cache is None:
        dir_cache = {}

    for mismatch in sorted(
        mismatches,
        key=lambda item: (len(PurePosixPath(item.logged_path).parts), item.path_type != "dir", item.logged_path.casefold()),
    ):
        current = root
        target_parts = PurePosixPath(mismatch.logged_path).parts
        try:
            for idx, part in enumerate(target_parts):
                actual_name = unique_casefold_match(current, part, dir_cache)
                src = current / actual_name
                dst = current / part
                is_dir_hint = idx + 1 < len(target_parts) or mismatch.path_type == "dir"
                actions.extend(rename_case_only(root, src, dst, dry_run, dir_cache, is_dir_hint))
                current = dst
        except (FileNotFoundError, RuntimeError, OSError) as exc:
            errors.append(f"{mismatch.actual_path} -> {mismatch.logged_path}: {exc}")

    return actions, errors


def apply_unlogged_name_renames(
    root: Path,
    rel_paths: Sequence[str],
    path_type: str,
    case_mode: str,
    dry_run: bool,
    dir_cache: Dict[Path, Dict[str, List[str]]],
) -> Tuple[List[str], List[str]]:
    actions: List[str] = []
    errors: List[str] = []
    sorted_paths = sorted(rel_paths, key=lambda path: (len(PurePosixPath(path).parts), path.casefold()))

    for rel_path in sorted_paths:
        if should_skip_unlogged_case_path(rel_path):
            continue
        try:
            src, actual_rel = resolve_current_path(root, rel_path, dir_cache)
            target_name = normalize_name_case(path_basename(actual_rel), case_mode)
            if target_name == src.name:
                continue
            dst = src.with_name(target_name)
            actions.extend(rename_case_only(root, src, dst, dry_run, dir_cache, path_type == "dir"))
        except (FileNotFoundError, RuntimeError, OSError) as exc:
            errors.append(f"{rel_path}: {exc}")

    return actions, errors


def apply_case_renames_ftp(
    config: FTPConfig,
    mismatches: Sequence[CaseMismatch],
    dry_run: bool,
    dir_cache: Optional[Dict[str, Dict[str, List[str]]]] = None,
) -> Tuple[List[str], List[str]]:
    actions: List[str] = []
    errors: List[str] = []
    if dir_cache is None:
        dir_cache = {}

    ftp = ftp_connect(config)
    try:
        for mismatch in sorted(
            mismatches,
            key=lambda item: (len(PurePosixPath(item.logged_path).parts), item.path_type != "dir", item.logged_path.casefold()),
        ):
            current = config.remote_root
            target_parts = PurePosixPath(mismatch.logged_path).parts
            try:
                for idx, part in enumerate(target_parts):
                    actual_name = ftp_unique_casefold_match(ftp, current, part, dir_cache)
                    src = ftp_join(current, actual_name)
                    dst = ftp_join(current, part)
                    is_dir_hint = idx + 1 < len(target_parts) or mismatch.path_type == "dir"
                    actions.extend(ftp_rename_case_only(config, ftp, src, dst, dry_run, dir_cache, is_dir_hint))
                    current = dst
            except (FileNotFoundError, RuntimeError, OSError, ftplib.all_errors) as exc:
                errors.append(f"{mismatch.actual_path} -> {mismatch.logged_path}: {exc}")
    finally:
        try:
            ftp.quit()
        except ftplib.all_errors:
            ftp.close()

    return actions, errors


def apply_unlogged_name_renames_ftp(
    config: FTPConfig,
    rel_paths: Sequence[str],
    path_type: str,
    case_mode: str,
    dry_run: bool,
    dir_cache: Dict[str, Dict[str, List[str]]],
) -> Tuple[List[str], List[str]]:
    actions: List[str] = []
    errors: List[str] = []
    sorted_paths = sorted(rel_paths, key=lambda path: (len(PurePosixPath(path).parts), path.casefold()))

    ftp = ftp_connect(config)
    try:
        for rel_path in sorted_paths:
            if should_skip_unlogged_case_path(rel_path):
                continue
            try:
                src, actual_rel = ftp_resolve_current_path(config, ftp, rel_path, dir_cache)
                target_name = normalize_name_case(path_basename(actual_rel), case_mode)
                if target_name == posixpath.basename(src):
                    continue
                dst = ftp_join(posixpath.dirname(src), target_name)
                actions.extend(ftp_rename_case_only(config, ftp, src, dst, dry_run, dir_cache, path_type == "dir"))
            except (FileNotFoundError, RuntimeError, OSError, ftplib.all_errors) as exc:
                errors.append(f"{rel_path}: {exc}")
    finally:
        try:
            ftp.quit()
        except ftplib.all_errors:
            ftp.close()

    return actions, errors


def markdown_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", "\\n").replace("\r", "\\r")


def render_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> List[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(markdown_escape(value) for value in row) + " |")
    return lines


def render_markdown(
    report: ReportData,
    log_file: str,
    game_root: str,
    rename_requested: bool,
    dry_run: bool,
) -> str:
    lines: List[str] = []
    lines.append("# Pathlog Comparison Report")
    lines.append("")
    lines.append(f"- Log file: `{log_file}`")
    lines.append(f"- Game root: `{game_root}`")
    lines.append(f"- Matching files: `{len(report.matching)}`")
    lines.append(f"- File case mismatches: `{len(report.file_mismatches)}`")
    lines.append(f"- Directory case mismatches: `{len(report.directory_mismatches)}`")
    lines.append(f"- File path case conflicts in log: `{len(report.log_conflicts)}`")
    lines.append(f"- Directory case conflicts in log: `{len(report.directory_log_conflicts)}`")
    lines.append(f"- Files present on disk but absent from log: `{len(report.unlogged)}`")
    lines.append("")

    if report.actual_collisions or report.ignored_directory_hits or report.parse_warnings or report.rename_actions or report.rename_errors:
        lines.append("## Warnings")
        lines.append("")
        for warning in report.parse_warnings:
            lines.append(f"- {warning}")
        for collision in report.actual_collisions:
            lines.append(f"- Multiple on-disk paths collide case-insensitively: `{', '.join(collision)}`")
        if report.ignored_directory_hits:
            lines.append(f"- Ignored `{len(report.ignored_directory_hits)}` open entries that match directories rather than files.")
        if rename_requested and report.rename_actions:
            mode = "Planned" if dry_run else "Applied"
            lines.append(f"- {mode} rename operations: `{len(report.rename_actions)}`")
        for error in report.rename_errors:
            lines.append(f"- Rename error: `{error}`")
        lines.append("")

    lines.append("## Files With Case Differences")
    lines.append("")
    if report.file_mismatches:
        lines.extend(render_table(
            ["Logged Path", "Actual Path", "Logged File", "Actual File"],
            [
                [
                    mismatch.logged_path,
                    mismatch.actual_path,
                    path_basename(mismatch.logged_path),
                    path_basename(mismatch.actual_path),
                ]
                for mismatch in report.file_mismatches
            ],
        ))
    else:
        lines.append("_None_")
    lines.append("")

    lines.append("## Directories With Case Differences")
    lines.append("")
    if report.directory_mismatches:
        lines.extend(render_table(
            ["Logged Directory", "Actual Directory"],
            [
                [mismatch.logged_path or ".", mismatch.actual_path or "."]
                for mismatch in report.directory_mismatches
            ],
        ))
    else:
        lines.append("_None_")
    lines.append("")

    lines.append("## File Path Case Conflicts In Log")
    lines.append("")
    if report.log_conflicts:
        lines.extend(render_table(
            ["Preferred Path", "Variants Seen"],
            [
                [
                    conflict.preferred_path,
                    ", ".join(f"{path} ({count})" for path, count in conflict.variants),
                ]
                for conflict in report.log_conflicts
            ],
        ))
    else:
        lines.append("_None_")
    lines.append("")

    lines.append("## Directory Case Conflicts In Log")
    lines.append("")
    if report.directory_log_conflicts:
        lines.extend(render_table(
            ["Preferred Directory", "Variants Seen"],
            [
                [
                    conflict.preferred_path,
                    ", ".join(f"{path} ({count})" for path, count in conflict.variants),
                ]
                for conflict in report.directory_log_conflicts
            ],
        ))
    else:
        lines.append("_None_")
    lines.append("")

    lines.append("## Files Present On Disk But Absent From Log")
    lines.append("")
    if report.unlogged:
        lines.extend(render_table(["Path"], [[path] for path in report.unlogged]))
    else:
        lines.append("_None_")
    lines.append("")

    lines.append("## Matching Files")
    lines.append("")
    if report.matching:
        lines.extend(render_table(["Path"], [[path] for path in report.matching]))
    else:
        lines.append("_None_")
    lines.append("")

    if rename_requested:
        lines.append("## Rename Operations")
        lines.append("")
        if report.rename_actions:
            lines.extend(render_table(
                ["From", "To"],
                [action.split(" -> ", 1) if " -> " in action else [action, ""] for action in report.rename_actions],
            ))
        else:
            lines.append("_None_")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    output_path = args.output or default_report_path(args.log_file)

    if args.dry_run and args.mode != "rename":
        print("--dry-run only makes sense together with --rename-case", file=sys.stderr)
        return 2

    if args.output and args.mode != "report":
        print("--output is only valid in report mode", file=sys.stderr)
        return 2

    if (args.unlogged_files_case or args.unlogged_dirs_case) and args.mode != "rename":
        print("--unlogged-files-case/--unlogged-dirs-case are only valid with --rename-case", file=sys.stderr)
        return 2

    log_entries, parse_warnings = parse_log(args.log_file)
    local_excluded_relpaths: Set[str] = set()
    if urlparse(args.game_root).scheme.lower() != "ftp":
        local_excluded_relpaths = build_local_exclusions(Path(args.game_root), [args.log_file, output_path])
    inventory, ftp_config, ftp_dir_cache = load_inventory(
        args.game_root,
        args.ftp_user,
        args.ftp_pass,
        args.ftp_port,
        local_excluded_relpaths,
    )
    report = compare_log_to_inventory(log_entries, inventory)
    report.parse_warnings.extend(parse_warnings)

    if args.mode == "rename":
        if ftp_config is None:
            root = Path(args.game_root)
            dir_cache: Dict[Path, Dict[str, List[str]]] = {}
            actions, errors = apply_case_renames(root, report.rename_targets, args.dry_run, dir_cache)
            report.rename_actions.extend(actions)
            report.rename_errors.extend(errors)
            if args.unlogged_files_case:
                actions, errors = apply_unlogged_name_renames(
                    root,
                    report.unlogged,
                    "file",
                    args.unlogged_files_case,
                    args.dry_run,
                    dir_cache,
                )
                report.rename_actions.extend(actions)
                report.rename_errors.extend(errors)
            if args.unlogged_dirs_case:
                actions, errors = apply_unlogged_name_renames(
                    root,
                    report.unlogged_directories,
                    "dir",
                    args.unlogged_dirs_case,
                    args.dry_run,
                    dir_cache,
                )
                report.rename_actions.extend(actions)
                report.rename_errors.extend(errors)
        else:
            dir_cache: Dict[str, Dict[str, List[str]]] = dict(ftp_dir_cache or {})
            actions, errors = apply_case_renames_ftp(ftp_config, report.rename_targets, args.dry_run, dir_cache)
            report.rename_actions.extend(actions)
            report.rename_errors.extend(errors)
            if args.unlogged_files_case:
                actions, errors = apply_unlogged_name_renames_ftp(
                    ftp_config,
                    report.unlogged,
                    "file",
                    args.unlogged_files_case,
                    args.dry_run,
                    dir_cache,
                )
                report.rename_actions.extend(actions)
                report.rename_errors.extend(errors)
            if args.unlogged_dirs_case:
                actions, errors = apply_unlogged_name_renames_ftp(
                    ftp_config,
                    report.unlogged_directories,
                    "dir",
                    args.unlogged_dirs_case,
                    args.dry_run,
                    dir_cache,
                )
                report.rename_actions.extend(actions)
                report.rename_errors.extend(errors)

    if args.mode == "report":
        markdown = render_markdown(report, args.log_file, args.game_root, False, False)
        with open(output_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(markdown)
            handle.write("\n")
        print(f"Wrote report: {output_path}")
    else:
        mode = "Planned" if args.dry_run else "Applied"
        print(f"{mode} renames: {len(report.rename_actions)}")
        if report.rename_actions:
            print(f"{mode} rename operations:")
            for action in report.rename_actions:
                print(f"  {action}")
        else:
            print("No rename operations required.")
        if report.rename_errors:
            print(f"Rename errors: {len(report.rename_errors)}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
