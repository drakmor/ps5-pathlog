# Pathlog Monitor

`pathlog-payload` is a set of utilities for:
- recording a file access log on PS5
- analyzing the resulting log and validating game files

The folder contains:
- `pathlog_all.elf`  
  continuous monitoring of all events
- `pathlog_apps.elf`  
  monitoring only while `CUSA*` and `PPSA*` games are running
- `pathlog_stop.elf`  
  clean shutdown of the active monitor process
- `analyze_pathlog.py`  
  a script for analyzing the log and renaming files to the correct case

## What It Is For

This project is useful when you need to:
- understand which files a game actually reads
- build a list of files that are really used
- find case mistakes in file and directory names
- compare a launch log against a local game folder or an FTP copy
- automatically rename files and folders to the case the game expects

## Requirements

Before using these tools, you need a special `kstuff-lite` build with logging support loaded.  

To build the ELF files, you need the SDK installed at:

```bash
/opt/ps5-payload-sdk
```

## Quick Start

### Build

```bash
make -C pathlog-payload clean all
```

### Option 1: Log Everything

Run:

```text
pathlog_all.elf
```

What happens:
- the monitor enables logging immediately
- new events are printed to the console
- the log is written to:

```text
/data/pathlog/all.log
```

### Option 2: Log Only Running Games

Run:

```text
pathlog_apps.elf
```

What happens:
- the monitor waits for an application to start
- when a game with a `CUSA*` or `PPSA*` title ID starts, logging is enabled automatically
- a separate log is created for each game:

```text
/data/pathlog/<TITLE_ID>.log
```

Example:

```text
/data/pathlog/PPSA12345.log
```

This mode is useful when you want a clean log for a single game without background system noise.

### Stop Monitoring

Always use:

```text
pathlog_stop.elf
```

The utility finds the active monitor process by name and terminates it cleanly.  
If no monitor is running, it simply reports that.

## Where Logs Are Stored

All logs are stored in:

```text
/data/pathlog/
```

Main variants:
- `all.log` for full monitoring
- `<TITLE_ID>.log` for game-only monitoring

Log line format:

```text
timestamp<TAB>kind<TAB>path
```

Example:

```text
2026-03-18T01:23:45.678	open	/app0/eboot.bin
2026-03-18T01:23:45.700	stat	/app0/sce_sys/param.sfo
```

## Analyzing Logs with the Python Script

`analyze_pathlog.py` works in two modes:
- build a Markdown report
- rename files and folders

The script:
- reads the pathlog file and analyzes `open` entries
- collects the game file list and compares paths case-insensitively
- works with both a local folder and FTP

## Report Mode

Example for a local folder:

```bash
python3 pathlog-payload/analyze_pathlog.py \
  --report \
  pathlog-payload/PPSA12345.log \
  /games/PPSA12345
```

Example for FTP:

```bash
python3 pathlog-payload/analyze_pathlog.py \
  --report \
  pathlog-payload/PPSA12345.log \
  ftp://user:pass@192.168.0.10:1337/user/app/PPSA12345
```

If no output path is specified, the report is created next to the log:

```text
<log>.report.md
```

The report includes:
- files whose file name case differs
- directories whose name case differs
- full file path case conflicts found inside the log
- directory case conflicts found inside the log
- files that exist in the game folder but never appeared in the log
- matching files

You can also specify a custom report path:

```bash
python3 pathlog-payload/analyze_pathlog.py \
  --report \
  -o result.md \
  pathlog-payload/PPSA12345.log \
  /games/PPSA12345
```

## Rename Mode

This mode is used when you want to rename real files and folders to the case the game expects.

A dry run is recommended first:

```bash
python3 pathlog-payload/analyze_pathlog.py \
  --rename-case \
  --dry-run \
  pathlog-payload/PPSA12345.log \
  /games/PPSA12345
```

The script shows the planned renames without modifying anything.

After verifying the plan, you can run the real rename:

```bash
python3 pathlog-payload/analyze_pathlog.py \
  --rename-case \
  pathlog-payload/PPSA12345.log \
  /games/PPSA12345
```

The same also works over FTP:

```bash
python3 pathlog-payload/analyze_pathlog.py \
  --rename-case \
  --dry-run \
  pathlog-payload/PPSA12345.log \
  ftp://user:pass@192.168.0.10:1337/user/app/PPSA12345
```

## Additional Rename Parameters

You can also set the case for files and folders that never appeared in the log.

Example:

```bash
python3 pathlog-payload/analyze_pathlog.py \
  --rename-case \
  --dry-run \
  --unlogged-files-case lower \
  --unlogged-dirs-case lower \
  pathlog-payload/PPSA12345.log \
  /games/PPSA12345
```

Available values:
- `lower`
- `upper`

This is useful if you want not only to fix the case according to the log, but also normalize unused files and folders to a consistent style.

Limitation:
- paths inside `sce_module` and `sce_sys` are intentionally ignored by `--unlogged-files-case` and `--unlogged-dirs-case`

## FTP Parameters

If the log is analyzed over FTP, you can pass connection parameters directly in the URL:

```text
ftp://user:pass@host:port/path/to/game
```

Or override them with separate arguments:
- `--ftp-user`
- `--ftp-pass`
- `--ftp-port`

Example:

```bash
python3 pathlog-payload/analyze_pathlog.py \
  --report \
  --ftp-user user \
  --ftp-pass pass \
  --ftp-port 1337 \
  pathlog-payload/PPSA12345.log \
  ftp://192.168.0.10/user/app/PPSA12345
```
