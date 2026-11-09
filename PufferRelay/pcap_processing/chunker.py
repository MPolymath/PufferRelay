"""Chunked parsing with resume (step 4) — for very large captures.

`editcap` splits the capture into packet-count chunks; each chunk runs the
normal handler pipeline and is then deleted. A checkpoint records completed
chunks so an interrupted run resumes instead of starting over. The database
accumulates across chunks; `INSERT OR IGNORE` keeps duplicates out.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile

from PufferRelay.pcap_processing.pcap_parser import parse_pcap
from PufferRelay.database.db_queries import process_extracted_data


class ChunkerError(RuntimeError):
    pass


def find_editcap():
    found = shutil.which("editcap")
    if found:
        return found
    for candidate in (
        r"C:\Program Files\Wireshark\editcap.exe",
        r"C:\Program Files (x86)\Wireshark\editcap.exe",
    ):
        if os.path.exists(candidate):
            return candidate
    return ""


def split_capture(pcap_file, out_dir, packets_per_chunk=200000):
    editcap = find_editcap()
    if not editcap:
        raise ChunkerError("editcap is not installed (it ships with Wireshark)")
    if packets_per_chunk < 1:
        raise ChunkerError("packets_per_chunk must be positive")
    os.makedirs(out_dir, exist_ok=True)
    prefix = os.path.join(out_dir, "chunk")
    command = [editcap, "-c", str(int(packets_per_chunk)), pcap_file, prefix]
    completed = subprocess.run(command, capture_output=True)
    if completed.returncode != 0:
        error = completed.stderr.decode("utf-8", "replace").strip().splitlines()
        raise ChunkerError(
            f"editcap failed: {error[-1] if error else completed.returncode}"
        )
    chunks = sorted(
        os.path.join(out_dir, name)
        for name in os.listdir(out_dir)
        if name.startswith("chunk") and os.path.isfile(os.path.join(out_dir, name))
    )
    if not chunks:
        raise ChunkerError("editcap produced no chunks")
    return chunks


def _checkpoint_path(pcap_file):
    base = os.path.basename(os.path.abspath(pcap_file))
    return os.path.join(
        tempfile.gettempdir(), f"pufferrelay-chunks-{base}.json"
    )


def load_checkpoint(pcap_file):
    path = _checkpoint_path(pcap_file)
    try:
        with open(path, encoding="utf-8") as handle:
            state = json.load(handle)
        stat = os.stat(pcap_file)
        if (
            state.get("source") != os.path.abspath(pcap_file)
            or state.get("size") != stat.st_size
            or state.get("mtime_ns") != stat.st_mtime_ns
        ):
            return {"completed": []}
        return {"completed": sorted(set(state.get("completed", [])))}
    except (OSError, ValueError):
        return {"completed": []}


def save_checkpoint(pcap_file, completed):
    stat = os.stat(pcap_file)
    state = {
        "source": os.path.abspath(pcap_file),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "completed": sorted(set(completed)),
    }
    path = _checkpoint_path(pcap_file)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(state, handle, indent=2)
        handle.write("\n")


def clear_checkpoint(pcap_file):
    try:
        os.remove(_checkpoint_path(pcap_file))
    except OSError:
        pass


def merge_data(target, data):
    for name, rows in data.items():
        if isinstance(rows, list):
            target.setdefault(name, []).extend(rows)
        else:
            target[name] = rows


def run_chunked(pcap_file, only=None, credentials_only=False, jobs=1,
                packets_per_chunk=200000, animate=False):
    """Split, parse and store each chunk; return merged handler data."""
    state = load_checkpoint(pcap_file)
    completed = set(state["completed"])
    directory = tempfile.mkdtemp(prefix="pufferrelay-chunks-")
    merged = {}
    try:
        chunks = split_capture(pcap_file, directory, packets_per_chunk)
        logging.info(
            "Chunked parse: %d chunk(s), %d already completed",
            len(chunks),
            len(completed),
        )
        for index, chunk in enumerate(chunks):
            if index in completed:
                continue
            data = parse_pcap(
                chunk,
                only=only,
                credentials_only=credentials_only,
                animate=animate,
                jobs=jobs,
            )
            process_extracted_data(data)
            merge_data(merged, data)
            completed.add(index)
            save_checkpoint(pcap_file, completed)
            logging.info("Chunk %d/%d stored", index + 1, len(chunks))
            try:
                os.remove(chunk)
            except OSError:
                pass
        clear_checkpoint(pcap_file)
        return merged
    finally:
        shutil.rmtree(directory, ignore_errors=True)
