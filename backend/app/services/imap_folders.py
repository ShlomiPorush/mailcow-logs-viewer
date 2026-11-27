import base64
import json
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

DEFAULT_FOLDER = 'INBOX'


@dataclass(frozen=True)
class Entry:
    name: str
    subfolders: bool = False


@dataclass(frozen=True)
class Folder:
    raw: str
    name: str
    delimiter: Optional[str]
    flags: frozenset = field(default_factory=frozenset)

    @property
    def selectable(self) -> bool:
        return not ({'\\noselect', '\\nonexistent'} & self.flags)

    @property
    def can_have_children(self) -> bool:
        return self.delimiter is not None and '\\noinferiors' not in self.flags


@dataclass(frozen=True)
class Target:
    select: str
    label: str


def parse_setting(value: Optional[str]) -> Tuple[Optional[List[Entry]], Optional[str]]:
    text = value if isinstance(value, str) else ''
    if not text.strip():
        return None, DEFAULT_FOLDER
    try:
        items = json.loads(text)
    except ValueError:
        return None, text
    if not isinstance(items, list) or not items:
        return None, text
    entries = []
    for item in items:
        if isinstance(item, str) and item:
            entries.append(Entry(item))
        elif (isinstance(item, dict) and set(item) <= {'name', 'subfolders'}
              and isinstance(item.get('name'), str) and item['name']
              and isinstance(item.get('subfolders', False), bool)):
            entries.append(Entry(item['name'], item.get('subfolders', False)))
        else:
            return None, text
    return entries, None


def describe_setting(value: Optional[str]) -> str:
    entries, legacy = parse_setting(value)
    if entries is None:
        return legacy
    return ', '.join(f"{e.name} (with subfolders)" if e.subfolders else e.name for e in entries)


def decode_mutf7(raw: str) -> str:
    out = []
    i = 0
    while i < len(raw):
        char = raw[i]
        if char != '&':
            out.append(char)
            i += 1
            continue
        end = raw.find('-', i)
        if end < 0:
            raise ValueError('unterminated shift')
        chunk = raw[i + 1:end]
        if not chunk:
            out.append('&')
        else:
            data = chunk.replace(',', '/')
            data += '=' * (-len(data) % 4)
            decoded = base64.b64decode(data, validate=True)
            if len(decoded) % 2:
                raise ValueError('odd UTF-16 length')
            text = decoded.decode('utf-16-be')
            if any(0x20 <= ord(char) <= 0x7e for char in text):
                raise ValueError('printable ASCII in a shifted sequence')
            out.append(text)
        i = end + 1
    return ''.join(out)


_QUOTED = r'"((?:[^"\\]|\\.)*)"'
_LIST_LINE = re.compile(r'^\(([^)]*)\)\s+(NIL|' + _QUOTED + r')(?:\s+(.*))?$', re.IGNORECASE | re.DOTALL)
_ATOM = re.compile(r'^[^\s"(){}\\]+$')


def _unquote(text: str) -> str:
    return re.sub(r'\\(.)', r'\1', text)


_CONTROL = re.compile(r'[\x00-\x1f\x7f]')


def _folder(flags_text: str, delimiter: Optional[str], raw: str) -> Folder:
    if _CONTROL.search(raw) or (delimiter is not None and (len(delimiter) != 1 or _CONTROL.search(delimiter))):
        raise ValueError(f'unsafe name or separator: {raw!r}')
    name = decode_mutf7(raw)
    if not name or _CONTROL.search(name):
        raise ValueError(f'unsafe decoded name: {raw!r}')
    flags = frozenset(flag.lower() for flag in flags_text.split())
    return Folder(raw=raw, name=name, delimiter=delimiter, flags=flags)


def parse_list(data) -> Tuple[List[Folder], int]:
    folders, unreadable = [], 0
    after_literal = False
    for item in data or []:
        try:
            if isinstance(item, tuple):
                head, literal = item[0].decode('ascii'), item[1].decode('ascii')
                match = _LIST_LINE.match(re.sub(r'\s*\{\d+\+?\}$', '', head))
                if not match or match.group(4):
                    raise ValueError(head)
                delimiter = None if match.group(3) is None else _unquote(match.group(3))
                folders.append(_folder(match.group(1), delimiter, literal))
                after_literal = True
                continue
            if item is None:
                continue
            line = item.decode('ascii').strip()
            if after_literal and line in ('', ')'):
                after_literal = False
                continue
            after_literal = False
            if not line:
                continue
            match = _LIST_LINE.match(line)
            if not match or match.group(4) is None:
                raise ValueError(line)
            delimiter = None if match.group(3) is None else _unquote(match.group(3))
            name = match.group(4).strip()
            if name.startswith('"') and name.endswith('"') and len(name) >= 2 and re.fullmatch(_QUOTED, name):
                raw = _unquote(name[1:-1])
            elif _ATOM.match(name):
                raw = name
            else:
                raise ValueError(line)
            folders.append(_folder(match.group(1), delimiter, raw))
        except (ValueError, UnicodeError, AttributeError, IndexError) as error:
            unreadable += 1
            logger.warning(f"Could not read a line of the IMAP folder list: {str(error)[:200]!r}")
    counts = {}
    for folder in folders:
        counts[_key(folder.name)] = counts.get(_key(folder.name), 0) + 1
    clashing = [folder for folder in folders if counts[_key(folder.name)] > 1]
    if clashing:
        logger.warning(f"{len(clashing)} IMAP folders share a name with another folder and are left out")
    return [folder for folder in folders if counts[_key(folder.name)] == 1], unreadable + len(clashing)


def list_folders(connection) -> Tuple[List[Folder], int]:
    status, data = connection.list('""', '*')
    if status != 'OK':
        raise RuntimeError("The server did not list its folders")
    return parse_list(data)


def _key(name: str) -> str:
    return DEFAULT_FOLDER if name.upper() == DEFAULT_FOLDER else name


def quote(raw: str) -> str:
    return '"' + raw.replace('\\', '\\\\').replace('"', '\\"') + '"'


def resolve(folders: List[Folder], entries: List[Entry]) -> Tuple[List[Target], List[str], List[str]]:
    by_key = {}
    for folder in folders:
        by_key.setdefault(_key(folder.name), folder)
    chosen = set()
    missing, empty = [], []
    for entry in entries:
        folder = by_key.get(_key(entry.name))
        if folder is None:
            missing.append(entry.name)
            continue
        found = False
        if folder.selectable:
            chosen.add(folder.raw)
            found = True
        if entry.subfolders and folder.can_have_children:
            prefix = folder.name + folder.delimiter
            for other in folders:
                if other.selectable and other.name.startswith(prefix):
                    chosen.add(other.raw)
                    found = True
        if not found:
            if entry.subfolders:
                empty.append(entry.name)
            else:
                missing.append(entry.name)
    targets = []
    for folder in folders:
        if folder.raw in chosen:
            targets.append(Target(select=quote(folder.raw), label=folder.name))
    return targets, missing, empty


def legacy_match(folders: List[Folder], value: str) -> Optional[str]:
    for folder in folders:
        if folder.raw == value or (folder.raw.upper() == DEFAULT_FOLDER and value.upper() == DEFAULT_FOLDER):
            return folder.name
    return None


def folder_targets(connection, value: Optional[str]) -> Tuple[List[Target], List[str], List[str], int]:
    entries, legacy = parse_setting(value)
    if entries is None:
        return [Target(select=legacy, label=legacy)], [], [], 0
    folders, unreadable = list_folders(connection)
    targets, missing, empty = resolve(folders, entries)
    return targets, missing, empty, unreadable
