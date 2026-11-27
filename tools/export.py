"""Extract reviewable sources from a KIXBOX EPF; refuse unknown credential layouts."""
from pathlib import Path
import argparse
import re
import struct
import zlib

ROOT = Path(__file__).resolve().parents[1]


def block(data, offset):
    result = bytearray()
    total = None
    seen = set()
    while offset != 0x7fffffff:
        if offset in seen or data[offset:offset+2] != b'\r\n':
            raise ValueError("Invalid EPF block")
        seen.add(offset)
        size, capacity, next_offset = [int(v, 16) for v in data[offset+2:offset+29].split()]
        if total is None:
            total = size
        start = offset + 31
        result.extend(data[start:start + min(capacity, total-len(result))])
        offset = next_offset
    if len(result) != total:
        raise ValueError("Truncated EPF")
    return bytes(result)


def entries(data):
    for header, content, marker in struct.iter_unpack('<III', block(data, 16)):
        if marker != 0x7fffffff:
            raise ValueError("Invalid EPF directory")
        name = block(data, header)[20:].decode('utf-16le').rstrip('\0')
        yield name, block(data, content)


def export(path):
    modules = []
    layout = None
    for name, content in entries(path.read_bytes()):
        raw = zlib.decompress(content, -15)
        if name == "d81ae4ec-a09c-4934-a462-833c4a84a02f.0":
            layout = raw
        if raw.startswith(b'\xff\xff\xff\x7f'):
            elements = dict(entries(raw))
            if 'module' in elements:
                modules.append(elements)
    if len(modules) != 1:
        raise ValueError("Review new module structure before exporting")
    source = modules[0]['module'].decode('utf-8-sig').replace('\r\n', '\n')
    pattern = r'(Узел\.КлючAPI\s*=\s*")[^"\n]+(")'
    source, count = re.subn(pattern, r'\g<1><LOCAL_B2B_CREDENTIAL>\2', source)
    token = r'(Функция ТокенПубличногоAPIKIT\(\)[\s\S]*?Возврат ")[^"\n]+(";)'
    source, tokens = re.subn(token, r'\g<1><LOCAL_PUBLIC_API_CREDENTIAL>\2', source)
    if (count, tokens) != (2, 1):
        raise ValueError("Credential layout changed; inspect before export")
    (ROOT/'src/Module.bsl').write_text(source, encoding='utf-8')
    (ROOT/'src/Form.txt').write_text(modules[0]['form'].decode('utf-8-sig').replace('\r\n','\n'),encoding='utf-8')

    if layout is None:
        raise ValueError("Missing data composition schema")
    _, count = struct.unpack_from('<II', layout)
    sizes = struct.unpack_from(f'<{count+1}Q', layout, 8)
    offset = 8 + 8 * len(sizes)
    folder = ROOT/'src/layout'
    folder.mkdir(exist_ok=True)
    for i, size in enumerate((*sizes, len(layout) - offset - sum(sizes))):
        xml = layout[offset:offset+size].decode('utf-8-sig')
        from xml.etree import ElementTree
        ElementTree.fromstring(xml)
        (folder/f'{i:02}.xml').write_text(xml.replace('\r\n','\n'),encoding='utf-8')
        offset += size
    if offset != len(layout):
        raise ValueError("Unexpected layout data")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('epf', type=Path)
    export(parser.parse_args().epf)
