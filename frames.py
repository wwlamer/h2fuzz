import os
import random
import struct

MAGIC = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
METHODS = {"GET": 2, "POST": 3}
PATHS = {"/": 4, "/index.html": 5}
TYPES = list(range(12))


def build_frame(kind, flags, stream, payload=b""):
    length = struct.pack(">I", len(payload))[1:]
    return length + bytes([kind, flags]) + struct.pack(">I", stream & 0x7fffffff) + payload


def build_settings(pairs):
    body = b"".join(struct.pack(">HI", key, value & 0xffffffff) for key, value in pairs)
    return build_frame(4, 0, 0, body)


def encode_int(value, bits, mask):
    limit = (1 << bits) - 1
    if value < limit:
        return bytes([mask | value])
    output = bytearray([mask | limit])
    value -= limit
    while value >= 128:
        output.append((value & 0x7f) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def encode_string(text):
    raw = text.encode()
    return encode_int(len(raw), 7, 0x00) + raw


def encode_block(method, path, extra):
    block = bytearray()
    index = METHODS.get(method)
    if index:
        block.append(0x80 | index)
    else:
        block += encode_int(0, 4, 0x40) + encode_string(method)
    block.append(0x86)
    block += encode_int(1, 4, 0x40) + encode_string("localhost")
    index = PATHS.get(path)
    if index:
        block.append(0x80 | index)
    else:
        block += encode_int(4, 4, 0x40) + encode_string(path)
    for name, value in extra:
        block += encode_int(0, 4, 0x40) + encode_string(name) + encode_string(value)
    return bytes(block)


def random_block(rng):
    extra = []
    for _ in range(rng.randint(0, 5)):
        name = rng.choice(["x-a", "cookie", "content-length", "range", "if-match", "x" * rng.randint(1, 40)])
        value = rng.choice(["", "0", "-1", str(2 ** 31), str(2 ** 63 - 1), "a" * rng.randint(1, 900), "chunked, chunked", "*/*"])
        extra.append((name, value))
    method = rng.choice(["GET", "POST", "HEAD", "PUT", "OPTIONS", "PATCH", "G" * rng.randint(1, 30)])
    path = rng.choice(["/", "/index.html", "/" + "a" * rng.randint(1, 2000), "/?q=" + "b" * rng.randint(1, 200)])
    return encode_block(method, path, extra)


def random_frames(rng, count):
    output = bytearray()
    for _ in range(count):
        kind = rng.choice(TYPES)
        flags = rng.randrange(256)
        stream = rng.choice([0, 1, 3, 5, rng.randrange(0, 1 << 31)])
        size = rng.choice([0, 1, 8, 64, 512, rng.randrange(0, 1024)])
        payload = os.urandom(size)
        output += build_frame(kind, flags, stream, payload)
    return bytes(output)


def http_seeds():
    return [
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET /index.html HTTP/1.1\r\nHost: x\r\nUser-Agent: a\r\nAccept: */*\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        b"HEAD / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n",
        b"OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET /%2e%2e/%2e%2e/etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\nabcd",
    ]


def mutate(data, rng):
    buffer = bytearray(data)
    for _ in range(rng.randint(1, 12)):
        if not buffer:
            buffer = bytearray(b"A")
        position = rng.randrange(len(buffer))
        action = rng.randrange(9)
        if action == 0:
            buffer[position] ^= 1 << rng.randrange(8)
        elif action == 1:
            buffer[position] = rng.randrange(256)
        elif action == 2:
            buffer[position:position] = os.urandom(rng.randint(1, 16))
        elif action == 3 and len(buffer) > 2:
            del buffer[position:position + rng.randint(1, 16)]
        elif action == 4:
            size = rng.randint(1, 32)
            buffer[position:position] = bytes(buffer[position:position + size])
        elif action == 5:
            buffer[position:position] = b"A" * rng.randint(100, 8000)
        elif action == 6:
            buffer[position:position] = rng.choice([b"\r\n", b":", b" ", b"\x00", b"\r", b"\n"])
        elif action == 7:
            buffer[position:position] = str(rng.choice([2 ** 31 - 1, 2 ** 31, 2 ** 32 - 1, 2 ** 63 - 1, -1, 0, 10 ** 20])).encode()
        else:
            buffer[position:position] = rng.choice([b"ffffffffffffffff\r\n", b"0\r\n", b"\r\n0\r\n\r\n", b"-1\r\n"])
    return bytes(buffer)
