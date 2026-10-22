#!/usr/bin/env python3
import argparse
import json
import os
import random
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import frames

TOP = [
    "██╗  ██╗  █████╗   ██████╗ ██╗  ██╗ ██╗  ██╗ ███████╗ ██╗   ██╗ ███╗   ██╗",
    "██║  ██║ ██╔══██╗ ██╔════╝ ██║ ██╔╝ ██║  ██║ ██╔════╝ ██║   ██║ ████╗  ██║",
    "███████║ ███████║ ██║      █████╔╝  ███████║ █████╗   ██║   ██║ ██╔██╗ ██║",
    "██╔══██║ ██╔══██║ ██║      ██╔═██╗  ╚════██║ ██╔══╝   ██║   ██║ ██║╚██╗██║",
    "██║  ██║ ██║  ██║ ╚██████╗ ██║  ██╗      ██║ ██║      ╚██████╔╝ ██║ ╚████║",
    "╚═╝  ╚═╝ ╚═╝  ╚═╝  ╚═════╝ ╚═╝  ╚═╝      ╚═╝ ╚═╝       ╚═════╝  ╚═╝  ╚═══╝",
]

COLORS = {"white": "231", "blue": "39", "red": "196", "orange": "214"}
VERSION = "1.0"


def paint(text, color, enabled):
    if not enabled:
        return text
    return "\x1b[38;5;%sm%s\x1b[0m" % (COLORS[color], text)


def print_banner(stream, colors):
    for line in TOP[0:2]:
        stream.write(paint(line, "white", colors) + "\n")
    for line in TOP[2:4]:
        stream.write(paint(line, "blue", colors) + "\n")
    for line in TOP[4:6]:
        stream.write(paint(line, "red", colors) + "\n")
    stream.write(paint("  httpd core and mod_http2 fuzzers", "orange", colors) + "\n")
    stream.write(paint("  Made by Walter White (Lamer)", "orange", colors) + "\n")
    link = "  https://t.me/walterlamer"
    if colors:
        link = "\x1b[38;5;%sm\x1b[4m%s\x1b[0m" % (COLORS["orange"], link)
    stream.write(link + "\n\n")


def show_help(colors):
    lines = [
        "h2fuzz  %s" % VERSION,
        "",
        "Два харнесса: мутационный по парсеру HTTP/1.x и покадровый по h2c.",
        "",
        "Быстрый старт:",
        "  ./fuzzer.py -u http://127.0.0.1:8520 -m both -d 300",
        "  ./fuzzer.py -u http://127.0.0.1:8520 -m h2 -d 600 -t 4",
        "  ./fuzzer.py -u http://127.0.0.1:8520 -m http1 -l /tmp/httpd/error.log",
        "",
        "Режимы:",
        "  http1    мутации запросов: строка запроса, заголовки, chunked, длины",
        "  h2       покадровые мутации h2c: HPACK, CONTINUATION, padding, окна",
        "  both     оба режима поровну",
        "",
        "Флаги:",
        "  -u  --url        адрес цели, обязателен",
        "  -d  --duration   длительность прогона в секундах",
        "  -m  --mode       http1, h2 или both",
        "  -t  --threads    число одновременных соединений",
        "  -s  --seed       зерно генератора",
        "  -l  --log        путь к error_log для подсчёта падений",
        "  -j  --json       машинный вывод",
        "  -q  --quiet      без баннера и служебных строк",
        "  -p  --plain      без цветов",
        "  -V  --version    версия",
        "  -h  --help       эта справка",
        "",
        "Замечание:",
        "  Харнесс ищет падения. ASan на этом классе не помогает, счёт идёт по",
        "  AH00051 и AH00052 в логе MPM.",
        "",
        paint("Telegram: https://t.me/walterlamer", "orange", colors),
    ]
    print("\n".join(lines))


def parse_target(url):
    text = url.strip()
    if text.startswith("http://"):
        text = text[7:]
    elif text.startswith("https://"):
        text = text[8:]
    text = text.rstrip("/")
    if ":" in text:
        host, port = text.rsplit(":", 1)
        return host, int(port)
    return text, 80


def send_http(host, port, rng):
    body = frames.mutate(rng.choice(frames.http_seeds()), rng)
    try:
        stream = socket.create_connection((host, port), timeout=2.0)
    except OSError:
        return False
    stream.settimeout(0.3)
    try:
        offset = 0
        while offset < len(body):
            size = rng.randint(1, max(1, len(body) - offset))
            stream.sendall(body[offset:offset + size])
            offset += size
            if rng.random() < 0.6:
                break
        stream.sendall(body[offset:])
        try:
            stream.recv(4096)
        except OSError:
            pass
    except OSError:
        return False
    finally:
        if rng.random() < 0.3:
            try:
                stream.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            except OSError:
                pass
        stream.close()
    return True


def send_h2(host, port, rng):
    try:
        stream = socket.create_connection((host, port), timeout=2.0)
    except OSError:
        return False
    stream.settimeout(0.3)
    output = bytearray()
    output += frames.MAGIC
    pairs = [(4, rng.choice([0, 1, 100, 65535, 2 ** 31 - 1]))]
    for _ in range(rng.randint(0, 3)):
        pairs.append((rng.choice([1, 2, 3, 5, 6]), rng.randrange(1 << 32)))
    output += frames.build_settings(pairs)

    stream_id = 1
    for _ in range(rng.randint(1, 6)):
        block = frames.random_block(rng)
        if rng.random() < 0.35 and len(block) > 8:
            split = rng.randrange(1, len(block) - 1)
            output += frames.build_frame(1, 0x0, stream_id, block[:split])
            rest = block[split:]
            while rest:
                size = rng.randrange(1, len(rest) + 1)
                output += frames.build_frame(9, 0x4 if size == len(rest) else 0x0, stream_id, rest[:size])
                rest = rest[size:]
        else:
            output += frames.build_frame(1, 0x4, stream_id, block)
        if rng.random() < 0.6:
            pad = rng.randrange(0, 256)
            payload = bytes([pad]) + os.urandom(rng.randint(0, 256)) + b"\x00" * pad
            output += frames.build_frame(0, 0x8 | (0x1 if rng.random() < 0.4 else 0x0), stream_id, payload)
        if rng.random() < 0.3:
            output += frames.build_frame(8, 0, rng.choice([0, stream_id]), struct.pack(">I", rng.choice([0, 1, 2 ** 31 - 1])))
        if rng.random() < 0.25:
            output += frames.build_frame(3, 0, stream_id, struct.pack(">I", rng.randrange(0, 16)))
        if rng.random() < 0.15:
            output += frames.build_frame(2, 0, stream_id, struct.pack(">I", rng.randrange(0, 1 << 31)) + b"\x00")
        stream_id += 2

    output += frames.random_frames(rng, rng.randint(0, 6))

    try:
        stream.sendall(bytes(output))
        try:
            stream.recv(4096)
        except OSError:
            pass
    except OSError:
        return False
    finally:
        if rng.random() < 0.25:
            try:
                stream.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            except OSError:
                pass
        stream.close()
    return True


def read_log(path, offset):
    if not path or not os.path.exists(path):
        return offset, 0
    with open(path, "rb") as handle:
        handle.seek(offset)
        chunk = handle.read()
        offset = handle.tell()
    text = chunk.decode("utf-8", "ignore")
    return offset, text.count("AH00051") + text.count("AH00052")


def run_fuzz(host, port, duration, threads, mode, seed, log_path):
    offset = 0
    if log_path and os.path.exists(log_path):
        offset = os.path.getsize(log_path)
    stopped = time.time() + duration
    counters = {"http1": 0, "h2": 0, "fail": 0}
    lock = threading.Lock()

    def worker(index):
        rng = random.Random((seed or time.time()) + index)
        while time.time() < stopped:
            use_http = mode == "http1" or (mode == "both" and rng.random() < 0.5)
            ok = send_http(host, port, rng) if use_http else send_h2(host, port, rng)
            with lock:
                if not ok:
                    counters["fail"] += 1
                elif use_http:
                    counters["http1"] += 1
                else:
                    counters["h2"] += 1

    with ThreadPoolExecutor(max_workers=threads) as pool:
        for index in range(threads):
            pool.submit(worker, index)

    offset, crashes = read_log(log_path, offset)
    counters["crash"] = crashes
    return counters


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-u", "--url")
    parser.add_argument("-d", "--duration", type=float, default=300.0)
    parser.add_argument("-m", "--mode", default="both")
    parser.add_argument("-t", "--threads", type=int, default=1)
    parser.add_argument("-s", "--seed", type=int)
    parser.add_argument("-l", "--log")
    parser.add_argument("-j", "--json", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("-p", "--plain", action="store_true")
    parser.add_argument("-V", "--version", action="store_true")
    parser.add_argument("-h", "--help", action="store_true")
    arguments = parser.parse_args()

    colors = (not arguments.plain) and (not os.environ.get("NO_COLOR")) and sys.stdout.isatty()
    banner_stream = sys.stderr if (arguments.json or arguments.quiet) else sys.stdout

    if arguments.help:
        print_banner(banner_stream, colors)
        show_help(colors)
        return 0
    if arguments.version:
        print_banner(banner_stream, colors)
        print("h2fuzz %s" % VERSION)
        return 0
    if not arguments.url:
        print_banner(banner_stream, colors)
        print("нужен адрес цели: -u http://host:port", file=sys.stderr)
        return 2

    print_banner(banner_stream, colors)
    host, port = parse_target(arguments.url)
    if not arguments.quiet:
        print("цель %s, режим %s, потоков %d, длительность %.0f с" % (arguments.url, arguments.mode, arguments.threads, arguments.duration))

    counters = run_fuzz(host, port, arguments.duration, arguments.threads, arguments.mode, arguments.seed, arguments.log)
    counters["target"] = arguments.url

    if arguments.json:
        print(json.dumps(counters))
    elif not arguments.quiet:
        print("http1: %d, h2: %d, отказов: %d, падений: %d" % (counters["http1"], counters["h2"], counters["fail"], counters["crash"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
