#!/usr/bin/env python3
"""Меню infra (infra-menu) в настоящем терминале: ждёт текст на экране и нажимает клавиши.
Для tests/scenarios.yml («6. Меню»), на сервере от root, только стандартный Python:

    python3 tests/menu.py <лог> <команда...> -- <ждать> <нажать> <ждать> <нажать> ...

Шаги парами: что ждать на экране (появилось после прошлого нажатия; пробелы не важны —
whiptail двигает курсор вместо пробелов) и что нажать: буквы как есть и {enter} {tab} {down}
{up} {esc} {ctrl-c}. После последнего шага — ждёт выхода команды. Код выхода — её код; текст
не появился за 5 минут — 99. Весь экран без управляющих последовательностей — в <лог>.
"""
import fcntl
import os
import pty
import re
import select
import struct
import sys
import termios
import time

KEYS = {"{enter}": "\r", "{tab}": "\t", "{down}": "\x1b[B", "{up}": "\x1b[A", "{esc}": "\x1b",
        "{ctrl-c}": "\x03"}
ESCAPES = re.compile(rb"\x1b(\[[0-?]*[ -/]*[@-~]|\][^\x07]*\x07|[()][0-9A-Za-z]|[=>78DEHMc])")
CONTROL = re.compile(rb"[\x00-\x08\x0b-\x1f\x7f]")
ROWS, COLS = 40, 120
TIMEOUT = 300                   # самое долгое — apply в «Сменить пароль базы»


def screen(raw):
    return CONTROL.sub(b"", ESCAPES.sub(b"", raw)).decode("utf-8", "replace")


def squash(text):
    return re.sub(r"\s+", "", text)


def keys(spec):
    for name, code in KEYS.items():
        spec = spec.replace(name, code)
    return spec.encode()


def main():
    log, args = sys.argv[1], sys.argv[2:]
    sep = args.index("--")
    command, steps = args[:sep], args[sep + 1:]
    if len(steps) % 2:
        sys.exit("шаги — парами: ждать, нажать")

    pid, fd = pty.fork()
    if pid == 0:
        fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
        os.environ["TERM"] = "xterm"
        os.execvp(command[0], command)

    out = bytearray()

    def read(timeout):
        """Дочитать, что есть; False — команда закрыла терминал"""
        ready, _, _ = select.select([fd], [], [], timeout)
        if ready:
            try:
                data = os.read(fd, 65536)
            except OSError:
                return False
            if not data:
                return False
            out.extend(data)
        return True

    def finish(code, why=""):
        with open(log, "w", encoding="utf-8") as f:
            f.write(screen(bytes(out)))
            if why:
                f.write(f"\n\n!!! {why}\n")
        sys.exit(code)

    mark = 0
    for wait, press in zip(steps[::2], steps[1::2]):
        deadline = time.monotonic() + TIMEOUT
        while squash(wait) not in squash(screen(bytes(out[mark:]))):
            if time.monotonic() > deadline or not read(0.2):
                finish(99, f"не дождались «{wait}» (дальше нажали бы {press!r})")
        mark = len(out)
        time.sleep(0.3)                  # whiptail дорисовал и ждёт клавиш
        os.write(fd, keys(press))

    deadline = time.monotonic() + TIMEOUT
    while read(0.2):
        if time.monotonic() > deadline:
            finish(99, "команда не завершилась после последнего шага")
    _, status = os.waitpid(pid, 0)
    finish(os.waitstatus_to_exitcode(status))


if __name__ == "__main__":
    main()
