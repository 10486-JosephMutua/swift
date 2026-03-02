import logging
import logging.handlers
import sys
from pathlib import Path

COLORS = {
    "DEBUG":    "\033[36m",
    "INFO":     "\033[32m",
    "WARNING":  "\033[33m",
    "ERROR":    "\033[31m",
    "CRITICAL": "\033[35m",
    "RESET":    "\033[0m",
}


class ColoredFormatter(logging.Formatter):
    FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-35s | %(message)s"

    def format(self, record: logging.LogRecord) -> str:
        color = COLORS.get(record.levelname, COLORS["RESET"])
        reset = COLORS["RESET"]
        fmt   = logging.Formatter(f"{color}{self.FORMAT}{reset}", datefmt="%Y-%m-%d %H:%M:%S")
        return fmt.format(record)


class PlainFormatter(logging.Formatter):
    FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-35s | %(message)s"

    def __init__(self):
        super().__init__(fmt=self.FORMAT, datefmt="%Y-%m-%d %H:%M:%S")


def setup_logging(level: str = "DEBUG") -> None:
    log_dir       = Path("logs")
    log_dir.mkdir(exist_ok=True)
    numeric_level = getattr(logging, level.upper(), logging.DEBUG)
    root          = logging.getLogger("swiftaudit")
    root.setLevel(numeric_level)

    if root.handlers:
        return

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(numeric_level)
    console.setFormatter(ColoredFormatter())
    root.addHandler(console)

    file_h = logging.handlers.RotatingFileHandler(
        filename=log_dir / "swiftaudit.log",
        maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8",
    )
    file_h.setLevel(logging.DEBUG)
    file_h.setFormatter(PlainFormatter())
    root.addHandler(file_h)

    err_h = logging.handlers.RotatingFileHandler(
        filename=log_dir / "swiftaudit_errors.log",
        maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8",
    )
    err_h.setLevel(logging.ERROR)
    err_h.setFormatter(PlainFormatter())
    root.addHandler(err_h)

    root.info("=" * 70)
    root.info("[LOGGER] Logging initialized")
    root.info(f"[LOGGER] Level    : {level.upper()}")
    root.info(f"[LOGGER] Log file : {log_dir.absolute()}/swiftaudit.log")
    root.info("=" * 70)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"swiftaudit.{name}")
