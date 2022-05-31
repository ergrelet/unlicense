import logging

import lief  # type: ignore


def setup_logger(logger: logging.Logger, verbose: bool) -> None:
    lief.logging.disable()
    if verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logger.setLevel(log_level)

    # Create a console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(log_level)

    ch.setFormatter(CustomFormatter())

    logger.addHandler(ch)


class CustomFormatter(logging.Formatter):

    grey = "\x1b[38;20m"
    green = "\x1b[1;32m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format_problem_str = "%(levelname)s - %(message)s"

    FORMATS = {
        logging.DEBUG: grey + "%(levelname)s - %(message)s" + reset,
        logging.INFO: green + "%(levelname)s" + reset + " - %(message)s",
        logging.WARNING: yellow + format_problem_str + reset,
        logging.ERROR: red + format_problem_str + reset,
        logging.CRITICAL: bold_red + format_problem_str + reset
    }

    def format(self, record: logging.LogRecord) -> str:
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)
