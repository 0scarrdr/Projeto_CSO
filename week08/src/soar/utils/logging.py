from rich.logging import RichHandler
import logging, os
def get_logger(name: str):
    logging.basicConfig(level=os.getenv("LOG_LEVEL","INFO"),
                        format="%(message)s", handlers=[RichHandler(rich_tracebacks=True)])
    return logging.getLogger(name)
