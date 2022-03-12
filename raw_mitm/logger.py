import logging
import json

filename = json.load(open("config.json", "r")).get("logfile")
logging.basicConfig(
    filename=filename,
    level=logging.INFO,
    format="[%(levelname)s] [%(asctime)s] %(message)s"
)

_logger = logging.getLogger(__name__)

class Colors:
    RED = "\033[91m"
    BLUE = "\033[94m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    PURPLE = "\033[95m"
    BOLD = "\033[1m"
    ENDC = "\033[0m"

class Logger:
    @staticmethod
    def get_symbol(symbol="*", color=Colors.YELLOW) -> str:
        return f"{color}[{symbol}]{Colors.ENDC}"

    @staticmethod
    def info(msg: str, bold=False):
        _logger.info(msg)
        if bold:
            print(f"{Logger.get_symbol()} {Colors.BOLD}{msg}{Colors.ENDC}")
            return None

        print(f"{Logger.get_symbol()} {msg}")

    @staticmethod
    def success(msg: str):
        _logger.info(msg)
        print(f"{Logger.get_symbol(symbol='+')} {Colors.GREEN}{msg}{Colors.ENDC}")

    @staticmethod
    def warning(msg: str):
        _logger.warning(msg)
        print(f"{Logger.get_symbol()} {Colors.YELLOW}{msg}{Colors.ENDC}")

    @staticmethod
    def error(msg: str):
        _logger.error(msg)
        print(f"{Logger.get_symbol(symbol='-')} {Colors.RED}{msg}{Colors.ENDC}")

    @staticmethod
    def custom(msg: str, line_break=False, symbol="*", color=Colors.PURPLE):
        custom_msg = msg
        if line_break:
            custom_msg += '\n'
        _logger.info(custom_msg)

        if not color:
            print(f"{Logger.get_symbol(symbol='{symbol}')} {msg}")
            return None

        print(f"{Logger.get_symbol(symbol='{symbol}')} {color}{msg}{Colors.ENDC}")
