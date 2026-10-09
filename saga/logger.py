"""
    Logger class for printing messages with colored tags
"""
import hashlib
import time

class Logger:
    """
    Logger class for printing messages with colored tags.
    This class provides methods to log messages with a timestamp and a tag.
    The tag is hashed to determine the color of the message.
    It supports different log levels such as warning and error.
    """
    COLORS = [
        "\033[91m",  # Red
        "\033[92m",  # Green
        "\033[93m",  # Yellow
        "\033[94m",  # Blue
        "\033[95m",  # Magenta
        "\033[96m",  # Cyan
        "\033[97m",  # White
    ]
    RESET = "\033[0m"

    @staticmethod
    def hash_tag(tag):
        """Hashes the tag and maps it to a color index."""
        return int(hashlib.md5(tag.encode()).hexdigest(), 16) % len(Logger.COLORS)

    @staticmethod
    def log(tag, message):
        """
        Prints a message to the console with a tag in the following format:
        hh:mm:ss [TAG] message

        Depending on the tag, the message will be printed in different colors.
        The tag is hashed in order to determine the color.
        """
        timestamp = time.strftime("%H:%M:%S")
        color = Logger.COLORS[Logger.hash_tag(tag)]
        print(f"{timestamp} {color}[{tag}]{Logger.RESET} {message}")
    
    @staticmethod
    def warn(message):
        """ Prints a warning message to the console with a timestamp."""
        timestamp = time.strftime("%H:%M:%S")
        color = Logger.COLORS[2]
        print(f"{timestamp} {color}[WARNING] {message} {Logger.RESET}")

    @staticmethod
    def error(message):
        """ Prints an error message to the console with a timestamp."""
        timestamp = time.strftime("%H:%M:%S")
        color = Logger.COLORS[0]
        print(f"{timestamp} {color}[ERROR] {message} {Logger.RESET}")
