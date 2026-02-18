"""Command-line interface for woodchipper."""

import json
import logging
import signal
import sys
import argparse

from . import __version__
from .core import process, ValidationError


def main() -> None:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="woodchipper",
        description="Process PDF files and output analysis as JSON.",
    )
    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging to stderr",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=0,
        metavar="SECONDS",
        help="Abort processing after SECONDS (0 = disabled)",
    )
    parser.add_argument(
        "file",
        metavar="FILE",
        help="Path to a PDF file to process",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(
            level=logging.INFO,
            stream=sys.stderr,
            format="%(name)s: %(message)s",
        )

    if args.timeout > 0:
        if not hasattr(signal, "SIGALRM"):
            print(
                "Warning: --timeout is not supported on this platform",
                file=sys.stderr,
            )
        else:
            def _timeout_handler(signum, frame):
                raise TimeoutError(
                    f"Processing timed out after {args.timeout} seconds"
                )

            signal.signal(signal.SIGALRM, _timeout_handler)
            signal.alarm(args.timeout)

    try:
        report = process(args.file)
        print(json.dumps(report, indent=2))
    except ValidationError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except TimeoutError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)
    finally:
        if args.timeout > 0 and hasattr(signal, "SIGALRM"):
            signal.alarm(0)
