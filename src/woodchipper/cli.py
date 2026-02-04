"""Command-line interface for woodchipper."""

import json
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
        "file",
        metavar="FILE",
        help="Path to a PDF file to process",
    )

    args = parser.parse_args()

    try:
        report = process(args.file)
        print(json.dumps(report, indent=2))
    except ValidationError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
