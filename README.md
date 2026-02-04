# Woodchipper

A Python library and CLI tool.

## Installation

```bash
pip install woodchipper
```

## Usage

### As a CLI

```bash
woodchipper "your input"
```

### As a library

```python
from woodchipper import process

result = process("your input")
```

## Development

Install in editable mode with dev dependencies:

```bash
pip install -e ".[dev]"
```

Run tests:

```bash
pytest
```
