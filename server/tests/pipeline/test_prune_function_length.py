"""The prune code stays in functions of at most 50 lines (docstring included), by AST line count."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import vigie_pipeline

SRC = Path(vigie_pipeline.__file__).parent
MAX_FUNCTION_LINES = 50
WHOLE_MODULES = ("prune.py", "prune_exclusions.py", "retirement.py", "overrides.py")
TOUCHED = (("processor.py", "run_once"), ("stitch_apply.py", "_attach"))


def lengths(name: str) -> dict[str, int]:
    tree = ast.parse((SRC / name).read_text())
    return {
        node.name: node.end_lineno - node.lineno + 1
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
    }


@pytest.mark.parametrize("module", WHOLE_MODULES)
def test_every_function_of_the_prune_modules_fits(module):
    too_long = {n: k for n, k in lengths(module).items() if k > MAX_FUNCTION_LINES}
    assert too_long == {}


@pytest.mark.parametrize(("module", "function"), TOUCHED)
def test_the_touched_functions_of_the_shared_modules_fit(module, function):
    assert lengths(module)[function] <= MAX_FUNCTION_LINES
