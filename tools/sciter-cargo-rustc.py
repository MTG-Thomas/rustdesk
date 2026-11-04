#!/usr/bin/env python3
"""Adapt Cargo 1.90's new check-cfg syntax to the pinned 2023 Sciter compiler.

The old Cargo never supplied these automatically generated declarations. Keep
all explicit compiler flags (including warnings/denied lints) and the original
compiler; only omit the new Cargo-generated check-cfg pairs it cannot parse.
"""

import subprocess
import sys


def compiler_arguments(arguments):
    result = []
    arguments = iter(arguments)
    for argument in arguments:
        if argument == "--check-cfg":
            if next(arguments, None) is None:
                raise ValueError("missing check-cfg declaration")
        else:
            result.append(argument)
    return result


if __name__ == "__main__":
    raise SystemExit(subprocess.call([sys.argv[1], *compiler_arguments(sys.argv[2:])]))
