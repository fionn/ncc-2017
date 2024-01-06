#!/usr/bin/env python3
"""How many ways are there to eat a dish of 99999 french fries?"""

import sys

sys.set_int_max_str_digits(0)


def ff(n: int) -> int:
    """Number of ways of eating n fries, either one or two at a time"""
    a, b = 1, 1
    for _ in range(n):
        a, b = b, a + b
    return a


def main() -> None:
    """Entry point"""
    print(ff(99999))

if __name__ == "__main__":
    main()
