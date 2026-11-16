#!/usr/bin/env python3
"""Small CPU-burning test program for exercising hamlet's profiler.

Runs a chain of nested function calls in a tight loop so the sampled
stack traces have a few recognizable frames (main -> foo -> bar).

Usage:
    python3 burn.py &
    cargo run --release -- --pid $!
"""


def bar(x):
    # Busy work with no syscalls, so the CPU stays pegged on this frame.
    total = 0
    for i in range(1000):
        total += (x * i) % 7919
    return total


def foo(x):
    return bar(x) + bar(x + 1)


def main():
    x = 0
    while True:
        x = foo(x) % 1000


if __name__ == "__main__":
    main()
