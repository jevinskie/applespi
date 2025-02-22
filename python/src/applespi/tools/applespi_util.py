#!/usr/bin/env python3

import argparse

from rich import print


def get_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="applespi-py-util")
    return parser


def real_main(args: argparse.Namespace):
    print(f"args: {args}")


def main():
    parser = get_arg_parser()
    args = parser.parse_args()
    real_main(args)


if __name__ == "__main__":
    main()
