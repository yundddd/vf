import shutil
import lief
import argparse
from pathlib import Path
import os


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--input", type=str, required=True)
    parser.add_argument("--output", type=str, required=True)

    args = parser.parse_args()

    if not Path(args.input).exists():
        raise Exception(f"Input file {args.input} doesn't exist")

    parasite_binary = lief.parse(args.input)

    parasite_rodata = parasite_binary.get_section(".rodata")
    parasite_text = parasite_binary.get_section(".text")

    start = parasite_text.offset
    num = parasite_text.size
    if parasite_rodata:
        num = num + parasite_rodata.offset - parasite_text.offset
    # TO-DO: add validation so that text and rodata are next to each other.
    with open(args.output, "wb") as f:
        with open(args.input, "rb") as input:
            input.seek(start, 0)
            f.write(input.read(num))


if __name__ == "__main__":
    main()
