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
    parasite_text = parasite_binary.get_section(".text")

    with open(args.output, "wb") as f:
        f.write(bytes(parasite_text.content))


if __name__ == "__main__":
    main()
