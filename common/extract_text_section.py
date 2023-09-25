import argparse
from pathlib import Path

import lief


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
    parasite_got = parasite_binary.get_section(".got")

    start = parasite_text.offset
    num = parasite_text.size

    """
    .text is always aligned. however rodata might not be.
        .text          padding .rodata
        ==============|=======|============
        0  1  2  3  4 5 6    7 8  9  10  11
    total num = 12 bytes
              = 8 - 0 + len(rodata)
    """
    if parasite_rodata:
        num = parasite_rodata.size + parasite_rodata.offset - parasite_text.offset
        # if there is padding, it can at most be 15 bytes. This also implies these two
        # sections must be contigous.
        assert (
            num >= parasite_text.size + parasite_rodata.size
            and num <= parasite_text.size + parasite_rodata.size + 15
        ), f"There are other sections between rodata and text. text start:{parasite_text.offset} size:{parasite_text.size} rodata start:{parasite_rodata.offset} size:{parasite_rodata.size}"

    # for some reason clang 16 puts all symbol addresses in got even they are known at compile time.
    # copy over the got section as well.
    if parasite_got:
        num = parasite_got.size + parasite_got.offset - parasite_text.offset

    with open(args.output, "wb") as f:
        with open(args.input, "rb") as input:
            input.seek(start, 0)
            f.write(input.read(num))


if __name__ == "__main__":
    main()
