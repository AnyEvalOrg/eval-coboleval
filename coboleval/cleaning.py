"""Upstream chat construction, including its unconditional prompt append.

CommonMark fence parsing uses markdown-it-py instead of Marko. It takes the first
fence regardless of language, including nested, tilde and EOF-terminated fences.
"""
from markdown_it import MarkdownIt


def extract_code_block(src: str) -> str | None:
    for token in MarkdownIt("commonmark").parse(src):
        if token.type == "fence":
            return token.content
    return None


def swap_sections(src: str) -> str:
    """
    Swap the Working Storage and Linkage Sections
    """
    working_storage, linkage, procedure, begin = [], [], [], []
    current_section = begin

    for line in src.split("\n"):
        stripped_line = line.strip().upper()
        if stripped_line.startswith("WORKING-STORAGE SECTION."):
            current_section = working_storage
        elif stripped_line.startswith("LINKAGE SECTION."):
            current_section = linkage
        elif stripped_line.startswith("PROCEDURE DIVISION"):
            current_section = procedure
            line = "       PROCEDURE DIVISION USING LINKED-ITEMS."
        current_section.append(line)

    return "\n".join(begin + working_storage + linkage + procedure)


def construct(prompt: str, sol: str) -> str:
    if sol.strip().startswith("WORKING-STORAGE SECTION."):
        sol = sol.replace("WORKING-STORAGE SECTION.", "")

    prog = f"{prompt}\n{sol}"
    return swap_sections(prog)
