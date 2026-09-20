"""Synthetic fixtures pin the upstream chat path's non-obvious behavior."""
import pytest
from coboleval.cleaning import construct, extract_code_block, swap_sections

PROMPT = ('       IDENTIFICATION DIVISION.\n       PROGRAM-ID. FIXTURE.\n'
          '       DATA DIVISION.\n       LINKAGE SECTION.\n'
          '       01 LINKED-ITEMS.\n       WORKING-STORAGE SECTION.\n')


@pytest.mark.parametrize('source,expected', [
    ('plain text', None),
    ('```\nfirst\n```', 'first\n'),
    ('```COBOL\nfirst\n```\n```java\nsecond\n```', 'first\n'),
    ('```cobol\nunterminated', 'unterminated'),
    ('~~~cobol\nfirst\n~~~', 'first\n'),
    ('> ```cobol\n> nested\n> ```', 'nested\n'),
    ('- ```cobol\n  nested\n  ```', 'nested\n'),
    ('```cobol\n```', ''),
    ('    indented code\n', None),
    ('````cobol\n```\n````', '```\n'),
])
def test_first_commonmark_fence(source, expected):
    assert extract_code_block(source) == expected


def test_remainder_and_repeated_working_storage_header():
    remainder = ('WORKING-STORAGE SECTION.\n       01 TEMP PIC 9.\n'
                 '       PROCEDURE DIVISION.\n           GOBACK.')
    program = construct(PROMPT, remainder)
    assert program.count('WORKING-STORAGE SECTION.') == 1
    assert program.index('WORKING-STORAGE') < program.index('01 TEMP') < program.index('LINKAGE')
    assert '       PROCEDURE DIVISION USING LINKED-ITEMS.' in program
    assert program.endswith('           GOBACK.')
    assert 'END PROGRAM' not in program


def test_whole_program_still_appends_upstream_prompt():
    whole = ('       IDENTIFICATION DIVISION.\n       PROGRAM-ID. FIXTURE.\n'
             '       DATA DIVISION.\n       WORKING-STORAGE SECTION.\n'
             '       LINKAGE SECTION.\n       01 LINKED-ITEMS.\n'
             '       PROCEDURE DIVISION USING OTHER.\n           GOBACK.')
    program = construct(PROMPT, whole)
    assert program.count('IDENTIFICATION DIVISION.') == 2
    assert program.count('WORKING-STORAGE SECTION.') == 2
    assert program.count('LINKAGE SECTION.') == 2
    assert 'USING OTHER' not in program
    assert program == swap_sections(PROMPT + '\n' + whole)


def test_header_removal_is_case_sensitive_but_reordering_is_not():
    program = construct(PROMPT, 'working-storage section.\nprocedure division.\nGOBACK.')
    assert 'working-storage section.' in program
    assert program.index('working-storage section.') < program.index('LINKAGE')
    assert '       PROCEDURE DIVISION USING LINKED-ITEMS.' in program


def test_leading_header_removal_replaces_all_exact_occurrences():
    program = construct(PROMPT, 'WORKING-STORAGE SECTION.\nWORKING-STORAGE SECTION.\nPROCEDURE DIVISION.')
    assert program.count('WORKING-STORAGE SECTION.') == 1
