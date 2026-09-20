COBOLEval data, chat prompt, section construction and result comparison derive
from zorse-project/COBOLEval, commit
0bb96c3114bb2bb28e221e9d6000614781f8609d (MIT).
UPSTREAM-LICENSE is retained verbatim. New package work is MIT under LICENSE.

Sandbox supervision, execution transport, comparison.py, publication filtering,
Helm chart, image definition, build/verification scripts and regression tests are
adapted from the reviewed local AnyEval eval-cobol-javatrans package, version 1.0.0.
Its Apache-2.0 license and attribution are retained as TEMPLATE-LICENSE and
TEMPLATE-NOTICE.md; those reused portions remain subject to that license.
Changes adapt the task to a single COBOL completion task, upstream chat assembly,
146 records, and explanation-only compilation evidence. Markdown fence parsing
uses markdown-it-py in CommonMark mode instead of upstream Marko.
