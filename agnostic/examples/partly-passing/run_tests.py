"""Runs the suite and writes a JUnit XML report, which is what `sv` reads.

`python:3.12-slim` has unittest and nothing else, and the container has no network to install a
runner from, so this writes the report itself. A real app passes `--junitxml` to pytest, or uses
gotestsum, jest-junit or surefire — `sv` only cares that JUnit XML lands where securevibe.toml
says it will, and that it is somewhere the runner can actually write.
"""

import os
import sys
import unittest
from xml.sax.saxutils import quoteattr

# `/app` is mounted read-only by `sv`, so the report goes to the one writable place it provides.
# Outside a `sv` run — running this by hand — fall back to a local folder.
REPORT = os.environ.get("JUNIT_REPORT") or (
    "/sv-reports/junit.xml" if os.path.isdir("/sv-reports") else "reports/junit.xml"
)


class Recording(unittest.TextTestResult):
    """Remembers how every test went, not only the ones that broke."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.outcomes = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.outcomes.append((test, None))

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.outcomes.append((test, "failure"))

    def addError(self, test, err):
        super().addError(test, err)
        self.outcomes.append((test, "error"))

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.outcomes.append((test, "skipped"))


result = unittest.TextTestRunner(verbosity=1, resultclass=Recording).run(
    unittest.defaultTestLoader.discover("tests")
)

os.makedirs(os.path.dirname(REPORT), exist_ok=True)
with open(REPORT, "w", encoding="utf-8") as out:
    out.write('<?xml version="1.0" encoding="utf-8"?>\n')
    out.write('<testsuite name="unittest" tests="%d">\n' % len(result.outcomes))
    for test, how in result.outcomes:
        name = quoteattr(test.id().rsplit(".", 1)[-1])
        classname = quoteattr(test.__class__.__name__)
        if how is None:
            out.write("  <testcase classname=%s name=%s/>\n" % (classname, name))
        else:
            out.write(
                "  <testcase classname=%s name=%s><%s message=%s/></testcase>\n"
                % (classname, name, how, quoteattr("see the run output"))
            )
    out.write("</testsuite>\n")

sys.exit(0 if result.wasSuccessful() else 1)
