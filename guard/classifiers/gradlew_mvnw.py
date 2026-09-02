"""./gradlew / ./mvnw: a narrow allowlist of side-effect-free build goals.

Unlike docker/kubectl/git, a build wrapper executes arbitrary project-defined
Gradle/Maven plugin code -- "read-only" isn't a property of a goal name the
way it is for e.g. `docker ps`, since a custom task named `test` could do
anything the build file says. Auto-allowing here is a trust decision about
the build tooling, not a provable-safe classification (issue #15).

To keep that trust decision narrow: EVERY operand must be either a goal in
``SAFE_GOALS`` or a flag in the small allowlist below. One unrecognized goal
or flag anywhere -> deny. Widen ``SAFE_GOALS`` deliberately; anything
resembling publish/release/deploy/*:apply must stay out.

These commands do write to build/ or target/ as a side effect -- not a temp
dir, so this isn't a `tmpwrite`-style confined write, just an accepted
byproduct of compiling/testing in place.
"""

import re
from typing import List

from .base import ALLOW, Result, deny

NAMES = ("./gradlew", "./mvnw")

# Exact goal/task names proven side-effect-free beyond build/ or target/.
SAFE_GOALS = {
    # Gradle tasks.
    "compileKotlin", "compileTestKotlin", "test", "spotlessCheck",
    "dependencyInsight", "dependencies",
    # Maven goals.
    "dependency:tree",
}

# Flags proven not to redirect execution to an unsafe goal or write outside
# build/ or target/. Anything else -> deny.
_NOARG_FLAGS = {"-q", "--quiet"}
_VALUE_FLAGS = {"--tests", "-pl", "--projects"}
_DPROP_RE = re.compile(r"^-D[A-Za-z0-9_.]+=.*$")


def classify(tokens: List[str]) -> Result:
    args = tokens[1:]
    saw_goal = False
    i = 0
    n = len(args)
    while i < n:
        t = args[i]
        if t in _NOARG_FLAGS:
            i += 1
            continue
        if t in _VALUE_FLAGS:
            i += 2
            continue
        if any(t.startswith(f + "=") for f in _VALUE_FLAGS):
            i += 1
            continue
        if _DPROP_RE.match(t):
            i += 1
            continue
        if t.startswith("-"):
            return deny(f"unrecognized flag: {t}")
        if t not in SAFE_GOALS:
            return deny(f"goal not in the safe set: {t}")
        saw_goal = True
        i += 1
    if not saw_goal:
        return deny("no goal given (bare or flags-only runs the default task)")
    return ALLOW
