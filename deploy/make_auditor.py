"""Assemble, and prove, the file set the deployed auditor service is built from.

The deployment rule for this project is that a viewer must not be able to make a
decision. It is one thing to write that down and another to keep it true after
the repository grows. This script is the kept-true version: it writes the
service directory (``auditor-service/``) from the modules the console actually
imports, and with ``--check`` it recomputes that set from the source, rebuilds
into a temporary directory, and fails if the committed copy has drifted, if the
dependency list no longer matches what is imported, or if the start command
names anything but report mode. The blueprint at the repository root
(``render.yaml``) is screened the same way, and must start the exact command
the ``Procfile`` runs.

Run it from anywhere; paths are resolved from this file.

    python deploy/make_auditor.py            # write auditor-service/
    python deploy/make_auditor.py --check    # prove it, change nothing
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "deploy" / "auditor"
SERVICE = ROOT / "auditor-service"
# Render's blueprint has to sit at the repository root, so it is the one copy of
# the start command that is not inside the deployed tree.
BLUEPRINT = ROOT / "render.yaml"

# The whole program. Anything not listed here is not in the service.
APP_MODULES = (
    "approval.py",
    "audit.py",
    "console.py",
    "evidence.py",
    "gateway.py",
    "policy.py",
    "providers.py",
    "risk_engine.py",
)

# Top-level modules deliberately left out. These are the decision-making and
# human-facing halves of the project; a new one shows up in --check until
# somebody decides which list it belongs on.
NOT_SHIPPED = frozenset({
    "main.py", "tools.py", "llm.py", "mcp_server.py", "conversation.py",
    "run_tests.py",
})

# Imported by the service, but only inside a function, so a minimal install
# works without the model SDK. If one moves to module scope, the service gains
# a dependency it does not need and the check fails.
LAZY_ONLY = frozenset({"google"})

# Third-party distribution name -> import name, for requirements.txt.
DISTRIBUTIONS = {"cryptography": "cryptography", "pyyaml": "yaml"}

SERVICE_FILES = ("Dockerfile", "Procfile", "README.md", "requirements.txt")


def imported_names(source: str, path: str) -> tuple[set[str], set[str]]:
    """Return ``(all imported roots, roots imported at module scope)``."""
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:  # pragma: no cover - CI parses these already
        raise SystemExit(f"{path}: does not parse ({exc})") from None

    def roots_of(node: ast.Import | ast.ImportFrom) -> set[str]:
        if isinstance(node, ast.Import):
            return {alias.name.split(".")[0] for alias in node.names}
        if node.level:  # a relative import: not a package name
            return set()
        return {node.module.split(".")[0]} if node.module else set()

    every: set[str] = set()
    top_level: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            every |= roots_of(node)
    # A class body runs at import time; a function body does not. Descent stops
    # at def/lambda, so an import inside a method is not counted as eager.
    stack = list(tree.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            top_level |= roots_of(node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        else:
            stack.extend(ast.iter_child_nodes(node))
    return every, top_level


def closure() -> tuple[set[str], set[str], set[str], set[str]]:
    """Walk console.py's local imports.

    Returns ``(local modules reached, third-party roots, module-scope roots,
    top-level modules that are neither shipped nor knowingly left out)``.
    """
    stdlib = set(sys.stdlib_module_names)
    local_files = {path.name: path for path in ROOT.glob("*.py")}
    left_out = {
        name for name in local_files
        if name not in APP_MODULES and name not in NOT_SHIPPED
    }

    reached: set[str] = set()
    third_party: set[str] = set()
    module_scope: set[str] = set()
    queue = ["console.py"]
    while queue:
        name = queue.pop()
        if name in reached or name not in local_files:
            continue
        reached.add(name)
        source = local_files[name].read_text(encoding="utf-8")
        every, top = imported_names(source, name)
        module_scope |= top
        for root_name in sorted(every):
            if root_name in stdlib:
                continue
            candidate = f"{root_name}.py"
            if candidate in local_files:
                queue.append(candidate)
                continue
            if root_name in {"deploy", "build", "dist"}:
                continue
            third_party.add(root_name)
    return reached, third_party, module_scope, left_out


def required_distributions() -> set[str]:
    text = (SOURCE / "requirements.txt").read_text(encoding="utf-8")
    return {
        line.split("==")[0].split(">=")[0].split("<")[0].strip().lower()
        for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    }


def _start_command_problems(name: str, text: str) -> list[str]:
    """The one command the service starts with, checked for a decision path."""
    problems: list[str] = []
    if "--serve-reports" not in text:
        problems.append(f"{name} does not start the console in report mode")
    for forbidden in ("--report ", "--policy ", "main.py", "mcp_server.py",
                      "tools.py", "llm.py"):
        if forbidden in text:
            problems.append(
                f"{name} mentions {forbidden.strip()!r}, which would give the "
                "deployed service a decision path"
            )
    if "COPY ." in text:
        problems.append(f"{name} copies the whole repository into the image")
    return problems


def _blueprint_problems(start_command: str) -> list[str]:
    """render.yaml is the same service on a host that needs no container."""
    if not BLUEPRINT.is_file():
        return ["render.yaml is missing from the repository root"]
    text = BLUEPRINT.read_text(encoding="utf-8")
    problems = _start_command_problems("render.yaml", text)
    for needle, why in (
        (f"rootDir: {SERVICE.name}",
         "render.yaml deploys some directory other than the generated one"),
        ("plan: free", "render.yaml asks for an instance that costs money"),
        ("runtime: python",
         "render.yaml no longer builds a plain Python service, so the deployed "
         "tree is not the one the tests launched"),
    ):
        if needle not in text:
            problems.append(why)
    match = re.search(r"^\s*startCommand:\s*(.+?)\s*$", text, re.M)
    if match is None:
        problems.append("render.yaml names no start command")
    elif match.group(1) != start_command:
        problems.append(
            f"render.yaml starts with {match.group(1)!r}, which is not the "
            "command the Procfile runs and the tests launch with"
        )
    return problems


def check() -> list[str]:
    """Return every reason the deployed service is not what it claims to be."""
    problems: list[str] = []
    reached, third_party, module_scope, left_out = closure()

    if left_out:
        problems.append(
            f"{', '.join(sorted(left_out))} is a new top-level module. If the "
            "console needs it, add it to APP_MODULES; if it must never be "
            "deployed, add it to NOT_SHIPPED; either way the choice is made "
            "out loud rather than by a copy line."
        )

    expected = set(APP_MODULES)
    if reached != expected:
        missing = expected - reached
        extra = reached - expected
        if missing:
            problems.append(
                "copied but not imported by the console: "
                f"{', '.join(sorted(missing))}"
            )
        if extra:
            problems.append(
                "imported by the console but not in APP_MODULES, so it would be "
                f"missing from the service: {', '.join(sorted(extra))}"
            )

    allowed = set(DISTRIBUTIONS.values()) | LAZY_ONLY
    if not third_party <= allowed:
        problems.append(
            "the service would need packages it does not install: "
            f"{', '.join(sorted(third_party - allowed))}"
        )
    for dist in DISTRIBUTIONS:
        if dist not in required_distributions():
            problems.append(f"requirements.txt does not install {dist!r}")

    if module_scope & LAZY_ONLY:
        problems.append(
            f"{', '.join(sorted(module_scope & LAZY_ONLY))} is imported at "
            "module scope. It is allowed only inside a function, so an install "
            "without the model SDK still works."
        )

    for name in SERVICE_FILES:
        if not (SOURCE / name).is_file():
            problems.append(f"deploy/auditor/{name} is missing")
    # Only the two start commands are screened for a decision path: the card
    # quotes `ssm --report` on purpose, and that is not a command it runs.
    for name in ("Procfile", "Dockerfile"):
        problems += _start_command_problems(name, (SOURCE / name).read_text(
            encoding="utf-8"))
    procfile = (SOURCE / "Procfile").read_text(encoding="utf-8")
    if "$PORT" not in procfile:
        problems.append("the Procfile does not bind the port the host assigns")
    if not procfile.startswith("web: "):
        problems.append("the Procfile has no `web:` process")
    else:
        problems += _blueprint_problems(procfile.strip()[len("web: "):])

    problems += _staged_problems()
    return problems


def _digests(directory: Path) -> dict[str, str]:
    return {
        str(path.relative_to(directory)).replace("\\", "/"):
            hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(directory.rglob("*")) if path.is_file()
    }


def _staged_problems() -> list[str]:
    """Is auditor-service/ still an exact copy of what this script writes?"""
    if not SERVICE.is_dir():
        return [f"{SERVICE.name}/ is missing; run python deploy/make_auditor.py"]
    staging = Path(tempfile.mkdtemp()) / "service"
    try:
        stage(staging)
        built, committed = _digests(staging), _digests(SERVICE)
    finally:
        shutil.rmtree(staging.parent, ignore_errors=True)
    problems = []
    for name in sorted(set(committed) - set(built)):
        problems.append(f"{SERVICE.name}/{name} is in the deployed directory "
                        "but is not generated from anything")
    for name in sorted(set(built) - set(committed)):
        problems.append(f"{SERVICE.name}/{name} is missing from the deployed "
                        "directory")
    for name in sorted(set(built) & set(committed)):
        if built[name] != committed[name]:
            problems.append(f"{SERVICE.name}/{name} differs from its source in "
                            "deploy/auditor/ or the repository root")
    return problems


def stage(dest: Path) -> Path:
    """Write the service tree into an empty directory."""
    (dest / "app").mkdir(parents=True, exist_ok=True)
    for name in APP_MODULES:
        shutil.copy2(ROOT / name, dest / "app" / name)
    for name in SERVICE_FILES:
        shutil.copy2(SOURCE / name, dest / name)
    return dest


def build() -> Path:
    if SERVICE.exists():
        shutil.rmtree(SERVICE)
    SERVICE.mkdir()
    return stage(SERVICE)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog=__name__,
        description="Stage and prove the deployed auditor service.")
    parser.add_argument("--check", action="store_true",
                        help="prove the deployed file set, change nothing")
    args = parser.parse_args(argv)

    if args.check:
        problems = check()
    else:
        # Generate first, then prove the copy that was just made. Repairing a
        # drifted tree is this command's job; --check never writes.
        dest = build()
        print(f"wrote {dest}")
        problems = check()
    if problems:
        print("deployed auditor service is NOT ready:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    reached, _, _, _ = closure()
    print(f"auditor service checks pass: {len(reached)} modules, "
          f"{len(required_distributions())} dependencies, "
          f"{len(_digests(SERVICE))} files in {SERVICE.name}/")
    if args.check:
        return 0
    print("  " + " ".join(SERVICE_FILES) + f"  app/{', '.join(APP_MODULES)}")
    print(f"point the host's repository root directory at {SERVICE.name}/; "
          "render.yaml in the repository root already does that for Render")
    return 0


if __name__ == "__main__":
    sys.exit(main())
