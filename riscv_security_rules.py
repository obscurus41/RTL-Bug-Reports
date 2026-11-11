"""
RISC-V security-rules prompting strategy: runs one LLM query per matching
security rule in Code/Prompts/security_rules.jsonl for each design file.

Public API (required by run_llm.py):
   NAME            str
   DESCRIPTION     str
   configure(args) -> None
   build_prompt(file_path, file_contents) -> dict
"""

import json
import os


BASE_NAME = "riscv_security_rules"
NAME = BASE_NAME
DESCRIPTION = "RISC-V JSON security-rule guided: one query per matching rule."

RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_rules.jsonl")

_CONFIG = {
    "spec": None,
    "extension": None,
    "extensions": None,
}


SYSTEM_MESSAGE = """\
You are a hardware design verification expert reviewing RTL for compliance with \
the provided RISC-V security rule. Your task is to find concrete RTL bugs that \
violate ONLY the rule included in this prompt.

Do not use CWE categories for this review. Do not report issues based on RISC-V \
chapters, extensions, privileged architecture rules, unprivileged architecture \
rules, or general background knowledge unless the provided rule explicitly \
supports the requirement. If a suspected bug cannot be tied to this exact rule, \
do not report it.

If a fixed parameter configuration is included in this prompt, analyze only that \
configuration and do not report issues that depend on alternate parameter values."""


PROMPT_TEMPLATE = """\
{system_message}

===========================================================================
RISC-V SECURITY RULE TO CHECK AGAINST
===========================================================================

RULE ID        : {rule_id}
SPEC           : {spec}
SOURCE SECTION : {source_section}
CATEGORY       : {category}
SEVERITY       : {severity}
EXTENSIONS     : {extensions}
PAGE RANGE     : {page_range}

RULE TEXT:
{rule_text}
{context_section}
===========================================================================
RTL CODE TO REVIEW (PRIMARY TARGET)
===========================================================================

FILE: {file_path}

{file_contents}

===========================================================================
INSTRUCTIONS
===========================================================================

Review the PRIMARY TARGET RTL code above for bugs that violate the RISC-V \
security rule above. The supporting context files are provided only to help \
understand how the primary target fits into the larger design. Report bugs in \
the primary target file only.

For each reported issue:
1. Ground it in the RISC-V security rule included in this prompt.
2. Identify the exact RTL behavior that violates that rule.
3. Do not report style issues, speculative implementation choices, or bugs that \
   require a different RISC-V rule.
4. Do not report a bug unless the issue is visible in the RTL code and can be \
   justified from this exact rule.

For EACH potential issue you identify, produce an entry in this format:

BUG #<N> ({rule_id})
  Severity              : CRITICAL | HIGH | MEDIUM | LOW
  Location              : line <start>-<end>  (or "line <n>" for a single line)
  Code                  : <copy the exact buggy line(s) verbatim from the RTL, preserving indentation>
  Rule Requirement      : <quote or tightly paraphrase the specific rule from the provided rule text>
  Issue                 : <one sentence summary of the RISC-V compliance bug>
  Details               : <explain why the RTL violates the provided rule and what behavior would be wrong>

If you find NO issues tied to this exact rule, write a single line:

NO ISSUES FOUND FOR {rule_id}
"""


def configure(args) -> None:
    global NAME

    spec = args.riscv_spec
    extension = args.riscv_extension

    if spec == "priveleged":
        spec = "privileged"

    missing = []
    if not spec:
        missing.append("--riscv-spec")
    if not extension:
        missing.append("--riscv-extension")
    if missing:
        raise SystemExit(
            "riscv_security_rules requires "
            + " and ".join(missing)
            + " (example: --riscv-spec privileged --riscv-extension A)"
        )

    _CONFIG["spec"] = spec
    _CONFIG["extension"] = extension
    _CONFIG["extensions"] = _expand_extension_filter(extension)
    safe_extension = "".join(c if c.isalnum() else "_" for c in extension).strip("_")
    NAME = f"{BASE_NAME}_{spec}_{safe_extension}"


def _spec_matches(rule_spec):
    return _CONFIG["spec"] == "both" or rule_spec == _CONFIG["spec"]


def _expand_extension_filter(extension):
    normalized = extension.strip()
    upper = normalized.upper()

    # Keep exact catalog/module names usable, e.g. "Machine ISA" or
    # "Supervisor ISA", where compact ISA parsing would be inappropriate.
    if any(c.isspace() for c in normalized):
        return [normalized]

    expanded = []
    if upper.startswith(("RV32", "RV64")):
        base = upper[:4]
        remainder = normalized[4:]
        if remainder[:1].upper() in ("I", "E"):
            expanded.append(base + remainder[0].upper())
            remainder = remainder[1:]
        else:
            expanded.append(base + "I")

        compact, _, named_extensions = remainder.partition("_")
        if named_extensions:
            for letter in compact.upper():
                expanded.append(letter)
            for token in named_extensions.split("_"):
                if token:
                    expanded.append(_normalize_extension_name(token))
            return _dedupe(expanded)

        idx = 0
        while idx < len(compact):
            if compact[idx].upper() == "Z":
                end = idx + 1
                while end < len(compact) and not compact[end].isupper():
                    end += 1
                expanded.append(_normalize_extension_name(compact[idx:end]))
                idx = end
            else:
                expanded.append(compact[idx].upper())
                idx += 1
        return _dedupe(expanded)

    return [normalized]


def _normalize_extension_name(extension):
    if len(extension) == 1:
        return extension.upper()
    return extension[0].upper() + extension[1:].lower()


def _dedupe(values):
    deduped = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        deduped.append(value)
        seen.add(value)
    return deduped


def _load_matching_rules():
    if _CONFIG["spec"] is None or _CONFIG["extensions"] is None:
        raise RuntimeError("riscv_security_rules was not configured")
    if not os.path.isfile(RULES_PATH):
        raise FileNotFoundError(f"Missing RISC-V security rules file: {RULES_PATH}")

    rules = []
    with open(RULES_PATH, encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rule = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON in {RULES_PATH}:{line_no}: {exc}") from exc

            if not _spec_matches(rule.get("spec")):
                continue
            if not set(_CONFIG["extensions"]).intersection(rule.get("extensions") or []):
                continue
            rules.append(rule)

    if not rules:
        raise FileNotFoundError(
            "No RISC-V security rules matched "
            f"spec={_CONFIG['spec']} extensions={_CONFIG['extensions']!r}"
        )
    return rules


def _build_context_section(context_files):
    """Format supporting context files into a prompt section."""
    if not context_files:
        return ""
    parts = [
        "\n===========================================================================",
        "SUPPORTING CONTEXT (related modules in the design hierarchy)",
        "===========================================================================\n",
    ]
    for fname, contents in context_files:
        parts.append(f"FILE: {fname}\n")
        parts.append(contents)
        parts.append("")
    return "\n".join(parts) + "\n"


def _rule_value(rule, key, default=""):
    value = rule.get(key)
    if value is None:
        return default
    return value


def build_prompt(file_path: str, file_contents: str, context_files=None) -> dict:
    context_section = _build_context_section(context_files or [])
    queries = []

    for rule in _load_matching_rules():
        extensions = ", ".join(rule.get("extensions") or [])
        rule_id = _rule_value(rule, "rule_id", "UNKNOWN-RULE")
        prompt = PROMPT_TEMPLATE.format(
            system_message=SYSTEM_MESSAGE,
            rule_id=rule_id,
            spec=_rule_value(rule, "spec"),
            source_section=_rule_value(rule, "source_section"),
            category=_rule_value(rule, "category"),
            severity=str(_rule_value(rule, "severity")).upper(),
            extensions=extensions,
            page_range=_rule_value(rule, "_page_range", "unknown"),
            rule_text=_rule_value(rule, "rule_text"),
            context_section=context_section,
            file_path=file_path,
            file_contents=file_contents,
        )
        queries.append(
            {
                "cwe_id": rule_id,
                "riscv_rule_id": rule_id,
                "riscv_spec": _rule_value(rule, "spec"),
                "riscv_extension": _CONFIG["extension"],
                "riscv_extensions": _CONFIG["extensions"],
                "riscv_source_section": _rule_value(rule, "source_section"),
                "riscv_category": _rule_value(rule, "category"),
                "prompt": prompt,
                "section_header": (
                    f"{rule_id} - {_rule_value(rule, 'source_section', 'Unknown section')}"
                ),
            }
        )

    return {
        "is_multi_query": True,
        "queries": queries,
    }
