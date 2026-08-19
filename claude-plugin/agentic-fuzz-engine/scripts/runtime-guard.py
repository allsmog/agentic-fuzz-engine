#!/usr/bin/env python3
"""Narrow command backstop for plugin hooks; this is not a sandbox."""
from __future__ import annotations

import json
import re
import shlex
import sys
from pathlib import PurePosixPath
from typing import Iterable, Sequence


BLOCKED_PROGRAMS = frozenset({"RealExternalExecutionPlane", "external_runtime.py"})
BLOCKED_PATHS = frozenset({"runtime-userspace/docker-run.py", "runtime-multilang/run.py"})
SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh", "fish"})
PREFIX_WRAPPERS = frozenset({"command", "env", "exec", "nice", "nohup", "setsid", "stdbuf", "sudo", "time", "timeout", "xargs"})
CONTROL_OPERATORS = frozenset({";", "&&", "||", "|", "&", "(", ")", "{", "}"})
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
BLOCKED_MENTION = re.compile(r"(?:RealExternalExecutionPlane|external_runtime\.py|runtime-userspace/docker-run\.py|runtime-multilang/run\.py)")
REDIRECTION = re.compile(r"^(?:\d*(?:>>?|<<?-?|<<<|<>)|&>>?)(.*)$")


def _is_blocked_program(token: str) -> bool:
    normalized = token.replace("\\", "/").removeprefix("./")
    return (
        normalized in BLOCKED_PATHS
        or any(normalized.endswith("/" + path) for path in BLOCKED_PATHS)
        or PurePosixPath(normalized).name in BLOCKED_PROGRAMS
    )


def _tokens(command: str) -> list[str] | None:
    try:
        lexer = shlex.shlex(_separate_unquoted_newlines(command), posix=True, punctuation_chars="|&;()")
        lexer.whitespace_split = True
        lexer.commenters = ""
        return list(lexer)
    except ValueError:
        return None


def _command_substitution_payloads(command: str) -> tuple[list[str], bool]:
    """Extract executable shell substitutions without expanding any of them."""
    payloads: list[str] = []
    index = 0
    quote: str | None = None
    while index < len(command):
        character = command[index]
        if character == "\\" and quote != "'":
            index += 2
            continue
        if quote is not None:
            if character == quote:
                quote = None
                index += 1
                continue
            if quote == '"' and character == "$" and index + 1 < len(command) and command[index + 1] == "(":
                payload, end = _parenthesized_payload(command, index + 2)
                payloads.append(payload)
                if end is None:
                    return payloads, True
                index = end + 1
                continue
            if quote == '"' and character == "`":
                payload, end = _backtick_payload(command, index + 1)
                payloads.append(payload)
                if end is None:
                    return payloads, True
                index = end + 1
                continue
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
            index += 1
        elif character == "$" and index + 1 < len(command) and command[index + 1] == "(":
            payload, end = _parenthesized_payload(command, index + 2)
            payloads.append(payload)
            if end is None:
                return payloads, True
            index = end + 1
        elif character == "`":
            payload, end = _backtick_payload(command, index + 1)
            payloads.append(payload)
            if end is None:
                return payloads, True
            index = end + 1
        else:
            index += 1
    return payloads, False


def _parenthesized_payload(command: str, index: int) -> tuple[str, int | None]:
    start = index
    depth = 1
    quote: str | None = None
    while index < len(command):
        character = command[index]
        if character == "\\" and quote != "'":
            index += 2
            continue
        if quote is not None:
            if character == quote:
                quote = None
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return command[start:index], index
        index += 1
    return command[start:], None


def _backtick_payload(command: str, index: int) -> tuple[str, int | None]:
    start = index
    while index < len(command):
        if command[index] == "\\":
            index += 2
        elif command[index] == "`":
            return command[start:index], index
        else:
            index += 1
    return command[start:], None


def _separate_unquoted_newlines(command: str) -> str:
    """Make shell list newlines visible to shlex without evaluating text."""
    result: list[str] = []
    quote: str | None = None
    escaped = False
    for character in command:
        if escaped:
            result.append(character)
            escaped = False
            continue
        if character == "\\" and quote != "'":
            result.append(character)
            escaped = True
            continue
        if quote is not None:
            result.append(character)
            if character == quote:
                quote = None
            continue
        if character in {"'", '"'}:
            result.append(character)
            quote = character
        elif character == "\n":
            result.append(";")
        else:
            result.append(character)
    return "".join(result)


def _segments(tokens: Iterable[str]) -> Iterable[list[str]]:
    segment: list[str] = []
    for token in tokens:
        if token in CONTROL_OPERATORS:
            if segment:
                yield segment
                segment = []
        else:
            segment.append(token)
    if segment:
        yield segment


def _skip_assignments_and_redirections(tokens: Sequence[str], index: int) -> int:
    while index < len(tokens):
        token = tokens[index]
        if ASSIGNMENT.fullmatch(token):
            index += 1
        elif (redirection := REDIRECTION.fullmatch(token)) is not None:
            index += 1 if redirection.group(1) else 2
        else:
            break
    return index


def _consume_flag_options(
    tokens: Sequence[str],
    index: int,
    *,
    value_options: frozenset[str] = frozenset(),
    payload_options: frozenset[str] = frozenset(),
) -> tuple[int, list[str], bool]:
    """Consume wrapper options, returning nested payloads and malformed state."""
    payloads: list[str] = []
    while index < len(tokens) and tokens[index].startswith("-") and tokens[index] != "-":
        option = tokens[index]
        index += 1
        if option == "--":
            break
        name, equals, attached = option.partition("=")
        if name in payload_options:
            if equals:
                payloads.append(attached)
            elif index < len(tokens):
                payloads.append(tokens[index])
                index += 1
            else:
                return index, payloads, True
        elif name in value_options:
            if not equals:
                if index >= len(tokens):
                    return index, payloads, True
                index += 1
    return index, payloads, False


def _unwrap(tokens: Sequence[str]) -> tuple[str | None, list[str], list[str], bool]:
    """Resolve transparent wrappers without executing or expanding anything."""
    index = _skip_assignments_and_redirections(tokens, 0)
    payloads: list[str] = []
    while index < len(tokens):
        program = tokens[index]
        index += 1
        wrapper = PurePosixPath(program).name
        if wrapper not in PREFIX_WRAPPERS:
            return program, list(tokens[index:]), payloads, False
        if wrapper == "env":
            index, nested, malformed = _consume_flag_options(
                tokens,
                index,
                value_options=frozenset({"-u", "--unset", "-C", "--chdir"}),
                payload_options=frozenset({"-S", "--split-string"}),
            )
            payloads.extend(nested)
            while index < len(tokens) and ASSIGNMENT.fullmatch(tokens[index]):
                index += 1
        elif wrapper == "sudo":
            index, nested, malformed = _consume_flag_options(
                tokens,
                index,
                value_options=frozenset({"-C", "-D", "-g", "-h", "-p", "-r", "-t", "-u", "--chdir", "--close-from", "--group", "--host", "--prompt", "--role", "--type", "--user"}),
            )
            payloads.extend(nested)
        elif wrapper == "nice":
            index, nested, malformed = _consume_flag_options(tokens, index, value_options=frozenset({"-n", "--adjustment"}))
            payloads.extend(nested)
        elif wrapper == "timeout":
            index, nested, malformed = _consume_flag_options(tokens, index, value_options=frozenset({"-k", "-s", "--kill-after", "--signal"}))
            payloads.extend(nested)
            if not malformed:
                if index >= len(tokens):
                    malformed = True
                else:
                    index += 1  # duration
        elif wrapper == "time":
            index, nested, malformed = _consume_flag_options(tokens, index, value_options=frozenset({"-f", "-o", "--format", "--output"}))
            payloads.extend(nested)
        elif wrapper == "stdbuf":
            index, nested, malformed = _consume_flag_options(tokens, index, value_options=frozenset({"-i", "-o", "-e", "--input", "--output", "--error"}))
            payloads.extend(nested)
        elif wrapper == "xargs":
            index, nested, malformed = _consume_flag_options(
                tokens,
                index,
                value_options=frozenset({"-a", "-d", "-E", "-e", "-I", "-i", "-L", "-l", "-n", "-P", "-p", "-s", "--arg-file", "--delimiter", "--eof", "--max-args", "--max-chars", "--max-lines", "--max-procs", "--process-slot-var", "--replace"}),
            )
            payloads.extend(nested)
        elif wrapper == "exec":
            index, nested, malformed = _consume_flag_options(tokens, index, value_options=frozenset({"-a"}))
            payloads.extend(nested)
        else:
            index, nested, malformed = _consume_flag_options(tokens, index)
            payloads.extend(nested)
        if malformed:
            return None, [], payloads, True
        index = _skip_assignments_and_redirections(tokens, index)
    return None, [], payloads, False


def _shell_is_blocked(args: Sequence[str]) -> bool:
    index = 0
    value_options = frozenset({"-o", "+o", "-O", "+O", "--init-file", "--rcfile"})
    while index < len(args):
        argument = args[index]
        if argument == "--":
            index += 1
            break
        if argument in value_options:
            index += 2
            continue
        if argument in {"-c", "--command"}:
            return index + 1 >= len(args) or command_is_blocked(args[index + 1])
        if argument.startswith("-") and not argument.startswith("--") and argument[1:].isalpha() and "c" in argument[1:]:
            return index + 1 >= len(args) or command_is_blocked(args[index + 1])
        if argument.startswith(("-", "+")):
            index += 1
            continue
        return _is_blocked_program(argument)
    return False


def _python_is_blocked(args: Sequence[str]) -> bool:
    index = 0
    value_options = frozenset({"-W", "-X", "-Q", "--check-hash-based-pycs", "--encoding", "--hash-seed"})
    while index < len(args):
        argument = args[index]
        if argument == "--":
            return index + 1 < len(args) and _is_blocked_program(args[index + 1])
        if argument in {"-c", "-m"}:
            return False
        if argument in value_options:
            index += 2
            continue
        if argument.startswith("-"):
            index += 1
            continue
        return _is_blocked_program(argument)
    return False


def _malformed_may_invoke_blocked(command: str) -> bool:
    """Fail closed only where malformed text still resembles an invocation."""
    if not BLOCKED_MENTION.search(command):
        return False
    if re.search(r"(?:^|[;&|]\s*)(?:(?:env|sudo|nice|timeout|setsid|xargs|command)\s+)*(?:(?:python\S*|bash|sh|zsh|dash|ksh|fish)\s+)?(?:[^\s]*?(?:external_runtime\.py|RealExternalExecutionPlane|runtime-userspace/docker-run\.py|runtime-multilang/run\.py))", command):
        return True
    if re.search(r"\b(?:bash|sh|zsh|dash|ksh|fish)\b(?:\s+\S+)*?\s(?:-c|--command|-[A-Za-z]*c[A-Za-z]*)\s+.*(?:external_runtime\.py|RealExternalExecutionPlane|runtime-userspace/docker-run\.py|runtime-multilang/run\.py)", command):
        return True
    return False


def _is_command_query(tokens: Sequence[str]) -> bool:
    index = _skip_assignments_and_redirections(tokens, 0)
    if index >= len(tokens) or PurePosixPath(tokens[index]).name != "command":
        return False
    index += 1
    query = False
    while index < len(tokens):
        option = tokens[index]
        if option == "--":
            return query and index + 1 < len(tokens)
        if not option.startswith("-") or option == "-":
            return query
        flags = option[1:]
        if not flags or any(flag not in {"p", "v", "V"} for flag in flags):
            return False
        query = query or "v" in flags or "V" in flags
        index += 1
    return False


def _segment_is_blocked(tokens: Sequence[str]) -> bool:
    if _is_command_query(tokens):
        return False
    program, args, payloads, malformed = _unwrap(tokens)
    if any(command_is_blocked(payload) for payload in payloads):
        return True
    if malformed or program is None:
        return any(_is_blocked_program(token) for token in tokens)
    if _is_blocked_program(program):
        return True
    name = PurePosixPath(program).name
    if name in SHELLS:
        return _shell_is_blocked(args)
    if name.startswith("python"):
        return _python_is_blocked(args)
    return False


def command_is_blocked(command: object) -> bool:
    """Detect executable invocation forms; arguments to benign search tools pass."""
    if not isinstance(command, str):
        return False
    try:
        substitutions, malformed_substitution = _command_substitution_payloads(command)
        if any(command_is_blocked(payload) for payload in substitutions):
            return True
        if malformed_substitution:
            return _malformed_may_invoke_blocked(command)
        tokens = _tokens(command)
        if tokens is None:
            return _malformed_may_invoke_blocked(command)
        return any(_segment_is_blocked(segment) for segment in _segments(tokens))
    except (IndexError, RecursionError, TypeError, ValueError):
        return _malformed_may_invoke_blocked(command)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError, RecursionError, TypeError, ValueError):
        return 0
    if not isinstance(payload, dict):
        return 0
    tool_input = payload.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if command_is_blocked(command):
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "agentic-fuzz denies direct external-runtime invocation; this narrow backstop is not a sandbox"}}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
