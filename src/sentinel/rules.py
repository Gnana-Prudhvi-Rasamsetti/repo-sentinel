"""Explainable, language-neutral heuristic checks for repository source files."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    category: str
    pattern: re.Pattern[str]
    message: str
    recommendation: str


def _rule(
    rule_id: str,
    title: str,
    severity: str,
    category: str,
    pattern: str,
    message: str,
    recommendation: str,
    flags: int = re.IGNORECASE,
) -> Rule:
    return Rule(rule_id, title, severity, category, re.compile(pattern, flags), message, recommendation)


RULES = (
    _rule("SEC001", "Possible hardcoded credential", "high", "security",
          r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd)\b\s*[:=]\s*['\"](?!\s*(?:\$\{|\{\{|<|your_|example|changeme|\*+))[^'\"]{8,}['\"]",
          "A credential-like value appears to be embedded in source.",
          "Load secrets from a secret manager or environment variable, and rotate any exposed credential."),
    _rule("SEC002", "Dynamic code execution", "high", "security",
          r"(?<![\w.])(?:eval|exec)\s*\(",
          "Dynamic code execution can turn untrusted input into executable code.",
          "Remove dynamic execution or constrain it to trusted, validated inputs."),
    _rule("SEC003", "Shell command with interpolation", "high", "security",
          r"(?:shell\s*=\s*True|\b(?:exec|spawn)\s*\([^\n]*(?:shell\s*:\s*true|\{\s*shell\s*:\s*true\}))",
          "A process appears to invoke a shell, which can enable command injection.",
          "Pass an argument array directly to the process API and validate each argument."),
    _rule("SEC004", "Disabled TLS certificate validation", "high", "security",
          r"(?:rejectUnauthorized\s*:\s*false|verify\s*=\s*False|CERT_NONE|InsecureSkipVerify\s*:\s*true)",
          "TLS certificate verification appears to be disabled.",
          "Enable certificate verification; use a trusted development certificate when needed."),
    _rule("SEC005", "Weak cryptographic hash", "medium", "security",
          r"\b(?:md5|sha1)\s*\(",
          "MD5 or SHA-1 is used and is unsuitable for security-sensitive hashing.",
          "Use SHA-256 or stronger for integrity; use a password hashing function for passwords."),
    _rule("SEC006", "Potentially unsafe SQL construction", "high", "security",
          r"(?:execute|query|createNativeQuery|createQuery|ExecuteSqlRaw|FromSqlRaw)\s*\(\s*(?:f['\"`]|['\"][^'\"]*%s|['\"][^'\"]*['\"]\s*\+|`[^`]*\$\{)",
          "A SQL call appears to build its query through string interpolation or concatenation.",
          "Use parameterized queries and bind untrusted values separately."),
    _rule("SEC007", "Unsafe deserialization", "high", "security",
          r"\b(?:pickle\.loads?|marshal\.loads?)\s*\(",
          "A deserializer that can construct executable or unsafe objects appears to be used.",
          "Use a safe data-only loader (such as yaml.safe_load) and reject untrusted serialized objects."),
    _rule("SEC008", "Wildcard CORS policy", "medium", "security",
          r"(?:['\"]?Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*|cors\s*\(\s*\{[^}]*origin\s*:\s*['\"]\*)",
          "A cross-origin policy appears to allow requests from every origin.",
          "Allow only the specific trusted origins your application needs."),
    _rule("SEC009", "Predictable randomness used for a secret", "medium", "security",
          r"\b(?:token|secret|session|nonce|auth[_-]?key)(?:[_-]?\w*)?\b[^\n]{0,60}(?:random\.random|Math\.random)\s*\(",
          "A predictable random-number generator may be used to create a security-sensitive value.",
          "Use a cryptographically secure random generator for tokens, secrets, and session identifiers."),
    _rule("SEC010", "Potential server-side request forgery", "high", "security",
          r"(?:requests|httpx|urllib\.request)\.(?:get|post|put|delete|request|urlopen)\s*\([^\n]*(?:request\.(?:args|query|form|json)|user[_-]?input|url_param)",
          "A URL from a request or user-controlled value may be sent by the server.",
          "Validate and allowlist destination hosts, and block access to private and metadata addresses."),
    _rule("SEC011", "Archive extraction may allow path traversal", "high", "security",
          r"\.(?:extractall|extract_to|unpack)\s*\(",
          "Archive extraction can write files outside the intended destination when entry paths are untrusted.",
          "Validate each archive entry path resolves inside the destination before writing files."),
    _rule("SEC012", "Shell command string in Go", "high", "security",
          r"exec\.Command\s*\(\s*['\"](?:sh|bash|cmd)(?:\.exe)?['\"]\s*,\s*['\"]-c['\"]",
          "A shell command string is passed to Go's process API.",
          "Invoke the intended executable directly with separate, validated arguments."),
    _rule("SEC013", "Django debug mode enabled", "high", "security",
          r"^\s*DEBUG\s*=\s*True\b",
          "Django debug mode appears to be enabled in a Python settings file.",
          "Disable DEBUG in deployed settings and load it from an environment-specific configuration."),
    _rule("SEC014", "Django allows every host", "high", "security",
          r"^\s*ALLOWED_HOSTS\s*=\s*\[[^\]]*['\"]\*['\"]",
          "Django's host allowlist appears to include every host.",
          "Set ALLOWED_HOSTS to the specific hostnames serving this deployment."),
    _rule("QUAL001", "Unfinished work marker", "low", "quality",
          r"\b(?:TODO|FIXME|HACK|XXX)\b",
          "An unfinished-work marker remains in the source.",
          "Resolve it or record a clear owner and tracked issue before release."),
    _rule("QUAL002", "Debug output left in code", "low", "quality",
          r"(?:\bconsole\.debug\s*\(|\bdebugger\s*;|\bconsole\.log\s*\(\s*['\"](?:debug|here|test|temp|todo)\b|\bprint\s*\(\s*['\"](?:debug|here|test|temp|todo)\b)",
          "Debug output or a debugger statement may have been left in production code.",
          "Remove temporary debugging statements or replace them with appropriate structured logging."),
    _rule("QUAL003", "Placeholder implementation", "medium", "quality",
          r"\b(?:not implemented|implement me|coming soon)\b|throw\s+new\s+Error\s*\(\s*['\"]TODO",
          "A placeholder or unimplemented path appears in source.",
          "Implement the behavior or return an explicit, handled unsupported response."),
    _rule("QUAL004", "Broad exception suppression", "medium", "quality",
          r"\b(?:except\s*:\s*(?:pass|\.\.\.)|catch\s*\([^)]*\)\s*\{\s*\})",
          "An exception may be silently discarded, hiding failures.",
          "Handle expected errors explicitly and log or propagate unexpected failures."),
    _rule("QUAL005", "Explicitly unimplemented path", "medium", "quality",
          r"\b(?:raise\s+NotImplementedError|throw\s+new\s+NotImplementedException|NotImplementedException\s*\()",
          "An execution path explicitly reports that its implementation is missing.",
          "Implement the required behavior or remove the path from the release build."),
    _rule("QUAL006", "Possibly unused Python import", "low", "quality",
          r"(?!)",
          "An imported Python name is not referenced in this module.",
          "Remove the import or use it; verify dynamic imports and package re-exports before deleting it."),
)
