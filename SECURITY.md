# Security policy

`pyfilecage` is itself a security control. Please treat bypasses as security
vulnerabilities, not ordinary bugs.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |

## Reporting

Please report vulnerabilities privately through GitHub Security Advisories for
`draarivpatel-ui/pyfilecage` when the repository is public. Do not open a public
issue, pull request, or proof-of-concept discussion before coordinated disclosure.

Include:

- the affected version and Python version,
- a minimal byte sequence or file structure that demonstrates the bypass,
- the policy used,
- the expected finding code,
- whether the issue is a validation bypass, memory or CPU exhaustion issue,
  incorrect detection, or unsafe filename/path behavior.

## Scope

In scope:

- magic-byte misclassification that lets executable content pass,
- MIME or extension cross-check bypasses,
- pixel-bomb dimension parser bypasses or nontermination,
- SVG, PDF, PNG metadata, or polyglot scan bypasses,
- filename sanitizer bypasses, including Unicode and Windows device tricks,
- path validation race or non-regular-file bypasses,
- unbounded memory reads in stream validation,
- CLI terminal-control injection.

Out of scope:

- attacks requiring the caller to ignore `allowed` or findings,
- attacks requiring explicit unsafe policy opt-ins,
- the fact that validation cannot prove every downstream viewer safe,
- vulnerabilities in unrelated frameworks, image decoders, PDF renderers, or
  operating systems.

## Response goals

Reports will be triaged as promptly as possible. A fix release should include a
regression test with a hostile fixture and a control fixture whenever the input
can be shared safely.
