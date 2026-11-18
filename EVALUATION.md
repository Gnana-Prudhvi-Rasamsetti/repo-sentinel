# Repository evaluation

Scans below were run on 2026-11-18 with Repo Sentinel's current heuristic rules. The public repositories are cloned under `fixtures/real-repos/` for local reproduction; those copies are excluded from Repo Sentinel's self-scan and Git changes.

| Repository | Commit | Findings | Notes |
| --- | --- | ---: | --- |
| [do-community/django-polls](https://github.com/do-community/django-polls) | `61c5b63ec0159b83d1c552f242f4389c80ce61b4` | 0 | Small tutorial app; quiet scan, though this also shows the checks can miss framework-specific issues. |
| [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) | `266448aba68cd8ba5915f526a128da4fa7bc3f9f` | 299 after tuning | 211 high, 4 medium, 84 low. Intentionally vulnerable TypeScript application, not a clean-code baseline. |
| [spring-petclinic/spring-petclinic-rest](https://github.com/spring-petclinic/spring-petclinic-rest) | `0515ec8b57e7708d99d7a1315638d81d3f2c9ead` | 1 | A low-severity unfinished-work marker; 17 SQL matches on entity IDs were filtered by the new request-data analysis. |
| [go-chi/chi](https://github.com/go-chi/chi) | `c64ed7d6635f33a8b2feaff7dcfa55677023ac7d` | 16 | Includes a test-only TLS skip for self-signed certificates and a comment saying a path is intentionally unimplemented. |

## Dependency audit

The opt-in OSV audit found 9 advisory/package-version matches across go-chi's example `go.mod` files. Several advisory IDs repeat for separate example modules and versions. Juice Shop has no npm lockfile in the scanned commit, so its ranged `package.json` dependencies were not queried; the tool intentionally avoids treating version ranges as exact versions. OSV queries were not run for Django Polls or Spring Petclinic because the current parser does not support their dependency formats/manifests.

The Juice Shop scan initially produced 807 findings. Reviewing samples showed three broad heuristics caused avoidable noise: normal `console.log` calls, HTML `placeholder` attributes, and `RegExp.exec()` calls. The rules were narrowed and regression cases were added; Python-only unsafe YAML deserialization was also corrected after reviewing library-specific behavior. The current scan produces 299 findings:

- 196 possible credentials, with most matches in tests and the app's intentional demo-user data.
- 12 interpolated SQL constructions, including deliberately vulnerable challenge code.
- No YAML `load` findings remain for this TypeScript project; the rule is now Python-aware and recognizes safe PyYAML loaders.
- Remaining findings include unfinished-work markers and intentionally vulnerable code paths.

## Finding review notes

- **SEC001 (196):** 158 are in `test/` and 15 in frontend specs, where they are test credentials. The other 23 are demo account passwords in `data/static/users.yml`; they are deliberately weak credentials for the training app, but remain security-relevant if such accounts are enabled outside a challenge environment.
- **SEC006 (12):** 10 are challenge/code-fix examples; 2 are the live `routes/login.ts` and `routes/search.ts` challenge paths. These are intentional vulnerabilities in this application and valid detections.
- **SEC007 (6 before the fix):** the matches were `js-yaml` calls, not Python PyYAML. The rule now checks Python AST calls only and exempts safe loaders, avoiding this language-specific false positive.
- **SEC002:** dynamic evaluation hits in challenge routes and tests; review them as expected challenge code rather than benign `.exec()` methods (which are no longer matched).

The Spring Petclinic scan initially showed a precision gap: the SQL regex flagged concatenated JPQL even where the value was an entity ID converted to a string. A simple same-file request-data analysis now filters those untainted expressions while retaining flows from `@RequestParam`, `@PathVariable`, and servlet request parameters. This analysis is intentionally limited and does not follow values across method or file boundaries. The Go TLS match is confined to a test server that intentionally uses a self-signed certificate; consider test-specific configuration or severity handling rather than suppressing the rule globally.

This comparison is useful for tuning, not a precision/recall benchmark: Juice Shop intentionally contains vulnerabilities, and Django Polls is small. Review each finding in context and add more clean and vulnerable projects before making claims about detection rates.
