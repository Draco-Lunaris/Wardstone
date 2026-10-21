# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Status

Greenfield repository. The initial commit contains only `README.md`, `LICENSE` (Apache 2.0), and this file — there is no source code, build system, or test infrastructure yet. Do not assume or invent build/lint/test commands; verify anything you claim about the codebase against what actually exists.

## Project Intent

From `README.md`: Wardstone is a self-hosted certificate authority with a web UI — simple enough for a homelab and hardened enough for production.

The "hardened enough for production" clause is a design constraint, not marketing copy: CA key handling, issuance/revoke flows, and the web UI's attack surface are security-sensitive, and choices in this space should be treated accordingly even in early scaffolding.

## Maintaining This File

As the codebase takes shape, replace this section with the facts future sessions need:

- Build, lint, and test commands — including how to run a single test
- The big-picture architecture that requires reading multiple files to understand (e.g. how the CA core, persistence, and web UI layers fit together and where data flows between them)
- Conventions that differ from the tool defaults