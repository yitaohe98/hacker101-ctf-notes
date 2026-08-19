# Web Security Lab

A personal knowledge base for studying web security through notes, authorized labs, and practical workflows.

The aim is to build a useful mental model of web security, document what I learn, and turn repeated practice into a disciplined testing process.

## Repository structure

```text
web-security-lab/
├── concepts/          # reusable explanations and vocabulary
├── learning-notes/    # dated study-session notes
├── playbook/          # living, practical testing workflows
├── labs/              # indexes for intentionally vulnerable environments
│   └── hacker101/
└── hacker101ctf/      # original Hacker101 CTF project and write-ups
```

## How to use it

- Capture what happened in a study session in `learning-notes/`.
- Promote durable lessons into `concepts/`.
- Update `playbook/` when a lesson changes how you would test an application.
- Keep lab-specific tricks and evidence in the relevant lab project.

## Scope and safety

Only test systems you own or are explicitly authorized to assess. For live programs, follow the program policy and keep target-specific, sensitive material out of a public repository.

## Current milestones

```text
Complete introductory labs
        ↓
Build a repeatable web-security workflow
        ↓
Explore an explicitly in-scope target
        ↓
Document and validate a plausible finding
        ↓
Submit a clear report
```
