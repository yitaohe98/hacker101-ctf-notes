# Micro-CMS v1 — Four vulnerability paths

## Overview

- **Platform:** Hacker101 CTF
- **Difficulty:** Level 1 / Easy
- **Category:** Web security
- **Status:** Solved
- **Flags found:** 4 of 4

## Goal

Find four flags in a small content-management system by examining how it handles page identifiers, access checks, and user-controlled content.

## Environment and scope

- **Target:** Hacker101 CTF Micro-CMS v1 (authorized training environment)
- **Techniques:** Object enumeration, access-control testing, malformed input, HTML injection, stored XSS

## Finding 1 — Hidden page reachable through an edit route

### Observation

Only pages 1 and 2 appeared in the normal interface, but creating a new page created page 9. That gap suggested that pages 3–8 might already exist but be unlinked.

### Test

Request the missing page IDs and look for behavior differences. A restricted page reported that its content existed but could not be viewed. Requesting the corresponding edit route, such as `/page/edit/x`, exposed the protected content and its flag.

### Lesson

The view route enforced a restriction that the edit route did not. Sequential identifiers are useful reconnaissance signals, but hiding a link or denying one route is not authorization. Every endpoint that reads or changes an object must perform the same server-side ownership or permission check.

**Classification:** Broken object-level authorization (IDOR)

## Finding 2 — Malformed page ID produced a database error

### Observation

The edit endpoint accepted the page ID in its route, making that value an input boundary worth testing.

### Test

Append a single quote to an otherwise valid ID, for example:

```text
/page/edit/1'
```

The application did not reject the value as non-numeric. Instead, its abnormal response revealed the second flag.

### Lesson

A quote can disrupt SQL string syntax when user input is concatenated into a query. This behavior is evidence of unsafe query construction or database-error leakage; the syntax error alone does not prove arbitrary SQL execution. Validate IDs as integers, use parameterized queries, and return generic error pages.

**Classification:** SQL-injection indicator / verbose error handling

## Finding 3 — Stored HTML was rendered as executable markup

### Observation

The editor claimed to support Markdown. The next question was whether it also preserved raw HTML and event-handler attributes.

### Test

Save a harmless button containing an inline event handler:

```html
<button onclick="alert('Test Hello')">Click</button>
```

The CMS rendered a real button. Inspecting the rendered DOM or page source revealed the third flag in the generated markup.

### Lesson

Attacker-controlled markup had crossed the storage and rendering boundary. Applications should escape untrusted content by default. If a product deliberately supports limited HTML, it needs a proven allowlist sanitizer that removes event-handler attributes and dangerous URL schemes.

**Classification:** HTML injection / unsafe output rendering

## Finding 4 — Stored JavaScript executed in the browser

### Observation

The previous finding showed that unsafe HTML reached the page. The remaining question was whether JavaScript could execute when the stored content was viewed.

### Test

Submit an alert-based XSS proof of concept in the page content and load the stored page:

```html
<script>alert(1)</script>
```

The browser executed the alert and triggered the fourth flag.

### Lesson

Because the CMS stored the payload and executed it later when the page was viewed, this is stored XSS. An alert is only a proof of execution; in a real application, the same primitive could act with the visitor’s browser privileges. Use context-aware output encoding and a proven HTML sanitizer; a restrictive Content Security Policy is defense in depth, not a replacement for sanitization.

**Classification:** Stored cross-site scripting (XSS)

## Key takeaways

- Gaps in sequential IDs can reveal objects that deserve authorized, controlled testing.
- Authorization must be checked for each object on every relevant route.
- Input validation, parameterized queries, and non-verbose error handling reduce database exposure.
- Rendering user content as HTML makes every surviving element and attribute part of the security boundary.

## References

- Personal solution summary: `Hacker101_Micro-CMS_v1_Flag_Summary.docx`
- [CyberNilsen’s Micro-CMS v1 solution](https://github.com/CyberNilsen/hacker101-CTF-Solutions/blob/main/Level-1_Micro-CMS-v1/solution.md) (cross-reference)

## Spoiler policy

Flag values are deliberately omitted. This note records the discovery process and defensive lessons for the authorized Hacker101 CTF environment.
