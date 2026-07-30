# Level 0 — Background image discovery

## Overview

- **Platform:** Hacker101 CTF
- **Difficulty:** Level 0
- **Category:** Web / information disclosure
- **Status:** Solved
- **Flags found:** 1

## Goal

Find the flag exposed by the Level 0 web application.

## Environment and scope

- **Target:** Hacker101 CTF Level 0 (authorized training environment)
- **Tools used:** Browser developer tools or Burp Suite

## Reconnaissance

The landing page returned a simple HTML document containing a CSS rule for the page background:

```html
body {
    background-image: url("background.png");
}
```

The referenced relative asset was a useful lead: the application may expose content directly through static files, not just through visible page text.

![Level 0 landing page](evidence/level-0-landing-page.png)

## Solution path

1. Load the Level 0 home page and inspect its source or HTTP response.
2. Notice the relative `background.png` asset in the CSS `background-image` rule.
3. Request the asset at `/background.png`:
   - In a browser, append `background.png` to the challenge base URL.
   - Or, in Burp Suite, change the request line from `GET / HTTP/2` to `GET /background.png HTTP/2` and resend it.
4. The image response contains the flag.

## Key lesson

Visible pages often reference additional static assets. Review HTML, CSS, JavaScript, and network requests during reconnaissance; an apparently decorative asset can expose meaningful application content.

## Cleanup / notes

- The flag value is deliberately omitted to keep this repository useful as a learning record without publishing a direct spoiler.
- This technique was used only within the authorized Hacker101 CTF environment.
