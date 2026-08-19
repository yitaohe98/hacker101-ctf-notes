# Web Security Terminology

A practical glossary. Definitions should explain what to investigate and why it matters.

## Access control

### Broken Access Control (BAC)

The application does not correctly enforce what a user is allowed to access or do. The useful question is: *the server knows who I am, but does it correctly check what I am allowed to do?*

Example: a normal user can call an administrator-only endpoint.


### IDOR / BOLA

An insecure direct object reference (IDOR), often called broken object-level authorization (BOLA) for APIs, occurs when an application lets a requester access or alter a specific object without verifying authorization for that object.

Predictable identifiers alone are not a vulnerability. The missing authorization check is the problem.

Example: changing `GET /api/invoices/1001` to `/1002` returns another customer's invoice.


## Vulnerability classes

### Cross-site scripting (XSS)

Attacker-controlled content reaches an executable browser context without appropriate output handling. Common forms are stored, reflected, and DOM-based XSS.

Example: a comment is saved and later runs JavaScript in every reader's browser.


### SQL injection (SQLi)

Attacker-controlled input changes the structure or meaning of a database query, rather than remaining data within that query.

Example: a login field changes a query so that it returns a user without a valid password check.


### Cross-site request forgery (CSRF)

An attack that causes a victim's browser to send an unwanted authenticated request. It relies on the browser automatically attaching authentication state such as cookies.

Example: a malicious page triggers an account-email change while the victim is logged in.


## Investigation and reporting

### Reconnaissance

Recon is the process of building a blueprint of an application's attack surface: its users, roles, objects, workflows, endpoints, APIs, and trust boundaries. It is broader than running automated tools.

Example: mapping an order workflow and the API requests behind each step.


### Proof of concept (PoC)

A minimal, reproducible demonstration of a security-boundary violation. It should identify the needed account or role, the action performed, the result, and why that result matters.

Example: two test accounts show that one can read the other's private order.


### Impact

The concrete consequence of a vulnerability: what an attacker can read, change, impersonate, or otherwise affect, and who is affected.

Example: an IDOR exposes every customer's invoice, including their personal details.


### Information disclosure

Information that should not be available to the requester is revealed, such as stack traces, internal paths, private data, credentials, or debug output. Severity depends on both the data and what it enables.

Example: an error page exposes a database hostname and application file paths.
