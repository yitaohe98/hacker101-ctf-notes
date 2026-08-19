# Web Security Testing Workflow

This is a living workflow for authorized targets and labs. Update it whenever practice changes how you work.

## 1. Confirm authorization and scope

- Confirm the asset is explicitly in scope.
- Read prohibited-testing rules, rate limits, and reporting requirements.
- Use only legitimate test accounts and safe testing methods.

## 2. Understand normal behavior

Use the application normally first. Identify what it does, who uses it, what data is valuable, and what actions look security-sensitive.

## 3. Map roles, objects, and workflows

Record roles (for example, anonymous, user, administrator), important objects (orders, files, messages), their identifiers, and key state transitions. Ask whether steps can be skipped, repeated, reordered, or performed by another role.

## 4. Observe requests and server-side enforcement

Record endpoints, methods, parameters, object identifiers, headers, API versions, and responses. Treat UI restrictions as hypotheses: the server must enforce the actual security boundary.

## 5. Test focused hypotheses

For each interesting action or object, ask:

- Can account A read or modify account B's object?
- Can a lower-privileged user invoke this action directly?
- Do different HTTP methods or API versions enforce authorization consistently?
- What happens when a workflow request is replayed or sent out of sequence?

For each test, record the observation, hypothesis, result, and next question.

## 6. Establish impact and document a PoC

Identify the security boundary, the capability gained, and the affected data or action. Reproduce the issue from a clean state, minimize the steps, and remove unnecessary secrets from evidence.

## 7. Learn from the outcome

After a lab or report outcome, capture what you misunderstood, what was confirmed, and what should change in this playbook.
