# Project Notes — Checkout Service

The checkout service owns cart validation, pricing and payment orchestration.
It is deployed as twelve replicas behind an internal load balancer.

## Conventions
- All money values are stored as integer minor units.
- Idempotency keys are required for every mutating endpoint.
- Feature flags are evaluated at the edge, not in the service.

## Review notes
The pricing cache was switched to a read-through cache with a 30 second TTL.
Stale prices are now reconciled asynchronously by the settlement job. The
reconciliation lag dropped from 19 minutes to 41 seconds.

## Open questions
- Should partial refunds invalidate the original idempotency key?
- Where should the tax rounding rules live so that they are shared with billing?
