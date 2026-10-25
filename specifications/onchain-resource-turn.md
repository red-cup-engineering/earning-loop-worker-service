# Original financial turn receiving

## Requirements

The earning clock MUST advance the actual keyless engine's `financial-arena-turn`,
not infer a scanner API from an HTTP status. The existing clock, R2 onchain
register, financial service-line events, evidence custody and actor outcome journal
remain their original owners. No new scheduler, execution ledger or signer is
introduced. Existing commercial, issuer, settlement and price loops are preserved.

Each pulse MUST retain its original scheduled occurrence and private retained
effect/request/run identities before an effect. An unknown result MUST hold that
original reference. A later pulse may only observe/reconcile it; it MUST NOT invoke
again, select another machine/account, or fall back to HTTP. The R2 reading is not
a distributed lock: original CSE authority and once-only authenticated supplier
provide effect custody. The host MUST admit the original state, authority, caller,
native receiver and $0 allowance; this source does not install such a binding.

A received stage, intent offer, external outcome, payment and recognized earning
are separate evidence. Financial turns remain keyless and intent-only. No capital,
gas, grant, transaction admission or account is widened.

## Specification

Private `withOnchain(occurrence, work)` selects and holds the original resource
capability only for this invocation, awaiting work before it closes. Its `onchain`
resource port supplies `identify(occurrence)`, `checkpoint`,
the currently held CSE `provider`, and observation-only `reconcile`. Identify reads
original retained invocation custody and returns `{effect, request, input:{run}}`.
Provider selection is fixed to `financial-arena`; the supplier maps these retained
identities to the original signed `financial-arena-turn` operation. Neither HTTP
parameters nor public configuration can supply these closures or choose a run.
For an uncertain submission, reconcile recovers the ORIGINAL pending token/claim
and calls CSE reconciliation. If native supplier receiving already settled but
local R2 readout failed, it only reads the original retained signed actor outcome;
the settled authority may already have released its holder. Local readout failure
does not make a settled native effect pending again. Reconciliation MUST NOT
acquire another claim or invoke the supplier. Closed private ports
must be selected again from original custody by the host, never reused.

The register retains occurrence and original invocation before calling. Terminal
readings are retained through the existing dated `record('onchain', ...)` carrier
before replacement; a dated content digest prevents same-time overwrite. The
current reading keeps a bounded previous-reference and last received summary,
never recursively embeds prior readings. A valid
reply contains the original FinancialArenaEvent mark and FinancialArenaStatus for
the same run/cycle. Its ID, stage, event status, entire reply and evidence references
are retained. Original stage/cycle/status/next consistency is checked. Receipt
readback and fence checks precede acknowledgment. Failed
receiving, including malformed replies, leaves the original pending reference.
An uncertain register read/write is not a domain failure or an excuse to continue.

Legacy URL/token installations keep their explicit HTTP capability, with a pending
reading before POST and the original response after receiving. This is transport
evidence only, has no automatic retry/reconciliation, and never becomes `ran`,
financial receiving or earnings. A pending legacy request blocks new dispatch;
pre-upgrade `unreachable`/HTTP-error readings without original request custody
remain unresolved and cannot silently enter another provider or request.

## Design

`runOnchainHook` owns this bounded adapter and continues using the same onchain
register. Existing DO turns pass their private option through; the worker factory
accepts the same private port for scheduled delivery. Scheduled delivery uses
`scheduledTime` instead of wall-clock arrival. Missing private port remains an
explicit gap; generated operation data and current runtime selection are untouched.
The scorecard projects driver, useful-work, external-reconciliation and accounting
readings separately; public reading projections omit original selectors, raw
diagnostics and complete replies, which remain original private receiving state.
Only existing independently received seller settlements feed
its monetary totals. Legacy financial stages are domain workflow, not Actor MAPE-K
or proof of PACE-S admission. Source-only adversarial tests are authored unrun.

## Source disposition

This candidate is independently source-reviewed. No application, test, build,
provider call or deployment was run. The real private `withOnchain` binding,
retained occurrence resolver, original actor identities, restored state admission,
installed CSE/AOE source selection and runtime qualification remain unestablished.
The default worker intentionally attaches no new provider. Existing operation
parameters and machine/account state are retained. No availability, one-machine
survival, external execution, payment or earnings proof is claimed by this change.
