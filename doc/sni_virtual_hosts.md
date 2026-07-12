# Server-side SNI virtual hosts

A picoquic server can present different TLS identities (a certificate
chain and signing key) to different clients, selected by the server name
(SNI) that the client sends in its ClientHello. This makes it possible
to serve several host names from one QUIC context, each with its own
certificate, and to route each connection to per-host application state.

The full API contract is documented in `picoquic.h`, next to the
declarations. This note explains the model and the rules.

## Identities

A server identity is a preloaded, immutable object created from
certificate and key files:

```c
picoquic_server_identity_t* identity = NULL;
ret = picoquic_server_identity_create(quic, cert_file, key_file, &identity);
```

Creation loads the credentials immediately, through the same crypto
provider that loads the default certificate; nothing is read from disk
during handshakes. An identity is bound to the QUIC context that
created it: passing it to another context is refused (registry) or
fails the handshake with a TLS `internal_error` alert (selector).

Identities do not copy the certificate-verification policy. They share
the master context's verifier object outright. A custom verifier
installed with `picoquic_set_verify_certificate_callback()`, and any
roots added with `picoquic_set_tls_root_certificates()`, therefore
apply identically to the fallback context and to every identity (this
matters for client authentication). The verifier is reference counted
across all contexts; an owned verifier's cleanup callback runs exactly
once, when the last context referencing it is released.

The opaque identity handle itself is not reference counted.
`picoquic_server_identity_release()` invalidates it immediately. What
is reference counted is the underlying TLS context:

* registering an identity stores a reference to its TLS context in the
  registry entry, not the handle, so registry-only users may release
  the handle right after registration;
* every connection that selects an identity keeps the underlying TLS
  context alive until the connection is deleted, no matter when the
  handle is released or the entry replaced or removed;
* a selector callback returns the handle itself: keep the handle alive
  for as long as the selector may return it, even if the same identity
  is also registered.

Identity handles not released when `picoquic_free()` runs are released
by `picoquic_free()`. Handles must not be used after that.

## The name registry

```c
ret = picoquic_set_server_identity(quic, "alpha.example.com", identity, vhost_alpha);
ret = picoquic_set_server_identity(quic, "*.beta.example.net", identity2, vhost_beta);
ret = picoquic_remove_server_identity(quic, "alpha.example.com");
```

Matching rules:

* names are DNS names, compared ASCII-case-insensitively;
* an exact entry takes precedence over a wildcard entry;
* a wildcard is accepted only as the complete leftmost label
  (`*.example.com`) and matches exactly one label, per RFC 9525;
* internationalized names must be supplied in A-label (punycode) form;
  no Unicode processing is performed;
* patterns must be well-formed DNS host names: at most 253 octets,
  labels of 1 to 63 letters, digits or hyphens, no hyphen at a label
  boundary, no leading or trailing dot, no all-digit final label (an IP
  literal is not a host name), and `*` accepted only as the complete
  leftmost label. Patterns are always validated, in every mode.

Registering a pattern that already exists replaces the entry: new
handshakes get the new identity, established connections keep the one
they selected. This is the hot-reload path for per-name certificate
rotation: create the new identity, register it under the same name,
release the old one. Removal releases only the registry's reference.

If the ClientHello has no SNI, or the SNI matches no entry, the server
uses the default certificate configured with `picoquic_create()`, which
is the pre-existing behavior. Once SNI selection has been enabled, a
malformed SNI fails the handshake with a TLS `illegal_parameter` alert.
A malformed SNI is anything that is not a well-formed DNS host name, by
the same rules as registration patterns, including names whose final
label is all digits (IP literals are not host names). Strict wire
validation is sticky: it stays enabled even after every entry and the
selector are removed. A server that never configures SNI selection
keeps the legacy permissive wire behavior and accepts arbitrary SNI
values; ordinary nonconforming names such as `my_host.example.com`
remain readable through `picoquic_tls_get_sni()`, the picotls-backed
C-string accessor. A name with an embedded NUL is accepted on such
legacy servers for compatibility, but cannot be fully represented by
that accessor, and the connection's internal C-string copy is only made
for validated names.

## Per-connection routing

The `server_name_ctx` pointer registered with an entry (or produced by
the selector) is stored on every connection that selects the entry and
is available from the connection callback:

```c
my_vhost_t* vhost = (my_vhost_t*)picoquic_get_server_name_context(cnx);
```

The pointer is borrowed: picoquic stores it, never frees it, and the
application must keep it valid for as long as any connection may have
selected it. The accepted SNI itself is available through
`picoquic_tls_get_sni()`.

## The selector callback

Applications that need more than a static table (many names, a dynamic
certificate store, strict rejection of unknown names) can install a
selector:

```c
picoquic_set_server_identity_select_fn(quic, my_selector, my_ctx);
```

The selector runs during ClientHello processing, before picotls picks
the server certificate. It receives a read-only view of the ClientHello
(server name, proposed ALPN list, signature algorithms, certificate
compression algorithms, server certificate types). The server name is
length-delimited, not NUL-terminated, and all pointers are only valid
for the duration of the call.

The return value drives resolution:

| result        | effect                                                     |
|---------------|------------------------------------------------------------|
| `selected`    | use the identity written to `*identity`                    |
| `fallthrough` | consult the registry, then the default certificate         |
| `use_default` | use the default certificate, bypassing the registry        |
| `reject`      | fail the handshake with a TLS `unrecognized_name` alert    |

An invalid result, a NULL identity with `selected`, or an identity from
another QUIC context fail the handshake with a TLS `internal_error`
alert. The callback may set `*server_name_ctx`; a registry match
overwrites it with the entry's value.

## Resumption scopes

SNI alone is not the tenant boundary for session resumption: a name can
be removed from the registry or reassigned to a different identity, and
a session ticket issued before the change would otherwise still resume.
That would route the connection, and any 0-RTT early data, into a
different application context than the ticket was issued under.

Each registry entry therefore carries a 16-octet *resumption scope*
(`picoquic_server_resumption_scope_t`), and the server binds every
session ticket to the scope selected for the issuing connection.
A ticket only resumes when the scope selected for the new connection
matches; on a mismatch ticket decryption fails, the handshake completes
as a full handshake, and 0-RTT data is rejected. PSK and 0-RTT can
never move between different scopes.

Scope selection follows identity selection: a registry match uses the
entry's scope (overriding anything the selector supplied); a registry
miss or a no-SNI connection uses a per-context default scope. A
selector must copy its own stable scope into the `resumption_scope`
output for every result it fully decides: `selected`, `use_default`,
and `fallthrough` when no registry entry matches. If it leaves the
value all-zero while routing the connection (a `server_name_ctx` was
supplied or an identity selected), resumption is disabled for that
connection: a ticket is issued, but bound to a scope no later
connection will reproduce, so a routing change can never be crossed by
an old ticket. A selector that supplies neither scope nor routing
context leaves the default scope in place, keeping ordinary fallback
resumption. The all-zero scope is a reserved sentinel: explicit
registration with it is refused, and the random helper never generates
it.

The plain registration API generates a fresh random scope on every
call, so replacing an entry (and removing then re-adding it)
deliberately invalidates previously issued tickets. To keep resumption
working across certificate rotation or a process restart, generate a
scope once with `picoquic_server_resumption_scope_random()`, persist
it, and pass it to `picoquic_set_server_identity_ex()`; registering a
new identity under the same name with the same explicit scope rotates
the certificate without invalidating tickets.

The default/fallback scope (used for registry misses, no-SNI
connections and selector `use_default`) is generated randomly when SNI
selection is first enabled, and is therefore process-local: persisting
the ticket encryption keys alone does not preserve fallback resumption
across a restart once SNI scoping is enabled. A selector can preserve
fallback resumption by supplying a persisted stable scope for
`use_default` or unmatched `fallthrough`. Registry-only deployments
have no explicit default-scope setter, a deliberate limitation for now.

Scoping is enabled the first time a registry entry is added or a
selector is installed, and stays enabled for the lifetime of the QUIC
context, even if every entry and the selector are later removed. This
keeps an old scoped ticket from becoming valid again under legacy
processing. Enabling scoping also invalidates tickets issued before it
was enabled. A server that never configures SNI selection keeps the
original ticket format and resumption behavior, byte for byte.

## Configuration freeze

An identity snapshots the QUIC context's TLS configuration when it is
created. To keep TLS policy identical across all identities,
context-wide TLS configuration must be completed before the first
identity is created; afterwards it is frozen.

Setters that return `int` then fail with
`PICOQUIC_ERROR_TLS_CONFIG_FROZEN`: `picoquic_set_cipher_suite`,
`picoquic_set_key_exchange`, `picoquic_set_private_key_from_file`,
`picoquic_set_tls_root_certificates`, `picoquic_set_low_memory_mode`,
`picoquic_set_verify_certificate_callback_ex`, and
`picoquic_ech_configure_quic_ctx`.

Setters that return `void` log through `DBG_PRINTF` and leave the
configuration unchanged: `picoquic_set_tls_certificate_chain`,
`picoquic_set_client_authentication`, `picoquic_set_use_exporter`,
`picoquic_set_verify_certificate_callback`, and
`picoquic_set_null_verifier`. On failure the void verify-certificate
setter disposes a newly supplied, not-yet-owned callback, but never
disposes or alters a callback already owned anywhere in the QUIC
context (active, or retained by an old TLS context across a certificate
refresh).

Shared runtime state that lives on the QUIC context, such as the
session ticket encryption keys (`picoquic_set_ticket_key`), is not
frozen: it is intentionally common to all identities.
`picoquic_refresh_tls_certificate()` also remains allowed; it refreshes
only the default (fallback) certificate.

## Interactions worth knowing

* **Session resumption.** picotls binds session tickets to the server
  name (a ticket issued for one host name cannot resume with another),
  and picoquic additionally binds them to the resumption scope (see
  above), so PSK and 0-RTT never cross virtual-host boundaries even
  when a name is removed or reassigned. Ticket encryption keys are
  shared, so resumption works normally within each scope.
* **Hello Retry Request.** The selector runs once, on the first
  ClientHello. picotls itself enforces that the SNI is unchanged in the
  second ClientHello of an HRR exchange, so the selected identity is
  stable across the retry.
* **Encrypted Client Hello.** When ECH is accepted, picotls presents
  the decrypted inner ClientHello to the selection logic, so selection
  operates on the real (inner) server name. Configure ECH before
  creating identities (the ECH setter is frozen afterwards). Identity
  contexts share the master context's ECH opener for the lifetime of
  the QUIC context.
* **Mixed client and server contexts.** A QUIC context is not
  restricted to one role. A context with no root store adopts the null
  verifier when its first identity is created, so a client connection
  later opened from the same context still accepts its peer instead of
  being rejected. Configure a root store or a custom verifier before
  creating identities if the context must verify its peers.
* **Logging.** On servers with identity selection configured, the
  accepted SNI and the selection source (selector, exact or wildcard
  registry entry, default) are recorded in the application log / qlog.
  Servers without virtual hosts log exactly as before.

With no selector and no registry entries, server behavior is unchanged
from previous versions of the library.
