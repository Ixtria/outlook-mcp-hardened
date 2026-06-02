# USAGE — common workflows with `outlook-mcp-hardened`

This document covers the most common workflows an agent (or operator via `mcp-inspector`) performs. For the full tool catalog with parameters, see [`API_REFERENCE.md`](./API_REFERENCE.md). For how to wire a client to the server, see [`CLIENT_CONFIG.md`](./CLIENT_CONFIG.md).

## Tool categories

The 55 tools are split across :

| Category | Count | Examples |
|---|---|---|
| Mail messages | 12 | `list-mail-messages`, `get-mail-message`, `send-mail`, `reply-mail-message`, `forward-mail-message`, `delete-mail-message`, `move-mail-message`, `update-mail-message`, draft variants |
| Mail folders | 6 | `list-mail-folders`, `create-mail-folder`, `update-mail-folder`, `delete-mail-folder`, child folder variants |
| Mail rules | 4 | `list-mail-rules`, `create-mail-rule`, `update-mail-rule`, `delete-mail-rule` |
| Mailbox settings | 2 | `get-mailbox-settings`, `update-mailbox-settings` |
| Attachments | 2 | `list-mail-attachments`, `get-mail-attachment` |
| Shared mailbox (read) | 5 | `list-shared-mailbox-messages`, `get-shared-mailbox-message`, `send-shared-mailbox-mail`, `list-shared-calendar-events`, `get-shared-calendar-view` |
| Calendars | 4 | `list-calendars`, `create-calendar`, `update-calendar`, `delete-calendar` |
| Calendar events | 13 | `list-calendar-events`, `get-calendar-event`, `create-calendar-event`, `update-calendar-event`, `delete-calendar-event`, `accept-calendar-event`, `decline-calendar-event`, `tentatively-accept-calendar-event`, calendar-view + specific-calendar variants |
| Calendar instances | 2 | `list-calendar-event-instances`, `get-calendar-view` |

## Write policy by category

| Default (read-only) | `--enable-send` | `--enable-write` |
|---|---|---|
| All `list-*`, `get-*` tools | Add : `send-mail`, `send-draft-message`, `forward-mail-message`, `reply-mail-message`, `reply-all-mail-message`, `create-draft-email`, `create-forward-draft`, `create-reply-draft`, `create-reply-all-draft`, `delete-mail-message`, `move-mail-message`, `update-mail-message`, `create-mail-folder`, `create-mail-child-folder`, `update-mail-folder`, `delete-mail-folder`, `create-mail-rule`, `update-mail-rule`, `delete-mail-rule`, `update-mailbox-settings`, `send-shared-mailbox-mail` | Add : `create-calendar`, `update-calendar`, `delete-calendar`, `create-calendar-event`, `create-specific-calendar-event`, `update-calendar-event`, `delete-calendar-event`, `update-specific-calendar-event`, `delete-specific-calendar-event`, `accept-calendar-event`, `decline-calendar-event`, `tentatively-accept-calendar-event` |

## Workflow 1 — Read recent mail

The most basic workflow.

**Tool** : `list-mail-messages`

**Parameters** (all optional) :

- `$top` : page size (default 10, max 1000)
- `$select` : fields to return (default : id, subject, from, receivedDateTime, bodyPreview)
- `$filter` : OData filter expression
- `$search` : KQL search query (MUST be wrapped in double quotes — see API_REFERENCE)
- `$orderby` : sort order (e.g., `receivedDateTime desc`)
- `account` : (multi-account mode only) which mailbox

**Example agent prompt** :

```
Use list-mail-messages with $top=20 and $orderby=receivedDateTime desc to fetch my 20 most recent emails.
```

**Returned shape (truncated)** :

```json
{
  "value": [
    {
      "id": "AAMkADcw...",
      "subject": "Q4 review meeting",
      "from": { "emailAddress": { "address": "alice@example.com", "name": "Alice" } },
      "receivedDateTime": "2026-06-02T14:32:11Z",
      "bodyPreview": "Hi, please review the attached..."
    }
  ]
}
```

## Workflow 2 — Read a specific email body

**Tool** : `get-mail-message`

**Parameters** :

- `message-id` (required) : the ID returned by `list-mail-messages`
- `$select` : optionally narrow returned fields

The body is automatically wrapped in `<untrusted_content>` tags so the LLM treats it as data, not instructions. Unicode obfuscation chars (zero-width, BiDi controls, Plane-14 tags) are stripped. Nested wrapper tags in the payload are neutralised with full-width angle brackets.

## Workflow 3 — Search mail

**Tool** : `list-mail-messages` with `$search`

**KQL syntax** (Keyword Query Language) — important constraints :

- The full search expression MUST be wrapped in double quotes : `$search="from:alice"`
- Supported keys : `from:`, `to:`, `cc:`, `bcc:`, `subject:`, `body:`, `attachment:`, `hasAttachments:`, `importance:`, `received:`, `sent:`
- Date filters : `received:2025-06-01..2025-06-30`, `received>=2026-01-01`
- Boolean : `AND`, `OR`, `NOT`
- Grouping : parentheses

**Examples** :

```
$search="from:alice@example.com AND subject:Q4"
$search="hasAttachments:true AND received>=2026-05-01"
$search="(from:alice OR from:bob) AND importance:high"
```

Microsoft Graph KQL reference : https://learn.microsoft.com/en-us/graph/search-query-parameter

## Workflow 4 — Send a new email

Requires `--enable-send`.

**Tool** : `send-mail`

**Parameters** :

```json
{
  "message": {
    "subject": "Re: Q4 review",
    "toRecipients": [
      { "emailAddress": { "address": "alice@example.com" } }
    ],
    "ccRecipients": [
      { "emailAddress": { "address": "bob@example.com" } }
    ],
    "body": {
      "contentType": "Text",
      "content": "Hi Alice,\n\nAttached is the revised draft.\n\n— Jimmy"
    }
  },
  "saveToSentItems": true
}
```

**Returned shape** : `204 No Content` on success.

## Workflow 5 — Reply to an email

Requires `--enable-send`.

**Tool** : `reply-mail-message` (reply to sender) or `reply-all-mail-message` (reply to all recipients)

**Parameters** :

- `message-id` (required) : original message ID
- `comment` : the reply text (Graph wraps it above the quoted original)

Or, for finer control, use `create-reply-draft` to get a draft you can edit before `send-draft-message`.

## Workflow 6 — Forward an email

Requires `--enable-send`.

**Tool** : `forward-mail-message`

**Parameters** :

- `message-id` (required)
- `toRecipients` (required) : array of `{ emailAddress: { address: "..." } }`
- `comment` (optional) : prepended text

## Workflow 7 — Create a draft, edit, send

Requires `--enable-send`.

```
1. create-draft-email  (with the bare draft body)
   → returns the draft message-id
2. update-mail-message (use the draft id, modify subject/body/recipients)
3. send-draft-message  (send it)
```

This pattern is useful when the agent needs to iterate on the content before committing to send.

## Workflow 8 — Move / archive / delete an email

Requires `--enable-send` (yes, "send" gates writes because all mail mutations share the same scope).

- `move-mail-message` : move to another folder (provide `destinationId`)
- `delete-mail-message` : soft-delete (goes to Deleted Items)
- `update-mail-message` : mark as read, flag, categorize

To get folder IDs, use `list-mail-folders`. Well-known folder names : `inbox`, `drafts`, `sentitems`, `deleteditems`, `archive`, `junkemail`.

## Workflow 9 — List calendar events

**Tool** : `list-calendar-events` or `get-calendar-view`

`list-calendar-events` returns events on the user's default calendar with simple filtering. `get-calendar-view` is better for **time-range queries** because it expands recurring events into individual instances.

**Example** (next 7 days) :

```
get-calendar-view with parameters:
  startDateTime=2026-06-02T00:00:00
  endDateTime=2026-06-09T00:00:00
```

## Workflow 10 — Create a calendar event

Requires `--enable-write`.

**Tool** : `create-calendar-event`

```json
{
  "subject": "Q4 review",
  "start": { "dateTime": "2026-06-10T14:00:00", "timeZone": "Europe/Zurich" },
  "end": { "dateTime": "2026-06-10T15:00:00", "timeZone": "Europe/Zurich" },
  "attendees": [
    { "emailAddress": { "address": "alice@example.com" }, "type": "required" }
  ],
  "body": { "contentType": "HTML", "content": "<p>Agenda: ...</p>" },
  "location": { "displayName": "Meeting room A" },
  "isOnlineMeeting": true,
  "onlineMeetingProvider": "teamsForBusiness"
}
```

## Workflow 11 — Respond to a meeting invitation

Requires `--enable-write`.

- `accept-calendar-event`
- `decline-calendar-event`
- `tentatively-accept-calendar-event`

**Parameters** :

- `event-id`
- `comment` (optional)
- `sendResponse` : whether to email the organiser back (default true)

## Workflow 12 — Multi-account

If you registered multiple accounts (`--list-accounts` shows them), every tool gains an additional `account` parameter — an enum of the registered account usernames.

```
list-mail-messages with account="alice@work.example.com" and $top=5
```

If `account` is omitted, the active account (from `--select-account` or the default) is used.

## Workflow 13 — Shared mailbox / shared calendar

If your tenant has shared mailboxes you have delegated access to :

- `list-shared-mailbox-messages` (param : `user-id` = the shared mailbox's UPN or object ID)
- `get-shared-mailbox-message`
- `send-shared-mailbox-mail`
- `list-shared-calendar-events`
- `get-shared-calendar-view`

Note : shared resources require the operator's account to have explicit delegation on the Microsoft side. The MCP server cannot grant access — only consume it.

## Workflow 14 — Mailbox settings

- `get-mailbox-settings` (read-only) : returns timezone, language, automatic replies, working hours
- `update-mailbox-settings` (`--enable-send`) : update any of the above

Common use : update the out-of-office message before vacation.

## Workflow 15 — Mail rules (server-side filters)

- `list-mail-rules` (read-only)
- `create-mail-rule`, `update-mail-rule`, `delete-mail-rule` (`--enable-send`)

Rules execute server-side on every incoming message. Useful for automated triage.

## Workflow 16 — Attachments

- `list-mail-attachments` (read-only) — returns attachment metadata for a message
- `get-mail-attachment` (read-only) — returns one attachment's content as base64

**Write attachments are out of scope v0.3** — there is no `create-mail-attachment` tool. To send an email with an attachment, build the multipart message in `send-mail`'s body. See Microsoft Graph docs : https://learn.microsoft.com/en-us/graph/api/user-sendmail

## Patterns we recommend

### Read-only by default

The default execution mode (`outlook-mcp-hardened` without `--enable-send` / `--enable-write`) registers ZERO write tools. The LLM physically cannot send mail or delete events. This is the safest baseline for agents you don't fully trust.

### Audit log monitoring

In production, ship `mcp-server.log` and the stderr audit JSON stream to your SIEM. Each Graph call emits :

```json
{"ts":"2026-06-02T14:32:11Z","tool":"list-mail-messages","method":"GET","path":"/me/messages","scopes":["Mail.Read","User.Read"],"account":"hmac-sha256:abc12345...","status":200,"duration_ms":142}
```

The `account` field is HMAC-SHA256 hashed (per-installation salt) so logs can be aggregated cross-host without leaking PII, while still allowing per-installation correlation.

### Combine with a stricter MCP gateway

If you don't fully trust the LLM driving this MCP server, layer a gateway (such as a custom tool-call filter) in front. The `outlook-mcp-hardened` server already :

- defaults to read-only
- audits every call
- rejects PII / Bearer / JWT patterns in logs
- enforces egress to Microsoft only

But the LLM still decides WHICH tool to call. A gateway can add policy on top (e.g., "never allow `send-mail` to external domains during business hours").

## Errors

Tools may throw any of :

- `401 Unauthorized` — token expired or revoked. Run `outlook-mcp-hardened --login` again.
- `403 Forbidden` — your app registration lacks the required scope. Check the [API_REFERENCE](./API_REFERENCE.md) for required scopes and ensure admin consent in Azure portal.
- `429 Too Many Requests` — Graph throttling. Back off and retry.
- `EgressViolationError` — internal bug : the server tried to fetch a host outside the allowlist. File a security report.

For full error troubleshooting : [`TROUBLESHOOTING.md`](./TROUBLESHOOTING.md).
