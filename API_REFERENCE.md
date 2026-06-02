# API_REFERENCE — full tool catalog

55 tools across Mail, Calendar, Folder, Settings, Attachment, Shared-mailbox surfaces.

Generated from `src/endpoints.json`. Each entry shows : tool name, HTTP method + Graph path, Graph scope(s) required, write-policy flag needed to enable.

For workflows that combine these tools, see [`USAGE.md`](./USAGE.md). For the underlying Graph endpoints, follow the Microsoft Graph docs links in each tool's `description` (returned by `tools/list`).

## Read-only tools (always registered)

These tools are registered regardless of `--enable-send` / `--enable-write` flags.

### Mail — read

| Tool | Method | Path | Scope |
|---|---|---|---|
| `list-mail-messages` | GET | `/me/messages` | Mail.Read |
| `get-mail-message` | GET | `/me/messages/{message-id}` | Mail.Read |
| `list-mail-folder-messages` | GET | `/me/mailFolders/{mailFolder-id}/messages` | Mail.Read |
| `list-mail-folders` | GET | `/me/mailFolders` | Mail.Read |
| `list-mail-child-folders` | GET | `/me/mailFolders/{mailFolder-id}/childFolders` | Mail.Read |
| `list-mail-attachments` | GET | `/me/messages/{message-id}/attachments` | Mail.Read |
| `get-mail-attachment` | GET | `/me/messages/{message-id}/attachments/{attachment-id}` | Mail.Read |
| `list-mail-rules` | GET | `/me/mailFolders/{mailFolder-id}/messageRules` | MailboxSettings.Read |
| `get-mailbox-settings` | GET | `/me/mailboxSettings` | MailboxSettings.Read |

### Calendar — read

| Tool | Method | Path | Scope |
|---|---|---|---|
| `list-calendars` | GET | `/me/calendars` | Calendars.Read |
| `list-calendar-events` | GET | `/me/events` | Calendars.Read |
| `get-calendar-event` | GET | `/me/events/{event-id}` | Calendars.Read |
| `list-calendar-event-instances` | GET | `/me/events/{event-id}/instances` | Calendars.Read |
| `get-calendar-view` | GET | `/me/calendarView` | Calendars.Read |
| `list-specific-calendar-events` | GET | `/me/calendars/{calendar-id}/events` | Calendars.Read |
| `get-specific-calendar-event` | GET | `/me/calendars/{calendar-id}/events/{event-id}` | Calendars.Read |
| `get-specific-calendar-view` | GET | `/me/calendars/{calendar-id}/calendarView` | Calendars.Read |

### Shared mailbox / shared calendar — read

| Tool | Method | Path | Scope |
|---|---|---|---|
| `list-shared-mailbox-messages` | GET | `/users/{user-id}/messages` | Mail.Read (or delegation) |
| `list-shared-mailbox-folder-messages` | GET | `/users/{user-id}/mailFolders/{mailFolder-id}/messages` | Mail.Read (or delegation) |
| `get-shared-mailbox-message` | GET | `/users/{user-id}/messages/{message-id}` | Mail.Read (or delegation) |
| `list-shared-calendar-events` | GET | `/users/{user-id}/events` | Calendars.Read (or delegation) |
| `get-shared-calendar-view` | GET | `/users/{user-id}/calendarView` | Calendars.Read (or delegation) |

## Write tools — `--enable-send`

Registered only when `--enable-send` is passed (or `OUTLOOK_MCP_ENABLE_SEND=1`).

### Mail — send + drafts

| Tool | Method | Path | Scope |
|---|---|---|---|
| `send-mail` | POST | `/me/sendMail` | Mail.Send |
| `send-shared-mailbox-mail` | POST | `/users/{user-id}/sendMail` | Mail.Send (or delegation) |
| `reply-mail-message` | POST | `/me/messages/{message-id}/reply` | Mail.Send |
| `reply-all-mail-message` | POST | `/me/messages/{message-id}/replyAll` | Mail.Send |
| `forward-mail-message` | POST | `/me/messages/{message-id}/forward` | Mail.Send |
| `send-draft-message` | POST | `/me/messages/{message-id}/send` | Mail.Send |
| `create-draft-email` | POST | `/me/messages` | Mail.ReadWrite |
| `create-reply-draft` | POST | `/me/messages/{message-id}/createReply` | Mail.ReadWrite |
| `create-reply-all-draft` | POST | `/me/messages/{message-id}/createReplyAll` | Mail.ReadWrite |
| `create-forward-draft` | POST | `/me/messages/{message-id}/createForward` | Mail.ReadWrite |

### Mail — modify + delete

| Tool | Method | Path | Scope |
|---|---|---|---|
| `update-mail-message` | PATCH | `/me/messages/{message-id}` | Mail.ReadWrite |
| `delete-mail-message` | DELETE | `/me/messages/{message-id}` | Mail.ReadWrite |
| `move-mail-message` | POST | `/me/messages/{message-id}/move` | Mail.ReadWrite |

### Mail folders

| Tool | Method | Path | Scope |
|---|---|---|---|
| `create-mail-folder` | POST | `/me/mailFolders` | Mail.ReadWrite |
| `create-mail-child-folder` | POST | `/me/mailFolders/{mailFolder-id}/childFolders` | Mail.ReadWrite |
| `update-mail-folder` | PATCH | `/me/mailFolders/{mailFolder-id}` | Mail.ReadWrite |
| `delete-mail-folder` | DELETE | `/me/mailFolders/{mailFolder-id}` | Mail.ReadWrite |

### Mail rules

| Tool | Method | Path | Scope |
|---|---|---|---|
| `create-mail-rule` | POST | `/me/mailFolders/{mailFolder-id}/messageRules` | MailboxSettings.ReadWrite |
| `update-mail-rule` | PATCH | `/me/mailFolders/{mailFolder-id}/messageRules/{messageRule-id}` | MailboxSettings.ReadWrite |
| `delete-mail-rule` | DELETE | `/me/mailFolders/{mailFolder-id}/messageRules/{messageRule-id}` | MailboxSettings.ReadWrite |

### Mailbox settings

| Tool | Method | Path | Scope |
|---|---|---|---|
| `update-mailbox-settings` | PATCH | `/me/mailboxSettings` | MailboxSettings.ReadWrite |

## Write tools — `--enable-write`

Registered only when `--enable-write` is passed (or `OUTLOOK_MCP_ENABLE_WRITE=1`).

### Calendars

| Tool | Method | Path | Scope |
|---|---|---|---|
| `create-calendar` | POST | `/me/calendars` | Calendars.ReadWrite |
| `update-calendar` | PATCH | `/me/calendars/{calendar-id}` | Calendars.ReadWrite |
| `delete-calendar` | DELETE | `/me/calendars/{calendar-id}` | Calendars.ReadWrite |

### Calendar events

| Tool | Method | Path | Scope |
|---|---|---|---|
| `create-calendar-event` | POST | `/me/events` | Calendars.ReadWrite |
| `update-calendar-event` | PATCH | `/me/events/{event-id}` | Calendars.ReadWrite |
| `delete-calendar-event` | DELETE | `/me/events/{event-id}` | Calendars.ReadWrite |
| `create-specific-calendar-event` | POST | `/me/calendars/{calendar-id}/events` | Calendars.ReadWrite |
| `update-specific-calendar-event` | PATCH | `/me/calendars/{calendar-id}/events/{event-id}` | Calendars.ReadWrite |
| `delete-specific-calendar-event` | DELETE | `/me/calendars/{calendar-id}/events/{event-id}` | Calendars.ReadWrite |

### Calendar invitations

| Tool | Method | Path | Scope |
|---|---|---|---|
| `accept-calendar-event` | POST | `/me/events/{event-id}/accept` | Calendars.ReadWrite |
| `decline-calendar-event` | POST | `/me/events/{event-id}/decline` | Calendars.ReadWrite |
| `tentatively-accept-calendar-event` | POST | `/me/events/{event-id}/tentativelyAccept` | Calendars.ReadWrite |

## Parameter conventions

Path parameters in `{braces}` are required when calling. The MCP tool schema (visible via `tools/list`) exposes them as named arguments. Examples :

- `{message-id}` : the `id` field from `list-mail-messages` response
- `{mailFolder-id}` : the `id` field from `list-mail-folders` response, OR a well-known name like `inbox`, `drafts`, `sentitems`
- `{event-id}` : the `id` field from `list-calendar-events`
- `{calendar-id}` : from `list-calendars` (or omit to use the default calendar via the `/me/events` tools instead of `/me/calendars/{id}/events`)
- `{user-id}` : for shared mailbox tools, the UPN (email) or Azure object ID of the shared user

OData query parameters (all optional) for `GET` tools :

- `$top` — page size
- `$skip` — pagination offset
- `$select` — comma-separated field whitelist
- `$filter` — OData filter expression
- `$orderby` — sort spec (e.g., `receivedDateTime desc`)
- `$search` — KQL search (must be quoted, see [`USAGE.md`](./USAGE.md) workflow 3)
- `$expand` — include linked resources

Body parameters for `POST`/`PATCH` tools follow the Microsoft Graph JSON schema. The MCP tool descriptions (visible to the LLM via `tools/list`) embed Graph documentation links and inline tips for common parameter pitfalls.

## Multi-account parameter

When the operator has registered multiple accounts (see [`INSTALL.md`](./INSTALL.md) §7), every tool gains an `account` parameter (enum of registered account usernames). If omitted, the currently-active account is used.

## Tool schema discovery

The canonical source is the running server itself. Call `tools/list` via any MCP client and you'll get the live schema, including the inline `description` and `inputSchema` (JSON Schema) for every tool. This documentation reflects the schema at the time of writing — if you ever see drift, the live schema wins.

```bash
npx @modelcontextprotocol/inspector outlook-mcp-hardened
# → web UI on http://localhost:5173, click "Tools" tab
```

## Egress scope reminder

Every tool ultimately makes a single fetch to either `login.microsoftonline.com` (token operations) or `graph.microsoft.com` (everything else). The egress allowlist enforces this at the network layer ; any tool implementation that tried to reach a third party would crash the server.

## Scope-to-tool quick reference

| Scope | Read tools | Write tools |
|---|---|---|
| `User.Read` | (implicit on every call) | — |
| `Mail.Read` | All `list/get-mail-*`, `get-mail-attachment`, `list-mail-folder*` | — |
| `Mail.ReadWrite` | — | `create-draft-email`, `update-mail-message`, `delete-mail-message`, `move-mail-message`, all `create*/update*/delete-mail-folder/*draft` |
| `Mail.Send` | — | `send-mail`, `send-shared-mailbox-mail`, `reply-*-mail-message`, `forward-mail-message`, `send-draft-message` |
| `Calendars.Read` | All `list/get-calendar*`, all `*-calendar-view`, `list-calendar-event-instances` | — |
| `Calendars.ReadWrite` | — | All `create/update/delete-calendar*`, `accept/decline/tentatively-accept-calendar-event` |
| `MailboxSettings.Read` | `list-mail-rules`, `get-mailbox-settings` | — |
| `MailboxSettings.ReadWrite` | — | `create/update/delete-mail-rule`, `update-mailbox-settings` |
| `offline_access` | (implicit, required for refresh tokens) | — |
| `openid`, `profile` | (implicit OIDC) | — |
