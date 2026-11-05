# HaloPSA tickets

BearWatch keeps one HaloPSA ticket per fix per client. A fix is one Windows update, one app
update or one settings change, the same rows as the dashboard.

- **When a ticket opens:** the fix covers a known exploited vulnerability, or its risk score is
  50 or more (`BEARWATCH_HALO_MIN_RISK`), or it is past its fix deadline. Findings under an
  exception don't count toward this.
- **What it says:** the PCs that need the fix, the CVEs it closes, the deadline, and a link to the
  fix page when `BEARWATCH_PUBLIC_URL` is set.
- **Updates:** when the list of PCs or CVEs changes, the ticket details are rewritten and a
  private note says so.
- **Closing:** when no PC needs the fix any more (BearWatch saw it fixed, not just a technician
  saying so), BearWatch adds a note and sets the closed status.
- **Closed by hand:** if a technician closes the ticket in Halo while PCs still need the fix,
  BearWatch notices at its next update and opens a new ticket.
- **A fix that comes back** gets a new ticket.

The worker runs this every 15 minutes, right after it evaluates devices. A failed call is
recorded on that ticket's row and retried next time; it doesn't stop the other tickets. The
overview's data table shows the last run as "HALO".

## Setting it up

1. In Halo, create an API application: **Configuration > Integrations > HaloPSA API > View
   Applications > New**. Use the Client ID and Secret authentication method, the **all**
   permission scope, and an agent to act as (for example a "BearWatch" agent).
2. Set these in the server's `.env`. The secret stays in `.env`; never commit it.

   ```
   BEARWATCH_HALO_URL=https://yourcompany.halopsa.com
   BEARWATCH_HALO_CLIENT_ID=...
   BEARWATCH_HALO_CLIENT_SECRET=...
   BEARWATCH_HALO_TENANT=            # hosted Halo only, if your instance needs it
   BEARWATCH_HALO_TICKET_TYPE_ID=    # optional; Halo's default type otherwise
   BEARWATCH_HALO_CLOSED_STATUS_ID=9 # your "Closed" status id
   BEARWATCH_HALO_NOTE_OUTCOME=Private Note
   BEARWATCH_PUBLIC_URL=https://bearwatch.example.com
   ```
3. On each client's page in BearWatch, enter its Halo client id. Or run
   `bearwatch halo client <client id> <halo client id>`. Clients without one get no tickets.
4. Run `bearwatch halo sync`. While `BEARWATCH_HALO_DRY_RUN` is on (the default), it prints the
   tickets it would create, update or close, and sends and saves nothing. The worker does
   nothing in dry run.
5. When the list looks right, set `BEARWATCH_HALO_DRY_RUN=false` and restart the worker.

## Check before going live

All Halo calls are in `HaloApi` in `server/bearwatch/halo.py`. Check them against your
instance's own API reference at `https://<your instance>/apidoc` before turning dry run off:

| Call | What BearWatch sends |
|---|---|
| Sign in | `POST /auth/token`, form fields `grant_type=client_credentials`, `client_id`, `client_secret`, `scope=all`, and `tenant` if set |
| New ticket | `POST /api/tickets` with a one-item list: `summary`, `details`, `client_id`, and `tickettype_id` if set |
| Update ticket | `POST /api/tickets` with a one-item list holding `id` and the changed fields (`details`, or `status_id` to close) |
| Private note | `POST /api/actions` with a one-item list: `ticket_id`, `note`, `outcome`, `hiddenfromuser: true` |
| Is it still open? | `GET /api/tickets/{id}`, reading `status_id` |

In particular, confirm the closed status id and the note outcome name used in your Halo.
