# Talanta Stadium

## Run locally

Install Node.js 24 or newer, then run this command from the project folder:

```powershell
node serve.js
```

Open the customer site at <http://127.0.0.1:4173/> and the administration site at <http://127.0.0.1:4173/admin.html>.

The server uses Node's built-in SQLite support; no npm packages are required. The database is created at `data/talantapass.sqlite` and is retained between server restarts. Keep this file private and back it up securely.

## First administrator setup

On the administration page, create the first administrator using your own name, email, and a password of at least 12 characters. This setup is available only until the first administrator is created; there is no default account or password. Subsequent visits require signing in. The server stores a salted password hash and uses an HTTP-only session cookie.

## Available system functions

Administrators can create, edit, publish, and delete events and configure prices and ticket allocations for each category. Sales dates determine the normal booking window. An administrator can grant a named customer a temporary, recorded exception outside those dates; allocation, event status, payment, and kickoff checks still apply. Customers can register, sign in, select a category and stadium block, request M-Pesa STK Push, track confirmation, download paid ticket PDFs from their account, and receive the PDFs by email when email delivery is configured. Customers and administrators can also exchange private in-app support messages from the customer dashboard and admin message inbox. Messages are stored in the local database and are not SMS texts.

### Enable production booking and M-Pesa

Copy `.env.example` to `.env` and fill in the HTTPS public origin, Daraja production consumer key/secret, STK shortcode/passkey/callback, and the B2C shortcode, initiator, encrypted security credential, and callback token. `PUBLIC_ORIGIN` must be only the origin (for example `https://tickets.example.com`), with no path or trailing slash. B2C API permission and a funded Utility account are required. Set `RESEND_API_KEY` and a sender address verified with Resend for ticket email. Generate independent random keys for ticket encryption, ticket lookup, and callback authentication; never paste these credentials into chat or commit `.env`. The server retries ticket emails from an outbox and email failure does not prevent account downloads.

Daraja must reach the public HTTPS callbacks at `/api/payments/mpesa/callback` and `/api/payments/mpesa/b2c?token=...`; put the local Node service behind your HTTPS reverse proxy/domain. The local development server binds to `127.0.0.1:4173`, so a local-only setup cannot receive Daraja callbacks. The admin revenue page shows confirmed customer sales separately from the current B2C Utility balance and limits M-Pesa payouts to funds supported by both. Payout callbacks are asynchronous; unresolved payouts remain reserved. Safaricom B2C has per-transaction/daily limits and uses the Utility account, which may require funds to be moved from the Working account first. Bank transfers require a separate bank payout integration and are not configured in this app.

Before publishing an event, set each ticket category's allocation, price, sales window, and published status in the admin page. Customers select a stadium block during checkout; the server reserves capacity in both the selected block and ticket category, and the issued ticket PDF names the block. Specific seat numbers are not assigned. Back up the SQLite database and encryption key securely; losing it prevents reprinting issued ticket codes.

The separate `backend/` Python/PostgreSQL project remains a foundation and is not used by the customer/admin pages in this app.

Ticket categories are fixed to Regular (KES 500), VIP (KES 1,500), and VVIP (KES 3,000). The admin Seating Management page configures Blocks A, B, C, and D (15,000 seats each by default, 60,000 total). Event category allocations cannot exceed their combined configured block capacity, and block capacity cannot be reduced below seats already allocated to an event. Set the available seat allocation for each category in the admin event form. Customer pages show remaining seats; a category becomes sold out only after its paid allocation is exhausted. Seats held during an in-progress checkout are temporarily reserved and become available again if payment expires. Stadium capacity changes are recorded in the admin audit log.

## Python/PostgreSQL backend foundation

Backend foundation details: see [backend/README.md](backend/README.md) and
[backend/docs/ARCHITECTURE.md](backend/docs/ARCHITECTURE.md).
