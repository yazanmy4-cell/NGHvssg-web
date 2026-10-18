# FF LIKE - Free Fire like bot panel (website)

Standalone project: **backend + complete UI**, Python standard library only, nothing to install.

- Site: dark/light dashboard, big typography, PNG icons only (no SVG, no emojis)
- The visitor must **create an account and log in** before buying anything.
- **Wallet system**: Binance Pay deposit -> Transaction ID -> credit lands on the balance -> orders are paid from the balance with one click.
- Admin can create **coupon codes** (free wallet credit) and **promo codes** (price discount, admin chooses how much it takes off).
- Player info + profile card come from the upstream API through a hidden proxy; the upstream URLs and keys never appear in the frontend.
- Public logs section: every account added to autolike since the first day of the project (UIDs partly hidden).
- Admin panel at `/admin` (not linked anywhere on the public site).

Run: double click `start.bat` (or `python server.py`) then open `http://localhost:8080`.

---

## 1) Run it

```
start.bat          # or: python server.py
```

- The first run shows a menu in the terminal: it starts the browser.
- Root of the site: `http://localhost:8080`
- Admin dashboard: `http://localhost:8080/admin`
- Stop: close the terminal or press Ctrl+C in it.

The server stores everything in `data/state.json` (users, wallets, deposits, orders, coupons, promos, accounts, events). Delete this file to start a fresh history.

## 2) Admin dashboard

The admin is **hidden**: there is no link to it on the public page.

- URL: `http://localhost:8080/admin`
- Default login: user **udp**, password **yazan** (hashed with PBKDF2 on the first start).
- Change the password from Admin -> Settings -> "New admin password" (recommended).

### What the admin can do
- **Send likes now** for any UID (single like wave).
- **Add Auto Like** for any UID and any number of days (the engine accepts any day count).
- **Orders**: see every order, approve a blocked one, reject (money goes back to the customer wallet), delete.
- **Autolike manager**: every run merged with the live engine job (days left, runs done, likes per day), remove a local record or delete the engine job.
- **Users and wallets**: every registered user, balance, orders count; add/remove credit for a user (+10 or -5).
- **Deposits**: Binance transfers sent by users; approve (credit added), reject, or delete an old row.
- **Coupons**: create a code worth X USD of wallet credit, limit the number of uses; the customer redeems it in his wallet.
- **Promo codes**: create a code that takes X percent off the order price at checkout.
- **Settings**: site name, tagline, Binance Pay ID, Binance note, auto activation of orders, auto approval of deposits, profile-card cookie, new admin password.
- **Upstream viewer + events**: inspect the like engine and read the site history.

## 3) Payment flow (customer side)

1. Create an account / log in (no purchase without login).
2. Open **Wallet**, send USDT with Binance Pay to the Pay ID shown there.
3. Paste the **Transaction ID** + the amount, confirm the deposit.
   - If *auto approval of deposits* is ON (default): the credit lands on the balance instantly; the admin double-checks after.
   - If OFF: the admin approves the deposit, then the balance updates.
4. Pick a plan (Auto Like 30/60/120 days, or Like Credit: 1 USD = 10 days), optionally apply a promo code, paste the UID, confirm: the price leaves the wallet and the order activates.

## 4) Profile card image (real API)

The card image is fetched server-side from `info_api_base` in `config.json`.
That API works only for a **logged session** on the source site, so:

1. Open `https://likes.freefire.site` in the browser and log in.
2. F12 -> Network -> click any request to that site -> copy the `Cookie:` header value.
3. Paste it in **Admin -> Settings -> Profile card cookie** (it stays in config.json, never sent to visitors).

Without a cookie the site still shows a nice generated card (name, UID, region, colored by UID).

## 5) Files

```
server.py              whole backend (stdlib only)
config.json            secrets + prices + Pay ID (never shown to visitors)
index.html             public site (login gate, wallet, offers, order, logs)
admin.html             admin dashboard
static/css/style.css   dark/light theme, PNG icon swaps per theme
static/js/app.js       public logic
static/js/admin.js     admin logic
tools/make_assets.py   regenerates every PNG (icons, banners, logo, cards)
data/state.json        runtime state (users, wallets, orders, events...)
start.bat              Windows launcher
```

## 6) Security notes

- Passwords (users and admin) hashed with PBKDF2-HMAC-SHA256 + random salt.
- Sessions: random 32-byte tokens in HTTP-only cookies (SameSite=Lax).
- Every POST needs the `X-Requested-With` header (blocks cross-site form posts).
- Rate limits: register 5/h, deposits 12/h, orders 15/h, promos 30/h per device.
- Login lockout: 8 wrong tries in a row = 10 minutes of pause.
- The owner ID (the Binance Pay ID) is the only "public" piece of the payment info; upstream URLs and the like engine key stay inside config.json.

## 7) Prices (config.json)

- Auto Like 30 days = 1.50 USD, 60 days = 3.00 USD, 120 days = 5.00 USD
- Like Credit: 1 USD = 10 days (the customer picks any amount)
- Change prices in `config.json` -> `autolike_plans` and `credit_rate_days_per_dollar`, or edit them while the server reads config at startup (restart after editing).

## 8) Troubleshooting

- **"Service offline" badge**: the server is not running, or another app uses port 8080 (change `port` in config.json).
- **Player info fails**: the upstream player API is down; try again later, orders still work with the name "Unknown" until info comes back.
- **Card never shows the real photo**: the cookie from section 4 is missing or expired - paste it again.
- **"The like engine is not configured yet"**: fill `like_api` in config.json (base + key).
- **A customer says his deposit was auto-approved wrongly**: Admin -> Users -> set his balance back with a negative amount.
