# FreightLogic Cloud Backup — Setup Guide
## Free automatic encrypted backups in 5 minutes

### What this does
Every time you add a trip, expense, or fuel entry, FreightLogic automatically encrypts your data with your passphrase and pushes it to your personal Cloudflare Worker. Your data is encrypted on your phone BEFORE it touches the internet. Cloudflare never sees your plaintext data.

### What it costs
**Free.** Cloudflare Workers free tier gives you 100,000 requests/day and 1GB KV storage. You'll use maybe 50 requests/day. Daily backups are kept for 30 days automatically.

---

## Step 1: Create a Cloudflare account
1. Go to **https://dash.cloudflare.com/sign-up**
2. Sign up with your email (no credit card needed)
3. Verify your email

## Step 2: Create a KV namespace
1. In the Cloudflare dashboard, click **Workers & Pages** in the left sidebar
2. Click **KV** in the submenu
3. Click **Create a namespace**
4. Name it `freightlogic-backups`
5. Click **Add**

## Step 3: Create the Worker
1. Click **Workers & Pages** → **Create**
2. Click **Create Worker**
3. Name it `freightlogic-backup`
4. Click **Deploy** (deploys the default hello-world code)
5. Click **Edit Code**
6. **Delete all the default code**
7. Open the file `cloud-backup-worker.js` from this zip
8. Copy the ENTIRE contents and paste it into the editor
9. Click **Deploy** (top right)

## Step 4: Bind KV storage
1. Go back to your Worker's page
2. Click **Settings** → **Variables and Secrets**
3. Scroll to **KV Namespace Bindings**
4. Click **Add**
5. Variable name: `BACKUPS`
6. KV Namespace: select `freightlogic-backups`
7. Click **Save**

## Step 5: Get your Worker URL
1. Go to your Worker's page
2. Your URL is shown at the top, like:
   `https://freightlogic-backup.YOUR-NAME.workers.dev`
3. Copy it

## Step 6: Configure FreightLogic
1. Open FreightLogic on your phone
2. Go to **More** → **Tax & Reports** → scroll to **Settings**
3. Scroll to **☁️ Cloud Backup**
4. Paste your Worker URL into **Backup URL**
5. Choose a strong **Encryption Passphrase** (at least 12 characters)
6. Tap **Save**
7. Tap **☁️ Backup Now** to test

If you see "☁️ Backup synced to cloud" — you're done. From now on, every data change auto-syncs within 30 seconds.

---

## How to restore from cloud backup
1. Open FreightLogic (even on a new device)
2. Go to Settings → Cloud Backup
3. Enter the same Worker URL and the same passphrase
4. Tap **📥 Restore**
5. Confirm the restore

---

## Important notes

- **Your passphrase is your key.** If you forget it, your cloud backups cannot be decrypted. Write it down somewhere safe.
- **Your passphrase never leaves your phone.** It's used locally to encrypt/decrypt. The Worker never sees it.
- **Each device gets its own backup slot.** If you use FreightLogic on your phone and your laptop, each gets a separate backup keyed by device ID.
- **Daily snapshots are kept for 30 days.** If something goes wrong, Cloudflare has the last 30 days of daily backups.
- **Data syncs automatically** whenever you add/edit/delete trips, expenses, or fuel, and when you close or switch away from the app.
- **Works offline gracefully.** If you have no internet, the sync just silently skips. It'll push next time you're online.
