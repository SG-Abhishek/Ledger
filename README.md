# Ledger — Personal balances

A private, installable ledger for tracking transfers between you and other people. The app is a progressive web app (PWA), so you can add it to your Android home screen from Chrome. Entries stay in browser storage on that device; there is no bank connection or account.

## Use on Android

1. Put this folder on a static web host that serves HTTPS, or run it from a local development server on your computer and open the address from your phone on the same network.
2. Open the app in Chrome on Android.
3. Open Chrome’s menu and choose **Install app** or **Add to Home screen**.
4. Add transfers with the person, direction, amount, transfer date, and an optional note.

The app shell works offline after the first load. For a personal ledger, make periodic backups from the up-arrow button and keep the downloaded JSON file somewhere safe. Restoring a backup replaces the ledger currently on that device.

## Included

- Separate “they owe you” and “you owe them” transfers, with editable person, amount, direction, date, and note.
- Per-person net balance, overall net metering, separate gross totals in each direction, and a transfer history.
- Partial repayments with dates and notes, plus actions to settle a remainder or undo a repayment.
- Shareable per-person statements through Android's share menu, with date range and settled-transfer options.
- On-device typo suggestions plus saved aliases. Suggestions are never merged automatically; people can also be merged manually. Changing a transfer's name moves that transfer to a separate person.
- Search, direction filters, sorting, rupee-only display, and CSV export.
- A 6–12 digit PIN that encrypts the local ledger using AES-GCM and PBKDF2. The app locks when you request it and after it has been in the background for two minutes.
- Encrypted JSON backups. Choose the same PIN when exporting and restoring; the app does not store it.

## Privacy and limitations

The encrypted ledger is stored in this browser’s local storage. Clearing the browser’s site data or removing the app data can erase it, so keep encrypted backups. The app does not sync across devices, connect to banks, or use an online AI service. Name matching is a local spelling-similarity helper, not an AI model. A short numeric PIN is less resistant to guessing than a longer password; choose a PIN you do not use elsewhere and keep a backup.

All amounts are in Indian rupees.

