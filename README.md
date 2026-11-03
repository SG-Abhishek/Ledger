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
- Per-person net balance, open transfer history, and a settled status for transfers that have been repaid.
- Copyable per-person statement and whole-ledger overview.
- On-device typo suggestions based on name similarity. Suggestions are never merged automatically: choose **Use this person** to group with an existing person, or **Keep as new** to create a separate record.
- Search, direction filters, sorting, currency display preference, and JSON backup/restore.

## Privacy and limitations

The ledger is stored in this browser’s local storage. Clearing the browser’s site data or removing the app data can erase it, so keep backups. The app does not sync across devices, encrypt its local records, connect to banks, or use an online AI service. Name matching is a small local spelling-similarity helper, not an AI model. Use a secure device lock and avoid entering sensitive account details in notes.

To use another currency, select it in settings. This changes the display symbol and formatting only; it does not convert values.

