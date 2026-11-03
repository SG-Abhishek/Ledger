(() => {
  'use strict';

  // Constants & Storage Keys
  const DB_NAME = 'ledger_vault_db';
  const DB_STORE = 'vault_store';
  const VAULT_RECORD_KEY = 'encrypted_vault';
  const SETTINGS_KEY = 'ledger.settings.v2';
  const BIO_META_KEY = 'ledger.bio.prf.v1';
  const AUTO_LOCK_MS = 2 * 60 * 1000; // 2 minutes

  // Currency symbols & configurations
  const CURRENCIES = {
    INR: { code: 'INR', symbol: '₹', locale: 'en-IN' },
    USD: { code: 'USD', symbol: '$', locale: 'en-US' },
    EUR: { code: 'EUR', symbol: '€', locale: 'de-DE' },
    GBP: { code: 'GBP', symbol: '£', locale: 'en-GB' },
    AED: { code: 'AED', symbol: 'د.إ', locale: 'ar-AE' }
  };

  const $ = (id) => document.getElementById(id);

  // In-memory application state
  let entries = [];
  let aliases = {};
  let settings = loadSettings();
  let filter = 'all';
  let query = '';
  let sort = 'recent';
  let selectedPersonId = null;
  let chosenPerson = null;

  // Cryptographic session state (never written to disk unencrypted)
  let cryptoKey = null;
  let vaultSalt = null;
  let lockMode = 'unlock'; // 'unlock' | 'setup' | 'change'
  let backgroundTimestamp = null;
  let toastTimer = null;
  let pendingConfirmResolve = null;
  let pendingBackupPinResolve = null;

  // Undo stack
  const undoStack = [];

  // ==========================================
  // Storage: IndexedDB Wrapper
  // ==========================================
  function openDatabase() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(DB_STORE)) {
          db.createObjectStore(DB_STORE);
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async function idbGet(key) {
    try {
      const db = await openDatabase();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(DB_STORE, 'readonly');
        const req = tx.objectStore(DB_STORE).get(key);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    } catch {
      return localStorage.getItem(key);
    }
  }

  async function idbSet(key, val) {
    try {
      const db = await openDatabase();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(DB_STORE, 'readwrite');
        tx.objectStore(DB_STORE).put(val, key);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    } catch {
      localStorage.setItem(key, typeof val === 'string' ? val : JSON.stringify(val));
    }
  }

  // ==========================================
  // Cryptography Helpers
  // ==========================================
  function bytes64(bytes) {
    let binary = '';
    const buf = new Uint8Array(bytes);
    for (let i = 0; i < buf.length; i++) binary += String.fromCharCode(buf[i]);
    return btoa(binary);
  }

  function from64(str) {
    const bin = atob(str);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  async function deriveKeyFromPin(pin, salt) {
    const rawPin = new TextEncoder().encode(String(pin));
    const baseKey = await crypto.subtle.importKey('raw', rawPin, 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 250000, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      true, // extractable for secure hardware wrapping
      ['encrypt', 'decrypt']
    );
  }

  async function encryptPayload(data, key, salt) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(JSON.stringify(data));
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
    return {
      format: 'ledger-encrypted-v2',
      salt: bytes64(salt),
      iv: bytes64(iv),
      data: bytes64(encrypted)
    };
  }

  async function decryptPayload(box, key) {
    const iv = from64(box.iv);
    const data = from64(box.data);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    return JSON.parse(new TextDecoder().decode(decrypted));
  }

  // ==========================================
  // Vault Persistence (Synchronized)
  // ==========================================
  let saveQueue = Promise.resolve();
  function save() {
    if (!cryptoKey || !vaultSalt) return Promise.resolve();
    const snapshot = { entries, aliases, settings };
    const currentKey = cryptoKey;
    const currentSalt = vaultSalt;

    saveQueue = saveQueue.then(async () => {
      const box = await encryptPayload(snapshot, currentKey, currentSalt);
      await idbSet(VAULT_RECORD_KEY, JSON.stringify(box));
    }).catch((err) => {
      console.error(err);
      toast('Failed to save encrypted vault');
    });

    return saveQueue;
  }

  // ==========================================
  // WebAuthn PRF Biometrics (Zero Plaintext Leak)
  // ==========================================
  function isPrfSupported() {
    return !!(window.PublicKeyCredential && PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable);
  }

  async function registerBiometricKey(masterKey) {
    if (!isPrfSupported()) return false;
    try {
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const userId = crypto.getRandomValues(new Uint8Array(16));
      const prfSalt = crypto.getRandomValues(new Uint8Array(32));

      const cred = await navigator.credentials.create({
        publicKey: {
          challenge,
          rp: { name: 'Ledger Local', id: location.hostname },
          user: { id: userId, name: 'vault-user', displayName: 'Vault User' },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
          authenticatorSelection: {
            authenticatorAttachment: 'platform',
            userVerification: 'required',
            residentKey: 'preferred'
          },
          extensions: {
            prf: { eval: { first: prfSalt } }
          }
        }
      });

      if (!cred || !cred.rawId) return false;
      const extResults = cred.getClientExtensionResults();
      if (!extResults.prf?.results?.first) {
        toast('Device does not support hardware PRF key derivation');
        return false;
      }

      // Derive symmetric wrapping key from PRF output
      const prfKeyMaterial = extResults.prf.results.first;
      const bioKey = await crypto.subtle.importKey('raw', prfKeyMaterial, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);

      // Export and encrypt the master vault key
      const rawMasterKey = await crypto.subtle.exportKey('raw', masterKey);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, bioKey, rawMasterKey);

      const meta = {
        enabled: true,
        credId: bytes64(cred.rawId),
        prfSalt: bytes64(prfSalt),
        iv: bytes64(iv),
        wrappedKey: bytes64(wrapped),
        vaultSalt: bytes64(vaultSalt)
      };

      localStorage.setItem(BIO_META_KEY, JSON.stringify(meta));
      settings.biometricEnabled = true;
      persistSettings();
      return true;
    } catch (e) {
      console.warn('Biometric registration error:', e);
      return false;
    }
  }

  async function unlockWithBiometric() {
    const rawMeta = localStorage.getItem(BIO_META_KEY);
    if (!rawMeta) return false;
    try {
      const meta = JSON.parse(rawMeta);
      const prfSalt = from64(meta.prfSalt);

      const cred = await navigator.credentials.get({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rpId: location.hostname,
          userVerification: 'required',
          allowCredentials: [{
            type: 'public-key',
            id: from64(meta.credId),
            transports: ['internal']
          }],
          extensions: {
            prf: { eval: { first: prfSalt } }
          }
        }
      });

      if (!cred) return false;
      const extResults = cred.getClientExtensionResults();
      const prfKeyMaterial = extResults.prf?.results?.first;
      if (!prfKeyMaterial) return false;

      // Import PRF derived key and unwrap master key
      const bioKey = await crypto.subtle.importKey('raw', prfKeyMaterial, { name: 'AES-GCM' }, false, ['decrypt']);
      const rawMasterKey = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: from64(meta.iv) },
        bioKey,
        from64(meta.wrappedKey)
      );

      // Re-import the master cryptoKey
      cryptoKey = await crypto.subtle.importKey('raw', rawMasterKey, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
      vaultSalt = from64(meta.vaultSalt);

      // Load and decrypt vault
      const rawBox = await idbGet(VAULT_RECORD_KEY);
      if (rawBox) {
        const box = typeof rawBox === 'string' ? JSON.parse(rawBox) : rawBox;
        const decrypted = await decryptPayload(box, cryptoKey);
        entries = decrypted.entries || [];
        aliases = decrypted.aliases || {};
        settings = { ...settings, ...(decrypted.settings || {}) };
      }

      render();
      $('lockDialog').close();
      toast('Unlocked via Biometrics');
      return true;
    } catch (e) {
      console.warn('Biometric unlock failed:', e);
      return false;
    }
  }

  // ==========================================
  // Vault Lifecycle & Unlock
  // ==========================================
  async function loadVault(pin) {
    const rawBox = await idbGet(VAULT_RECORD_KEY);
    if (rawBox) {
      const box = typeof rawBox === 'string' ? JSON.parse(rawBox) : rawBox;
      vaultSalt = from64(box.salt);
      cryptoKey = await deriveKeyFromPin(pin, vaultSalt);
      const decrypted = await decryptPayload(box, cryptoKey);
      entries = decrypted.entries || [];
      aliases = decrypted.aliases || {};
      settings = { ...settings, ...(decrypted.settings || {}) };
    } else {
      vaultSalt = crypto.getRandomValues(new Uint8Array(16));
      cryptoKey = await deriveKeyFromPin(pin, vaultSalt);
      entries = [];
      aliases = {};
      await save();
    }
    render();
    $('lockDialog').close();
    $('pinInput').value = '';
    $('pinConfirm').value = '';
    toast('Vault unlocked');
  }

  function showPinDialog(mode) {
    lockMode = mode;
    $('pinError').textContent = '';
    $('pinInput').value = '';
    $('pinConfirm').value = '';
    $('pinConfirmWrap').hidden = mode === 'unlock';
    $('lockTitle').textContent = mode === 'setup' ? 'Protect your ledger' : mode === 'change' ? 'Change your PIN' : 'Unlock your ledger';
    $('lockCopy').textContent = mode === 'setup'
      ? 'Choose a 4 to 6 digit PIN. Keep it safe: a forgotten PIN cannot be recovered.'
      : mode === 'change'
      ? 'Choose a new PIN. Your vault will be re-encrypted.'
      : 'Enter your PIN to decrypt your balances.';
    $('pinSubmit').textContent = mode === 'setup' ? 'Create PIN' : mode === 'change' ? 'Update PIN' : 'Unlock';

    const bioBtn = $('biometricButton');
    const hasBio = !!localStorage.getItem(BIO_META_KEY);
    bioBtn.hidden = !(mode === 'unlock' && hasBio);

    $('lockDialog').showModal();
    setTimeout(() => $('pinInput').focus(), 100);

    if (mode === 'unlock' && hasBio) {
      unlockWithBiometric().catch(() => {});
    }
  }

  function lockLedger() {
    for (const dialog of document.querySelectorAll('dialog')) {
      if (dialog.open) dialog.close();
    }
    entries = [];
    aliases = {};
    cryptoKey = null;
    vaultSalt = null;
    $('personDetail').innerHTML = '';
    render();
    showPinDialog('unlock');
  }

  // ==========================================
  // Financial Calculations & Formatters (Minor units: Paise/Cents)
  // ==========================================
  function parseToMinorUnits(amount) {
    return Math.round(Number(amount || 0) * 100);
  }

  function money(minorUnits) {
    const cur = CURRENCIES[settings.currency] || CURRENCIES.INR;
    const value = Math.abs(minorUnits || 0) / 100;
    return new Intl.NumberFormat(cur.locale, {
      style: 'currency',
      currency: cur.code,
      minimumFractionDigits: 2
    }).format(value);
  }

  function remainingMinor(entry) {
    if (entry.status === 'paid') return 0;
    const total = parseToMinorUnits(entry.amount);
    const paid = (entry.payments || []).reduce((acc, p) => acc + parseToMinorUnits(p.amount), 0);
    return Math.max(0, total - paid);
  }

  function dateText(iso) {
    if (!iso) return '';
    return new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short', year: 'numeric' }).format(new Date(`${iso}T12:00:00`));
  }

  function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function today() {
    const d = new Date();
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  }

  // ==========================================
  // Settings & Themes
  // ==========================================
  function loadSettings() {
    try {
      return { currency: 'INR', theme: 'system', ...JSON.parse(localStorage.getItem(SETTINGS_KEY) || '{}') };
    } catch {
      return { currency: 'INR', theme: 'system' };
    }
  }

  function persistSettings() {
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
    void save();
  }

  function applyTheme() {
    const t = settings.theme || 'system';
    if (t === 'system') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', t);

    const isDark = t === 'dark' || (t === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', isDark ? '#0c1420' : '#f7f8f9');

    // Update currency prefixes
    const prefix = CURRENCIES[settings.currency]?.symbol || '₹';
    document.querySelectorAll('.currency-prefix').forEach(el => el.textContent = prefix);
  }

  // ==========================================
  // Aggregation & Rendering
  // ==========================================
  function people() {
    const map = new Map();
    for (const e of entries) {
      const id = e.personId || `legacy-${e.name.toLowerCase()}`;
      if (!map.has(id)) {
        map.set(id, {
          id,
          name: e.name,
          aliases: aliases[id] || [],
          entries: [],
          netMinor: 0,
          toYouMinor: 0,
          youOweMinor: 0,
          latest: ''
        });
      }
      const p = map.get(id);
      p.entries.push(e);
      const rem = remainingMinor(e);
      if (e.direction === 'toYou') {
        p.netMinor += rem;
        p.toYouMinor += rem;
      } else {
        p.netMinor -= rem;
        p.youOweMinor += rem;
      }
      if (e.date > p.latest) p.latest = e.date;
    }
    return [...map.values()];
  }

  function render() {
    const ps = people();
    let toYouMinor = 0, youOweMinor = 0, toCount = 0, oweCount = 0;

    for (const p of ps) {
      toYouMinor += p.toYouMinor;
      youOweMinor += p.youOweMinor;
      if (p.toYouMinor > 0) toCount++;
      if (p.youOweMinor > 0) oweCount++;
    }

    const netMinor = toYouMinor - youOweMinor;
    $('owedToYou').textContent = money(toYouMinor);
    $('youOwe').textContent = money(youOweMinor);
    $('netBalance').textContent = (netMinor < 0 ? '−' : '') + money(Math.abs(netMinor));
    $('netCaption').textContent = netMinor === 0 ? 'All settled up' : netMinor > 0 ? 'You are owed more overall' : 'You owe more overall';
    $('toYouCount').textContent = toCount;
    $('oweCount').textContent = oweCount;
    $('allCount').textContent = ps.length;

    renderAnalytics(ps);

    let visible = ps.filter(p => {
      const matchQuery = !query || (p.name + ' ' + p.entries.map(e => e.note || '').join(' ')).toLowerCase().includes(query);
      const matchFilter = filter === 'all' || (filter === 'owed' && p.toYouMinor > 0) || (filter === 'owe' && p.youOweMinor > 0);
      return matchQuery && matchFilter;
    });

    visible.sort((a, b) => {
      if (sort === 'name') return a.name.localeCompare(b.name);
      if (sort === 'amount') return Math.abs(b.netMinor) - Math.abs(a.netMinor);
      return b.latest.localeCompare(a.latest);
    });

    const list = $('peopleList');
    if (!visible.length) {
      list.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">◈</div>
          <h3>${ps.length ? 'No matching people found' : 'No transfers yet'}</h3>
          <p>${ps.length ? 'Try a different search term or change your active filter.' : 'Record a transfer you lent or borrowed to keep clear records.'}</p>
          ${ps.length ? '' : '<button class="primary-button" id="emptyAddBtn">＋ Add your first transfer</button>'}
        </div>`;
      $('emptyAddBtn')?.addEventListener('click', openAdd);
      return;
    }

    list.innerHTML = visible.map((p, i) => {
      const initials = (p.name.trim().split(/\s+/).map(x => x[0]).slice(0, 2).join('') || '?').toUpperCase();
      const isSettled = p.toYouMinor === 0 && p.youOweMinor === 0;
      const statusClass = p.netMinor > 0 ? 'positive' : p.netMinor < 0 ? 'negative' : '';
      const statusLabel = isSettled ? 'Settled' : p.netMinor > 0 ? 'Owes you' : 'You owe';
      const openCount = p.entries.filter(e => remainingMinor(e) > 0).length;

      return `
        <article class="person-row" data-person="${esc(p.id)}">
          <div class="person-ident">
            <div class="person-avatar c${(i % 4) + 1}">${esc(initials)}</div>
            <div style="min-width:0">
              <div class="person-name">${esc(p.name)}</div>
              <div class="person-meta">${p.entries.length} transfer${p.entries.length === 1 ? '' : 's'}${openCount ? ` · ${openCount} open` : ''} · ${dateText(p.latest)}</div>
            </div>
          </div>
          <div class="amount-block">
            <div class="money ${statusClass}">${p.netMinor < 0 ? '−' : ''}${money(Math.abs(p.netMinor))}</div>
            <small>${statusLabel}</small>
          </div>
          <span class="row-arrow">›</span>
        </article>`;
    }).join('');

    list.querySelectorAll('[data-person]').forEach(row => {
      row.addEventListener('click', () => openPerson(row.dataset.person));
    });
  }

  function renderAnalytics(ps) {
    const el = $('analyticsCard');
    if (!ps.length) {
      el.innerHTML = '';
      return;
    }
    const topOwed = [...ps].filter(p => p.toYouMinor > 0).sort((a, b) => b.toYouMinor - a.toYouMinor)[0];
    const topYouOwe = [...ps].filter(p => p.youOweMinor > 0).sort((a, b) => b.youOweMinor - a.youOweMinor)[0];
    const oldest = entries.filter(e => remainingMinor(e) > 0).sort((a, b) => a.date.localeCompare(b.date))[0];

    let html = '<div class="analytics-card"><div class="card-label"><span class="label-icon">◇</span> INSIGHTS</div>';
    if (topOwed) html += `<div class="insight-row">Highest owed to you · <b>${esc(topOwed.name)}</b> (${money(topOwed.toYouMinor)})</div>`;
    if (topYouOwe) html += `<div class="insight-row">You owe most to · <b>${esc(topYouOwe.name)}</b> (${money(topYouOwe.youOweMinor)})</div>`;
    if (oldest) html += `<div class="insight-row">Oldest active transfer · <b>${esc(oldest.name)}</b> from ${dateText(oldest.date)}</div>`;
    html += '</div>';
    el.innerHTML = html;
  }

  // ==========================================
  // Person Detail & Settlement Actions
  // ==========================================
  function openPerson(id) {
    const p = people().find(x => x.id === id);
    if (!p) return;
    selectedPersonId = id;

    const netClass = p.netMinor > 0 ? '#3dcea8' : p.netMinor < 0 ? '#ee9289' : 'white';
    const directionLabel = p.netMinor > 0 ? 'owes you' : p.netMinor < 0 ? 'you owe' : 'settled';
    const activity = [...p.entries].sort((a, b) => b.date.localeCompare(a.date));

    $('personDetail').innerHTML = `
      <div class="person-detail-head">
        <div class="dialog-head">
          <div><p class="eyebrow">PERSON BALANCE</p><h2>${esc(p.name)}</h2></div>
          <button type="button" class="close-button" data-close="personDialog" aria-label="Close">×</button>
        </div>
        <div class="detail-total" style="color:${netClass}">${p.netMinor < 0 ? '−' : ''}${money(Math.abs(p.netMinor))}</div>
        <div class="detail-label">${directionLabel} · ${money(Math.abs(p.netMinor))} net</div>
        <div class="detail-summary">
          <span>OWED TO YOU<b>${money(p.toYouMinor)}</b></span>
          <span>YOU OWE<b>${money(p.youOweMinor)}</b></span>
        </div>
      </div>
      <div class="person-detail-body">
        <div class="detail-actions">
          <button class="primary-button" id="addForPerson">＋ Add transfer</button>
          <button class="secondary-button" id="sharePerson">Share statement</button>
        </div>
        <div class="detail-actions">
          <button class="secondary-button" id="settleAllBtn" style="color:var(--green);border-color:var(--green)">Settle all balances</button>
          <button class="secondary-button" id="manageAliases">Aliases</button>
          <button class="secondary-button" id="mergePerson">Merge</button>
        </div>
        <div class="activity-label">TRANSFER HISTORY (${p.entries.length})</div>
        ${activity.map(e => {
          const remMinor = remainingMinor(e);
          return `
            <div class="activity-item" data-entry="${esc(e.id)}">
              <div>
                <b>${e.direction === 'toYou' ? 'They owe you' : 'You owe them'} · ${money(parseToMinorUnits(e.amount))}</b>
                <small>
                  ${remMinor > 0 ? `${money(remMinor)} remaining · ` : e.status === 'paid' ? 'Settled · ' : ''}
                  ${dateText(e.date)}
                  ${e.dueDate ? ` · Due ${dateText(e.dueDate)}${e.dueDate < today() && remMinor > 0 ? ' ⚠ Overdue' : ''}` : ''}
                  ${e.note ? ` · ${esc(e.note)}` : ''}
                </small>
                <div class="payment-history">
                  ${(e.payments || []).map((x, j) => `
                    <div>
                      ↳ Repaid ${money(parseToMinorUnits(x.amount))} on ${dateText(x.date)}${x.note ? ` (${esc(x.note)})` : ''}
                      <button type="button" class="undo-payment" data-entry="${esc(e.id)}" data-index="${j}">Remove</button>
                    </div>
                  `).join('')}
                </div>
              </div>
              <div class="activity-tools">
                ${remMinor > 0 ? `
                  <button class="status-chip record-repay" data-id="${esc(e.id)}">Record repayment</button>
                  <button class="status-chip toggle-paid" data-id="${esc(e.id)}">Mark paid</button>
                ` : `
                  <button class="status-chip toggle-paid" data-id="${esc(e.id)}">Reopen</button>
                `}
              </div>
            </div>`;
        }).join('')}
      </div>`;

    $('personDialog').showModal();

    // Event handlers inside person sheet
    $('personDetail').querySelector('[data-close]').onclick = () => $('personDialog').close();

    $('addForPerson').onclick = () => {
      $('personDialog').close();
      openAdd();
      $('personName').value = p.name;
      chosenPerson = p;
    };

    $('sharePerson').onclick = () => {
      const summary = generatePersonStatement(p);
      shareContent(summary, `Balance with ${p.name}`);
    };

    $('settleAllBtn').onclick = async () => {
      const openTransfers = p.entries.filter(e => remainingMinor(e) > 0);
      if (!openTransfers.length) {
        toast('No open balance to settle');
        return;
      }
      const confirmed = await showConfirmModal(`Settle all with ${p.name}?`, `This will mark all ${openTransfers.length} open transfer(s) as settled.`);
      if (!confirmed) return;

      const snapshot = openTransfers.map(e => ({ id: e.id, status: e.status }));
      openTransfers.forEach(e => e.status = 'paid');
      pushUndo({ type: 'settleAll', entries: snapshot });
      await save();
      render();
      openPerson(id);
      toast('All balances marked settled', true);
    };

    $('manageAliases').onclick = () => openAliases(p);
    $('mergePerson').onclick = () => openMerge(p);

    $('personDetail').querySelectorAll('.record-repay').forEach(btn => {
      btn.onclick = (e) => {
        e.stopPropagation();
        openRepayment(btn.dataset.id);
      };
    });

    $('personDetail').querySelectorAll('.toggle-paid').forEach(btn => {
      btn.onclick = async (e) => {
        e.stopPropagation();
        const item = entries.find(x => x.id === btn.dataset.id);
        if (!item) return;
        const prevStatus = item.status;
        item.status = item.status === 'paid' ? 'open' : 'paid';
        pushUndo({ type: 'toggleStatus', id: item.id, prevStatus });
        await save();
        render();
        openPerson(id);
        toast(item.status === 'paid' ? 'Transfer settled' : 'Transfer reopened', true);
      };
    });

    $('personDetail').querySelectorAll('.undo-payment').forEach(btn => {
      btn.onclick = async (e) => {
        e.stopPropagation();
        const item = entries.find(x => x.id === btn.dataset.entry);
        if (!item) return;
        const removed = item.payments.splice(+btn.dataset.index, 1)[0];
        item.status = 'open';
        pushUndo({ type: 'addPayment', entryId: item.id, payment: removed });
        await save();
        render();
        openPerson(id);
        toast('Repayment removed', true);
      };
    });

    $('personDetail').querySelectorAll('.activity-item').forEach(el => {
      el.onclick = (e) => {
        if (e.target.closest('button')) return;
        $('personDialog').close();
        editEntry(el.dataset.entry);
      };
    });
  }

  // ==========================================
  // Form Operations: Add / Edit Transfer
  // ==========================================
  function openAdd() {
    chosenPerson = null;
    $('entryForm').reset();
    $('entryId').value = '';
    $('transferDate').value = today();
    $('dueDate').value = '';
    $('formEyebrow').textContent = 'NEW TRANSFER';
    $('formTitle').textContent = 'Add a transfer';
    $('deleteEntry').hidden = true;
    $('matchHint').hidden = true;
    $('entryDialog').showModal();
    setTimeout(() => $('personName').focus(), 100);
  }

  function editEntry(id) {
    const e = entries.find(x => x.id === id);
    if (!e) return;
    chosenPerson = null;
    $('entryId').value = e.id;
    $('personName').value = e.name;
    $('amount').value = e.amount;
    $('transferDate').value = e.date;
    $('dueDate').value = e.dueDate || '';
    $('note').value = e.note || '';
    document.querySelector(`input[name="direction"][value="${e.direction}"]`).checked = true;
    $('formEyebrow').textContent = 'EDIT TRANSFER';
    $('formTitle').textContent = 'Edit transfer';
    $('deleteEntry').hidden = false;
    $('matchHint').hidden = true;
    $('entryDialog').showModal();
  }

  $('entryForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = $('entryId').value;
    const prior = id ? entries.find(x => x.id === id) : null;
    const name = $('personName').value.trim();
    if (!name) return;

    const amountFloat = Number($('amount').value);
    const amountMinor = parseToMinorUnits(amountFloat);

    if (prior) {
      const repaidMinor = (prior.payments || []).reduce((acc, p) => acc + parseToMinorUnits(p.amount), 0);
      if (amountMinor < repaidMinor) {
        toast('Amount cannot be less than repayments already recorded');
        return;
      }
    }

    const item = {
      id: id || crypto.randomUUID(),
      personId: chosenPerson?.id || prior?.personId || crypto.randomUUID(),
      name: chosenPerson?.name || name,
      direction: document.querySelector('input[name="direction"]:checked').value,
      amount: amountFloat,
      date: $('transferDate').value,
      dueDate: $('dueDate').value || null,
      note: $('note').value.trim(),
      status: prior?.status || 'open',
      payments: prior?.payments || [],
      createdAt: prior?.createdAt || new Date().toISOString()
    };

    if (prior) {
      const priorClone = JSON.parse(JSON.stringify(prior));
      entries = entries.map(x => x.id === id ? item : x);
      pushUndo({ type: 'replaceEntry', entry: priorClone });
    } else {
      entries.push(item);
      pushUndo({ type: 'deleteEntry', id: item.id });
    }

    await save();
    $('entryDialog').close();
    render();
    toast(prior ? 'Transfer updated' : 'Transfer saved', true);
    if (selectedPersonId) openPerson(selectedPersonId);
  });

  $('deleteEntry').addEventListener('click', async () => {
    const id = $('entryId').value;
    if (!id) return;
    const item = entries.find(e => e.id === id);
    if (!item) return;

    const confirmed = await showConfirmModal('Delete transfer?', 'This entry will be permanently removed from your ledger.');
    if (!confirmed) return;

    entries = entries.filter(e => e.id !== id);
    pushUndo({ type: 'restoreEntry', entry: item });
    await save();
    $('entryDialog').close();
    render();
    toast('Transfer deleted', true);
    if (selectedPersonId) openPerson(selectedPersonId);
  });

  // Name Matching Helpers
  function normalize(s) {
    return s.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]/g, '');
  }

  $('personName').addEventListener('input', (e) => {
    chosenPerson = null;
    const val = e.target.value.trim();
    const hint = $('matchHint');
    if (!val) {
      hint.hidden = true;
      return;
    }
    const ps = people();
    const match = ps.find(p => [p.name, ...p.aliases].some(n => normalize(n) === normalize(val)));
    if (match) {
      hint.hidden = false;
      chosenPerson = match;
      hint.innerHTML = `Grouping under <b>${esc(match.name)}</b>`;
    } else {
      hint.hidden = true;
    }
  });

  // ==========================================
  // Repayments
  // ==========================================
  function openRepayment(entryId) {
    const e = entries.find(x => x.id === entryId);
    if (!e) return;
    $('personDialog').close();
    $('repaymentEntryId').value = e.id;
    $('repayContext').textContent = `${e.name} · ${money(remainingMinor(e))} remaining`;
    $('repaymentAmount').value = '';
    $('repaymentDate').value = today();
    $('repaymentNote').value = '';
    $('repaymentDialog').showModal();
  }

  $('repaymentForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const item = entries.find(x => x.id === $('repaymentEntryId').value);
    if (!item) return;

    const amountFloat = Number($('repaymentAmount').value);
    const amountMinor = parseToMinorUnits(amountFloat);
    const remMinor = remainingMinor(item);

    if (amountMinor <= 0 || amountMinor > remMinor) {
      toast('Enter an amount up to the remaining balance');
      return;
    }

    item.payments = item.payments || [];
    const payment = {
      id: crypto.randomUUID(),
      amount: amountFloat,
      date: $('repaymentDate').value,
      note: $('repaymentNote').value.trim()
    };
    item.payments.push(payment);
    if (remainingMinor(item) === 0) item.status = 'paid';

    pushUndo({ type: 'removePayment', entryId: item.id, paymentId: payment.id });
    await save();
    $('repaymentDialog').close();
    render();
    openPerson(item.personId);
    toast('Repayment recorded', true);
  });

  // ==========================================
  // Undo Engine
  // ==========================================
  function pushUndo(action) {
    undoStack.push(action);
    if (undoStack.length > 20) undoStack.shift();
  }

  async function performUndo() {
    if (!undoStack.length) {
      toast('Nothing to undo');
      return;
    }
    const action = undoStack.pop();
    switch (action.type) {
      case 'settleAll':
        for (const snap of action.entries) {
          const item = entries.find(x => x.id === snap.id);
          if (item) item.status = snap.status;
        }
        break;
      case 'toggleStatus': {
        const item = entries.find(x => x.id === action.id);
        if (item) item.status = action.prevStatus;
        break;
      }
      case 'restoreEntry':
        entries.push(action.entry);
        break;
      case 'deleteEntry':
        entries = entries.filter(x => x.id !== action.id);
        break;
      case 'replaceEntry':
        entries = entries.map(x => x.id === action.entry.id ? action.entry : x);
        break;
      case 'removePayment': {
        const item = entries.find(x => x.id === action.entryId);
        if (item) {
          item.payments = (item.payments || []).filter(p => p.id !== action.paymentId);
          item.status = 'open';
        }
        break;
      }
      case 'addPayment': {
        const item = entries.find(x => x.id === action.entryId);
        if (item) item.payments.push(action.payment);
        break;
      }
    }
    await save();
    render();
    if (selectedPersonId) openPerson(selectedPersonId);
    toast('Action undone');
  }

  // ==========================================
  // Aliases & Merge
  // ==========================================
  function openAliases(p) {
    $('aliasTitle').textContent = `Aliases for ${p.name}`;
    renderAliases(p);
    $('aliasDialog').showModal();
  }

  function renderAliases(p) {
    const list = aliases[p.id] || [];
    $('aliasList').innerHTML = list.length
      ? list.map((a, i) => `
        <div class="alias-item">
          <span>${esc(a)}</span>
          <button type="button" class="undo-payment" data-index="${i}">×</button>
        </div>
      `).join('')
      : '<p class="settings-copy tiny">No alternate names recorded.</p>';

    $('aliasList').querySelectorAll('button').forEach(btn => {
      btn.onclick = async () => {
        aliases[p.id].splice(+btn.dataset.index, 1);
        if (!aliases[p.id].length) delete aliases[p.id];
        await save();
        renderAliases(p);
      };
    });
  }

  $('addAliasButton').onclick = async () => {
    const p = people().find(x => x.id === selectedPersonId);
    const val = $('aliasInput').value.trim();
    if (!p || !val) return;
    aliases[p.id] = aliases[p.id] || [];
    aliases[p.id].push(val);
    $('aliasInput').value = '';
    await save();
    renderAliases(p);
  };

  function openMerge(p) {
    const others = people().filter(x => x.id !== p.id);
    if (!others.length) {
      toast('No other people to merge with');
      return;
    }
    $('mergeCopy').textContent = `Move all records of ${p.name} into another person.`;
    $('mergeSelect').innerHTML = others.map(x => `<option value="${esc(x.id)}">${esc(x.name)}</option>`).join('');
    $('mergeDialog').dataset.source = p.id;
    $('mergeDialog').showModal();
  }

  $('mergeForm').onsubmit = async (e) => {
    e.preventDefault();
    const fromId = $('mergeDialog').dataset.source;
    const toId = $('mergeSelect').value;
    const target = people().find(x => x.id === toId);
    const source = people().find(x => x.id === fromId);
    if (!target || !source) return;

    for (const item of entries) {
      if (item.personId === fromId) {
        item.personId = toId;
        item.name = target.name;
      }
    }
    aliases[toId] = [...new Set([...(aliases[toId] || []), source.name, ...(aliases[fromId] || [])])];
    delete aliases[fromId];

    await save();
    $('mergeDialog').close();
    $('personDialog').close();
    render();
    toast('People merged');
  };

  // ==========================================
  // Statements & Sharing
  // ==========================================
  function generatePersonStatement(p) {
    const lines = [
      `Statement with ${p.name}`,
      `Date: ${dateText(today())}`,
      `You owe me: ${money(p.toYouMinor)}`,
      `I owe you: ${money(p.youOweMinor)}`,
      `Net balance: ${p.netMinor > 0 ? `You owe me ${money(p.netMinor)}` : p.netMinor < 0 ? `I owe you ${money(Math.abs(p.netMinor))}` : 'Settled'}`,
      '',
      'Transfers:'
    ];

    for (const e of p.entries) {
      const rem = remainingMinor(e);
      lines.push(`• ${dateText(e.date)}: ${e.direction === 'toYou' ? 'Lent' : 'Borrowed'} ${money(parseToMinorUnits(e.amount))}${e.note ? ` (${e.note})` : ''} — Remaining: ${money(rem)}`);
    }

    return lines.join('\n');
  }

  async function shareContent(text, title) {
    if (navigator.share) {
      try {
        await navigator.share({ title, text });
      } catch (err) {
        if (err.name !== 'AbortError') copyToClipboard(text);
      }
    } else {
      copyToClipboard(text);
    }
  }

  function copyToClipboard(str) {
    navigator.clipboard?.writeText(str).then(() => toast('Statement copied to clipboard'));
  }

  // ==========================================
  // Modal Confirm & PIN Helpers
  // ==========================================
  function showConfirmModal(title, text) {
    return new Promise((resolve) => {
      $('confirmTitle').textContent = title;
      $('confirmCopy').textContent = text;
      pendingConfirmResolve = resolve;
      $('confirmDialog').showModal();
    });
  }

  $('confirmYes').onclick = () => {
    $('confirmDialog').close();
    if (pendingConfirmResolve) pendingConfirmResolve(true);
  };
  $('confirmNo').onclick = () => {
    $('confirmDialog').close();
    if (pendingConfirmResolve) pendingConfirmResolve(false);
  };

  function requestBackupPin(title, copy) {
    return new Promise((resolve) => {
      $('backupPinTitle').textContent = title;
      $('backupPinCopy').textContent = copy;
      $('backupPinInput').value = '';
      $('backupPinError').textContent = '';
      pendingBackupPinResolve = resolve;
      $('backupPinDialog').showModal();
      setTimeout(() => $('backupPinInput').focus(), 100);
    });
  }

  $('backupPinForm').onsubmit = (e) => {
    e.preventDefault();
    const pin = $('backupPinInput').value;
    if (!/^\d{4,6}$/.test(pin)) {
      $('backupPinError').textContent = 'Enter a 4 to 6 digit PIN.';
      return;
    }
    $('backupPinDialog').close();
    if (pendingBackupPinResolve) pendingBackupPinResolve(pin);
  };

  // ==========================================
  // Backup & CSV Export / Import
  // ==========================================
  $('exportButton').onclick = async () => {
    const pin = await requestBackupPin('Set Backup PIN', 'Enter a 4 to 6 digit PIN to encrypt this backup.');
    if (!pin) return;
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKeyFromPin(pin, salt);
    const box = await encryptPayload({ entries, aliases, settings }, key, salt);
    downloadFile(JSON.stringify(box, null, 2), `ledger-backup-${today()}.json`, 'application/json');
    toast('Encrypted backup downloaded');
  };

  $('csvButton').onclick = () => {
    const rows = [['Person', 'Direction', 'Transfer Date', 'Amount', 'Remaining', 'Status', 'Note', 'Repayments']];
    for (const e of entries) {
      const repays = (e.payments || []).map(p => `${p.date}: ${p.amount}${p.note ? ` (${p.note})` : ''}`).join('; ');
      rows.push([
        e.name,
        e.direction === 'toYou' ? 'They owe you' : 'You owe them',
        e.date,
        e.amount,
        remainingMinor(e) / 100,
        e.status,
        e.note || '',
        repays
      ]);
    }
    const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\r\n');
    downloadFile('\ufeff' + csv, `ledger-${today()}.csv`, 'text/csv');
    toast('CSV downloaded');
  };

  function downloadFile(content, name, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  $('importFile').onchange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    try {
      const text = await file.text();
      const raw = JSON.parse(text);
      let payloadData;
      if (raw.format === 'ledger-encrypted-v2') {
        const pin = await requestBackupPin('Enter Backup PIN', 'Enter the PIN used to encrypt this file.');
        if (!pin) return;
        const salt = from64(raw.salt);
        const key = await deriveKeyFromPin(pin, salt);
        payloadData = await decryptPayload(raw, key);
      } else {
        payloadData = raw;
      }

      if (!Array.isArray(payloadData.entries)) throw new Error('Invalid vault structure');
      const confirmed = await showConfirmModal('Restore backup?', `This will replace your current ${entries.length} transfer(s) with ${payloadData.entries.length} transfer(s) from the backup.`);
      if (!confirmed) return;

      entries = payloadData.entries;
      aliases = payloadData.aliases || {};
      settings = { ...settings, ...(payloadData.settings || {}) };
      await save();
      render();
      toast('Backup restored');
      $('backupDialog').close();
    } catch {
      toast('Could not decrypt or read backup file');
    }
    e.target.value = '';
  };

  // ==========================================
  // Lock Form Submissions
  // ==========================================
  $('lockForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const pin = $('pinInput').value;
    if (!/^\d{4,6}$/.test(pin)) {
      $('pinError').textContent = 'Enter a 4 to 6 digit PIN.';
      return;
    }
    if (lockMode !== 'unlock' && pin !== $('pinConfirm').value) {
      $('pinError').textContent = 'PINs do not match.';
      return;
    }

    try {
      if (lockMode === 'change') {
        vaultSalt = crypto.getRandomValues(new Uint8Array(16));
        cryptoKey = await deriveKeyFromPin(pin, vaultSalt);
        await save();
        $('lockDialog').close();
        toast('PIN updated');
      } else {
        await loadVault(pin);
      }
    } catch {
      $('pinError').textContent = lockMode === 'unlock' ? 'Incorrect PIN.' : 'Error securing vault.';
      $('pinInput').value = '';
      $('pinInput').focus();
    }
  });

  // ==========================================
  // Mobile Background Auto-Lock Watcher
  // ==========================================
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') {
      backgroundTimestamp = Date.now();
    } else if (document.visibilityState === 'visible' && backgroundTimestamp) {
      const elapsed = Date.now() - backgroundTimestamp;
      if (elapsed >= AUTO_LOCK_MS && cryptoKey) {
        lockLedger();
      }
      backgroundTimestamp = null;
    }
  });

  // ==========================================
  // Backdrop Dismissal for All Native Dialogs
  // ==========================================
  document.querySelectorAll('dialog').forEach(dialog => {
    dialog.addEventListener('click', (e) => {
      // Do not dismiss non-cancelable unlock dialog on outside tap
      if (dialog.id === 'lockDialog' && !cryptoKey) return;
      const rect = dialog.getBoundingClientRect();
      const clickedInside = (
        rect.top <= e.clientY && e.clientY <= rect.top + rect.height &&
        rect.left <= e.clientX && e.clientX <= rect.left + rect.width
      );
      if (!clickedInside) dialog.close();
    });
  });

  // ==========================================
  // Event Bindings & Init
  // ==========================================
  $('biometricButton').onclick = () => unlockWithBiometric();
  $('enableBiometric').onclick = async () => {
    if (!cryptoKey) {
      toast('Unlock vault first to configure biometrics');
      return;
    }
    const ok = await registerBiometricKey(cryptoKey);
    if (ok) {
      toast('Hardware biometrics enabled');
      $('biometricRow').style.display = 'none';
    }
  };

  $('currencySelect').value = settings.currency || 'INR';
  $('currencySelect').onchange = (e) => {
    settings.currency = e.target.value;
    persistSettings();
    applyTheme();
    render();
  };

  document.querySelectorAll('.theme-chip').forEach(chip => {
    chip.onclick = () => {
      settings.theme = chip.dataset.theme;
      persistSettings();
      applyTheme();
      document.querySelectorAll('.theme-chip').forEach(c => c.classList.toggle('active', c.dataset.theme === settings.theme));
    };
  });

  $('settingsButton').onclick = () => {
    document.querySelectorAll('.theme-chip').forEach(c => c.classList.toggle('active', c.dataset.theme === (settings.theme || 'system')));
    if (isPrfSupported() && !localStorage.getItem(BIO_META_KEY)) {
      $('biometricRow').style.display = 'flex';
    }
    $('settingsDialog').showModal();
  };

  $('saveSettings').onclick = () => $('settingsDialog').close();
  $('lockNowButton').onclick = () => lockLedger();
  $('changePinButton').onclick = () => {
    $('settingsDialog').close();
    showPinDialog('change');
  };
  $('undoButton').onclick = () => {
    performUndo();
    $('settingsDialog').close();
  };

  $('toastUndo').onclick = () => performUndo();

  function toast(msg, showUndo = false) {
    $('toastText').textContent = msg;
    $('toastUndo').hidden = !showUndo;
    const t = $('toast');
    t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), showUndo ? 3500 : 2500);
  }

  $('searchInput').oninput = (e) => {
    query = e.target.value.toLowerCase().trim();
    render();
  };

  $('sortSelect').onchange = (e) => {
    sort = e.target.value;
    render();
  };

  document.querySelectorAll('.filter').forEach(btn => {
    btn.onclick = () => {
      document.querySelectorAll('.filter').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      filter = btn.dataset.filter;
      render();
    };
  });

  ['addButton', 'fabButton'].forEach(id => $(id)?.addEventListener('click', openAdd));
  document.querySelectorAll('[data-close]').forEach(b => b.addEventListener('click', () => $(b.dataset.close).close()));
  $('clearDueDate').onclick = () => $('dueDate').value = '';
  $('backupButton').onclick = () => $('backupDialog').showModal();
  $('shareAllButton').onclick = () => {
    const ps = people();
    const text = ps.map(p => `${p.name}: ${p.netMinor > 0 ? `Owes ${money(p.netMinor)}` : p.netMinor < 0 ? `You owe ${money(Math.abs(p.netMinor))}` : 'Settled'}`).join('\n');
    shareContent(`Ledger Overview (${dateText(today())})\n\n${text}`, 'Ledger Overview');
  };

  // Init
  $('todayLabel').textContent = new Intl.DateTimeFormat(undefined, { weekday: 'long', month: 'short', day: 'numeric' }).format(new Date()).toUpperCase();
  applyTheme();

  // Determine setup vs unlock
  (async () => {
    const rawBox = await idbGet(VAULT_RECORD_KEY);
    showPinDialog(rawBox ? 'unlock' : 'setup');
  })();

  if ('serviceWorker' in navigator && location.protocol.startsWith('http')) {
    navigator.serviceWorker.register('sw.js').catch(() => {});
  }
})();