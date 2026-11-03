(() => {
  const KEY = 'ledger.entries.v1', SETTINGS_KEY = 'ledger.settings.v1', VAULT_KEY = 'ledger.vault.v2';
  const $ = (id) => document.getElementById(id);
  const today = () => { const d=new Date(); return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`; };
  let entries = [], aliases = {}, settings = loadSettings(), filter = 'all', query = '', sort = 'recent', selectedPersonId = null, toastTimer, cryptoKey = null, vaultSalt = null, lockMode = 'unlock', saveQueue = Promise.resolve(), lockTimer, undoStack = [], lastBackupPrompt = 0;

  function loadLegacy() { try { const v = JSON.parse(localStorage.getItem(KEY) || '[]'); return Array.isArray(v) ? v : []; } catch { return []; } }
  function loadSettings() { try { return { ...JSON.parse(localStorage.getItem(SETTINGS_KEY) || '{}') }; } catch { return {}; } }
  function applyTheme() {
    const t = settings.theme || 'system';
    if (t === 'system') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', t);
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) {
      const dark = t === 'dark' || (t === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
      meta.setAttribute('content', dark ? '#0d1520' : '#f7f8f9');
    }
  }
  applyTheme();
  function bytes64(bytes) { let binary='';for(const b of new Uint8Array(bytes))binary+=String.fromCharCode(b);return btoa(binary); }
  function from64(value) { return Uint8Array.from(atob(value), c => c.charCodeAt(0)); }
  async function deriveKey(pin, salt) { const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(pin), 'PBKDF2', false, ['deriveKey']); return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:250000,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']); }
  function payload() { return { entries, aliases, settings }; }
  async function encryptPayload(data, key, salt) { const iv=crypto.getRandomValues(new Uint8Array(12));const encrypted=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,new TextEncoder().encode(JSON.stringify(data)));return {format:'ledger-encrypted-v2',salt:bytes64(salt),iv:bytes64(iv),data:bytes64(encrypted)}; }
  async function decryptPayload(box, pin) { const salt=from64(box.salt),key=await deriveKey(pin,salt);const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:from64(box.iv)},key,from64(box.data));return {data:JSON.parse(new TextDecoder().decode(plain)),key,salt}; }
  function save() { if (!cryptoKey || !vaultSalt) return Promise.resolve(); const snapshot=payload(),key=cryptoKey,salt=vaultSalt; saveQueue=saveQueue.then(async()=>{const box=await encryptPayload(snapshot,key,salt);localStorage.setItem(VAULT_KEY,JSON.stringify(box));localStorage.removeItem(KEY);localStorage.removeItem(SETTINGS_KEY);}).catch(()=>toast('Could not save the encrypted ledger'));return saveQueue; }
  function remaining(e) { if(e.status==='paid')return 0;return Math.max(0,Math.round((+e.amount-(e.payments||[]).reduce((n,p)=>n+(+p.amount||0),0))*100)/100); }
  function legacySettings(){try{return JSON.parse(localStorage.getItem(SETTINGS_KEY)||'{}')}catch{return{}}}
  async function loadVault(pin){const box=JSON.parse(localStorage.getItem(VAULT_KEY)||'null');if(box){const result=await decryptPayload(box,pin);cryptoKey=result.key;vaultSalt=result.salt;entries=result.data.entries||[];aliases=result.data.aliases||{};settings=result.data.settings||{};}else{vaultSalt=crypto.getRandomValues(new Uint8Array(16));cryptoKey=await deriveKey(pin,vaultSalt);entries=loadLegacy();aliases={};settings=legacySettings();entries=entries.map(e=>({...e,payments:e.payments||[]}));await save();}render();$('lockDialog').close();$('pinInput').value='';$('pinConfirm').value='';toast('Ledger unlocked');}
  function showPin(mode){lockMode=mode;$('pinError').textContent='';$('pinInput').value='';$('pinConfirm').value='';$('pinConfirmWrap').hidden=mode==='unlock';$('pinInput').minLength=mode==='unlock'?4:4;$('pinInput').maxLength=mode==='unlock'?12:4;if(mode==='unlock')$('pinInput').removeAttribute('pattern');else $('pinInput').pattern='[0-9]{4}';$('lockTitle').textContent=mode==='setup'?'Protect your ledger':mode==='change'?'Change your PIN':'Unlock your ledger';$('lockCopy').textContent=mode==='setup'?'Choose a 4 digit PIN. It encrypts your ledger on this device. Keep it safe: a forgotten PIN cannot be recovered.':mode==='change'?'Choose a new 4 digit PIN. Your encrypted ledger will be re-encrypted with it.':'Enter your PIN to decrypt and open your ledger on this device.';$('pinSubmit').textContent=mode==='setup'?'Create PIN':mode==='change'?'Update PIN':'Unlock';$('lockDialog').showModal();setTimeout(()=>$('pinInput').focus(),100);
    const bioBtn=$('biometricButton');
    if(bioBtn){
      const show = mode==='unlock' && settings.biometricEnabled;
      bioBtn.hidden = !show;
      if(show) biometricAvailable().then(ok => { bioBtn.hidden = !ok; });
    }
  }
  async function initializeVault(){if(!crypto?.subtle){$('lockCopy').textContent='This app needs a secure HTTPS connection to protect your ledger.';return;}showPin(localStorage.getItem(VAULT_KEY)?'unlock':'setup');}
  function money(n) { return new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR', maximumFractionDigits: 2 }).format(Math.abs(n)); }
  function dateText(d) { if (!d) return ''; return new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short', year: 'numeric' }).format(new Date(`${d}T12:00:00`)); }
  function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  function toast(message) { const t = $('toast'); t.textContent = message; t.classList.add('show'); clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('show'), 2300); }
  function people() {
    const map = new Map();
    entries.forEach(e => { const id = e.personId || `legacy-${e.name.toLowerCase()}`; if (!map.has(id)) map.set(id, { id, name: e.name, aliases: aliases[id]||[], entries: [], net: 0, toYou: 0, youOwe: 0, latest: '' }); const p = map.get(id); p.entries.push(e); const due=remaining(e); if (e.direction === 'toYou') { p.net += due; p.toYou += due; } else { p.net -= due; p.youOwe += due; } if (e.date > p.latest) p.latest = e.date; });
    return [...map.values()];
  }
  function render() {
    const ps = people(); let toYou=0, youOwe=0, toCount=0, oweCount=0;
    ps.forEach(p => { toYou += p.toYou; youOwe += p.youOwe; if (p.toYou > 0) toCount++; if (p.youOwe > 0) oweCount++; });
    $('owedToYou').textContent=money(toYou); $('youOwe').textContent=money(youOwe); $('netBalance').textContent=(toYou-youOwe < 0 ? '−' : '')+money(toYou-youOwe); $('netCaption').textContent=toYou===youOwe?'All settled up':toYou>youOwe?'You’re owed more overall':'You owe more overall'; $('toYouCount').textContent=toCount; $('oweCount').textContent=oweCount; $('allCount').textContent=ps.length; renderAnalytics(); checkBackupReminder();
    let visible=ps.filter(p => (!query || (p.name+' '+p.entries.map(e=>e.note||'').join(' ')).toLowerCase().includes(query)) && (filter==='all'||(filter==='owed'&&p.toYou>0)||(filter==='owe'&&p.youOwe>0)));
    visible.sort((a,b)=>sort==='name'?a.name.localeCompare(b.name):sort==='amount'?Math.abs(b.net)-Math.abs(a.net):b.latest.localeCompare(a.latest));
    const list=$('peopleList');
    if(!visible.length){list.innerHTML=`<div class="empty-state"><div class="empty-icon">◈</div><h3>${ps.length?'No matches found':'Start with a transfer'}</h3><p>${ps.length?'Try another name or change the filter.':'Add money you lent or borrowed to see everyone’s balance in one place.'}</p>${ps.length?'':'<button class="primary-button" id="emptyAdd">＋ Add your first transfer</button>'}</div>`; $('emptyAdd')?.addEventListener('click',openAdd); return;}
    list.innerHTML=visible.map((p,i)=>{const avatar=(p.name.trim().split(/\s+/).map(x=>x[0]).slice(0,2).join('')||'?').toUpperCase();const settled=p.toYou===0&&p.youOwe===0;const cls=p.net>0?'positive':p.net<0?'negative':'';const label=settled?'Settled':p.net>0?'Owes you':p.net<0?'You owe':'Even';return `<article class="person-row" data-person="${esc(p.id)}"><div class="person-ident"><div class="person-avatar c${i%4+1}">${esc(avatar)}</div><div style="min-width:0"><div class="person-name">${esc(p.name)}</div><div class="person-meta">${p.entries.length} transfer${p.entries.length===1?'':'s'} · ${dateText(p.latest)}</div></div></div><div class="amount-block"><div class="money ${cls}">${settled?money(0):money(p.net)}</div><small>${label}</small></div><div class="amount-block"><div class="money">${p.entries.filter(e=>remaining(e)>0).length} <span style="font:10px 'DM Sans';color:#9aa4af">open</span></div><small>of ${p.entries.length} total</small></div><span class="row-arrow">›</span></article>`}).join('');
    list.querySelectorAll('[data-person]').forEach(row=>row.addEventListener('click',()=>openPerson(row.dataset.person)));
  }
  function openAdd() { chosenPerson=null;$('entryForm').reset(); $('entryId').value=''; $('personName').value=''; $('amount').value=''; $('transferDate').value=today(); $('dueDate').value=''; $('note').value=''; document.querySelector('input[name="direction"][value="toYou"]').checked=true; $('formEyebrow').textContent='NEW TRANSFER'; $('formTitle').textContent='Add a transfer'; $('deleteEntry').hidden=true; $('matchHint').hidden=true; $('matchHint').innerHTML=''; $('entryDialog').showModal(); setTimeout(()=>$('personName').focus(),100); }
  function editEntry(id) { const e=entries.find(x=>x.id===id); if(!e)return;chosenPerson=null;$('entryId').value=e.id; $('personName').value=e.name; $('amount').value=e.amount; $('transferDate').value=e.date; $('dueDate').value=e.dueDate||''; $('note').value=e.note||''; document.querySelector(`input[name="direction"][value="${e.direction}"]`).checked=true; $('formEyebrow').textContent='EDIT TRANSFER'; $('formTitle').textContent='Edit transfer'; $('deleteEntry').hidden=false; $('matchHint').hidden=true; $('entryDialog').showModal(); }
  function normalize(s) { return s.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,'').replace(/[^a-z0-9]/g,''); }
  function similarity(a,b) { a=normalize(a);b=normalize(b);if(!a||!b)return 0;const d=Array.from({length:a.length+1},(_,i)=>[i]);for(let j=1;j<=b.length;j++)d[0][j]=j;for(let i=1;i<=a.length;i++)for(let j=1;j<=b.length;j++)d[i][j]=Math.min(d[i-1][j]+1,d[i][j-1]+1,d[i-1][j-1]+(a[i-1]===b[j-1]?0:1));return 1-d[a.length][b.length]/Math.max(a.length,b.length); }
  function findMatch(name) { const peopleList=people(); const exact=peopleList.find(p=>[p.name,...p.aliases].some(n=>normalize(n)===normalize(name))); if(exact)return {p:exact,score:1,exact:true};return peopleList.map(p=>({p,score:Math.max(...[p.name,...p.aliases].map(n=>similarity(name,n)))})).filter(x=>x.score>=.70).sort((a,b)=>b.score-a.score)[0]||null; }
  let chosenPerson=null;
  $('personName').addEventListener('input', e=>{chosenPerson=null;const hint=$('matchHint'),name=e.target.value.trim(); if(!name){hint.hidden=true;return;}const match=findMatch(name);if(!match){hint.hidden=true;return;}hint.hidden=false;hint.innerHTML=match.exact?`This matches <b>${esc(match.p.name)}</b>. New transfers will be grouped with them.`:`Did you mean <b>${esc(match.p.name)}</b>? <button type="button" id="chooseMatch">Use this person</button><button type="button" class="dismiss-match" id="dismissMatch">Keep as new</button>`; if(match.exact) chosenPerson=match.p; else { $('chooseMatch').onclick=()=>{chosenPerson=match.p;$('personName').value=match.p.name;hint.innerHTML=`Using existing person <b>${esc(match.p.name)}</b>. <button type="button" class="dismiss-match" id="undoMatch">Undo</button>`;$('undoMatch').onclick=()=>{chosenPerson=null;hint.hidden=true;};}; $('dismissMatch').onclick=()=>hint.hidden=true; }});
  $('entryForm').addEventListener('submit',e=>{e.preventDefault();const id=$('entryId').value;const prior=id?entries.find(x=>x.id===id):null;const name=$('personName').value.trim();if(!name)return;const amount=Math.round(Number($('amount').value)*100)/100;if(prior&&amount+0.001<(prior.payments||[]).reduce((n,p)=>n+(+p.amount||0),0)){toast('Amount cannot be less than repayments already recorded');return;}const nameChanged=prior&&normalize(name)!==normalize(prior.name);const item={id:id||crypto.randomUUID(),personId:chosenPerson?.id||(nameChanged?crypto.randomUUID():(prior?.personId||crypto.randomUUID())),name:chosenPerson?.name||name,direction:document.querySelector('input[name="direction"]:checked').value,amount,date:$('transferDate').value,dueDate:$('dueDate').value||null,note:$('note').value.trim(),status:prior?.status||'open',payments:prior?.payments||[],createdAt:prior?.createdAt||new Date().toISOString()};if(prior)entries=entries.map(x=>x.id===id?item:x);else entries.push(item);void save();$('entryDialog').close();render();toast(prior?'Transfer updated':'Transfer saved');if(selectedPersonId)openPerson(selectedPersonId);});
  $('deleteEntry').addEventListener('click',()=>{const id=$('entryId').value;if(!id)return;if(confirm('Delete this transfer? This cannot be undone.')){entries=entries.filter(e=>e.id!==id);save();$('entryDialog').close();render();toast('Transfer deleted');if(selectedPersonId)openPerson(selectedPersonId);}});
  function openPerson(id) { const p=people().find(x=>x.id===id);if(!p)return;selectedPersonId=id;const direction=p.net>0?'owes you':p.net<0?'you owe':'settled';const activity=[...p.entries].sort((a,b)=>b.date.localeCompare(a.date));$('personDetail').innerHTML=`<div class="person-detail-head"><div class="dialog-head"><div><p class="eyebrow">PERSON BALANCE</p><h2>${esc(p.name)}</h2></div><button type="button" class="close-button" data-close="personDialog" aria-label="Close">×</button></div><div class="detail-total" style="color:${p.net>0?'#64cba3':p.net<0?'#ee9289':'white'}">${p.net<0?'−':''}${money(p.net)}</div><div class="detail-label">${direction} · ${money(Math.abs(p.net))} net balance</div><div class="detail-summary"><span>OWED TO YOU<b>${money(p.toYou)}</b></span><span>YOU OWE<b>${money(p.youOwe)}</b></span></div></div><div class="person-detail-body"><div class="detail-actions"><button class="secondary-button" id="sharePerson">Share statement</button><button class="primary-button" id="addForPerson">＋ Add transfer</button></div><div class="detail-actions secondary-actions"><button class="secondary-button" id="settleAllBtn" style="border-color:var(--green);color:var(--green)">Settle all with this person</button></div><div class="detail-actions secondary-actions"><button class="secondary-button" id="manageAliases">Manage aliases</button><button class="secondary-button" id="mergePerson">Merge duplicate</button></div><div class="share-options"><label><input type="checkbox" id="shareSettled" checked /> Include settled</label><label>From <input type="date" id="shareFrom" /></label><label>To <input type="date" id="shareTo" /></label></div><div class="activity-label">TRANSFER HISTORY · ${p.entries.length}</div>${activity.map(e=>{const rem=remaining(e);return `<div class="activity-item" data-entry="${esc(e.id)}"><div><b>${e.direction==='toYou'?'They owe you':'You owe them'} · ${money(e.amount)}</b><small>${rem>0?`${money(rem)} remaining · `:e.status==='paid'?'Settled · ':''}${dateText(e.date)}${e.dueDate?` · Due ${dateText(e.dueDate)}${e.dueDate<today()&&rem>0?' ⚠':''}`:''}${e.note?' · '+esc(e.note):''}</small><div class="payment-history">${(e.payments||[]).map((x,j)=>`<div>Repayment ${money(x.amount)} · ${dateText(x.date)}${x.note?' · '+esc(x.note):''}<button type="button" class="undo-payment" data-entry="${esc(e.id)}" data-index="${j}">Undo</button></div>`).join('')}</div></div><div class="activity-tools">${rem>0?`<button class="status-chip record-repay" data-id="${esc(e.id)}">Record repayment</button><button class="status-chip toggle-paid" data-id="${esc(e.id)}">Settle remainder</button>`:e.status==='paid'?`<button class="status-chip toggle-paid" data-id="${esc(e.id)}">Reopen</button>`:`<span class="status-chip static-chip">Repaid</span>`}<span class="status">Tap transfer to edit</span></div></div>`}).join('')}</div>`;$('personDialog').showModal();$('personDetail').querySelector('[data-close]').onclick=()=>$('personDialog').close();const opts=()=>({includeSettled:$('shareSettled').checked,from:$('shareFrom').value,to:$('shareTo').value});$('sharePerson').onclick=()=>shareSummary(personSummary(p,opts()),p.name);
$('settleAllBtn')&&($('settleAllBtn').onclick=()=>{
  const openOnes = p.entries.filter(e => remaining(e) > 0);
  if (!openOnes.length) { toast('Nothing open to settle'); return; }
  if (!confirm(`Mark all ${openOnes.length} open transfer(s) with ${p.name} as settled?`)) return;
  const snapshot = openOnes.map(e => ({id:e.id, status:e.status, payments: JSON.parse(JSON.stringify(e.payments||[]))}));
  openOnes.forEach(e => { e.status = 'paid'; });
  pushUndo({type:'settleAll', entries: snapshot});
  void save(); render(); openPerson(id); toast('All settled with ' + p.name);
});$('addForPerson').onclick=()=>{const person=p;$('personDialog').close();openAdd();$('personName').value=person.name;chosenPerson=person;$('matchHint').hidden=false;$('matchHint').innerHTML=`Using existing person <b>${esc(person.name)}</b>.`;};$('manageAliases').onclick=()=>openAliases(p);$('mergePerson').onclick=()=>openMerge(p);$('personDetail').querySelectorAll('.activity-item').forEach(el=>el.addEventListener('click',ev=>{if(ev.target.closest('button'))return;$('personDialog').close();editEntry(el.dataset.entry);}));$('personDetail').querySelectorAll('.record-repay').forEach(btn=>btn.addEventListener('click',ev=>{ev.stopPropagation();openRepayment(btn.dataset.id);}));$('personDetail').querySelectorAll('.toggle-paid').forEach(btn=>btn.addEventListener('click',ev=>{ev.stopPropagation();const item=entries.find(x=>x.id===btn.dataset.id);if(item){item.status=item.status==='paid'?'open':'paid';void save();render();openPerson(id);toast(item.status==='paid'?'Marked as settled':'Reopened transfer');}}));$('personDetail').querySelectorAll('.undo-payment').forEach(btn=>btn.addEventListener('click',ev=>{ev.stopPropagation();const item=entries.find(x=>x.id===btn.dataset.entry);if(item){item.payments.splice(+btn.dataset.index,1);item.status='open';void save();render();openPerson(id);toast('Repayment removed');}})); }
  function personSummary(p,options={includeSettled:true}){let transfers=p.entries.filter(e=>(!options.from||e.date>=options.from)&&(!options.to||e.date<=options.to)&&(options.includeSettled||remaining(e)>0));const toYou=transfers.filter(e=>e.direction==='toYou').reduce((n,e)=>n+remaining(e),0),youOwe=transfers.filter(e=>e.direction==='youOwe').reduce((n,e)=>n+remaining(e),0),net=toYou-youOwe;const lines=[`Balance with ${p.name}`,`As of ${dateText(today())}`,`You owe me: ${money(toYou)}`,`I owe you: ${money(youOwe)}`,`Net: ${net>0?`You owe me ${money(net)}`:net<0?`I owe you ${money(-net)}`:'settled'}`,options.from||options.to?`Period: ${options.from?dateText(options.from):'Any'} – ${options.to?dateText(options.to):'Today'}`:'',``,`Transfers:`];[...transfers].sort((a,b)=>a.date.localeCompare(b.date)).forEach(e=>{lines.push(`${dateText(e.date)} · ${e.direction==='toYou'?'You owe me':'I owe you'} ${money(e.amount)}${e.note?' · '+e.note:''}`);(e.payments||[]).forEach(x=>lines.push(`  Repayment ${dateText(x.date)} · ${money(x.amount)}${x.note?' · '+x.note:''}`));lines.push(`  Remaining: ${money(remaining(e))}${e.status==='paid'?' · settled':''}`);});return lines.filter(Boolean).join('\n');}
async function shareSummary(text,name){if(navigator.share){try{await navigator.share({title:`Balance with ${name}`,text});}catch(e){if(e.name!=='AbortError')toast('Could not open the share menu');}}else toast('The share menu is available on Android.');}
  function openRepayment(id){const e=entries.find(x=>x.id===id);if(!e)return;$('personDialog').close();$('repaymentEntryId').value=e.id;$('repayContext').textContent=`${e.name} · ${money(remaining(e))} remaining`;$('repaymentAmount').value='';$('repaymentAmount').max=remaining(e);$('repaymentDate').value=today();$('repaymentNote').value='';$('repaymentDialog').showModal();}
  function openAliases(p){$('aliasTitle').textContent=`Names for ${p.name}`;renderAliases(p);$('aliasDialog').showModal();}
  function renderAliases(p){const vals=aliases[p.id]||[];$('aliasList').innerHTML=vals.length?vals.map((a,i)=>`<div class="alias-item"><span>${esc(a)}</span><button type="button" class="remove-alias" data-index="${i}" aria-label="Remove ${esc(a)}">×</button></div>`).join(''):'<p class="settings-copy tiny">No saved aliases yet.</p>'; $('aliasList').querySelectorAll('.remove-alias').forEach(b=>b.onclick=()=>{aliases[p.id].splice(+b.dataset.index,1);if(!aliases[p.id].length)delete aliases[p.id];void save();renderAliases(p);});}
  function openMerge(p){const options=people().filter(x=>x.id!==p.id);if(!options.length){toast('There is no other person to merge');return;}$('mergeCopy').textContent=`All transfers and aliases for ${p.name} will be moved into the selected person.`;$('mergeSelect').innerHTML=options.map(x=>`<option value="${esc(x.id)}">${esc(x.name)}</option>`).join('');$('mergeDialog').dataset.source=p.id;$('mergeDialog').showModal();}
  $('shareAllButton').addEventListener('click',()=>{const ps=people();if(!ps.length){toast('No transfers to share yet');return;}const net=ps.reduce((a,p)=>a+p.net,0);const text=[`Personal ledger overview · ${dateText(today())}`,`Owed to you: ${money(ps.reduce((a,p)=>a+p.toYou,0))}`,`You owe: ${money(ps.reduce((a,p)=>a+p.youOwe,0))}`,`Net: ${net>=0?money(net)+' owed to you':money(net)+' you owe'}`, '',...ps.map(p=>`${p.name}: ${p.net>0?money(p.net)+' owed to you':p.net<0?money(-p.net)+' you owe':'settled'}`)].join('\n');shareSummary(text,'Ledger overview');});
  document.querySelectorAll('.filter').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('.filter').forEach(x=>x.classList.remove('active'));b.classList.add('active');filter=b.dataset.filter;render();}));
  $('searchInput').addEventListener('input',e=>{query=e.target.value.toLowerCase().trim();render();});$('sortSelect').addEventListener('change',e=>{sort=e.target.value;render();});
  ['addButton','fabButton'].forEach(id=>$(id).addEventListener('click',openAdd));document.querySelectorAll('[data-close]').forEach(b=>b.addEventListener('click',()=>$(b.dataset.close).close()));
  $('settingsButton').addEventListener('click',()=>$('settingsDialog').showModal());$('saveSettings').addEventListener('click',e=>{e.preventDefault();$('settingsDialog').close();});
  $('lockNowButton').addEventListener('click',async()=>{await saveQueue;$('settingsDialog').close();for(const id of ['personDialog','entryDialog','backupDialog','repaymentDialog','aliasDialog','mergeDialog'])if($(id).open)$(id).close();$('personDetail').innerHTML='';entries=[];aliases={};cryptoKey=null;vaultSalt=null;render();showPin('unlock');});
  $('changePinButton').addEventListener('click',()=>{$('settingsDialog').close();showPin('change');});
  $('lockForm').addEventListener('submit',async e=>{e.preventDefault();const pin=$('pinInput').value;if(lockMode==='unlock'?!/^\d{4,12}$/.test(pin):!/^\d{4}$/.test(pin)){$('pinError').textContent=lockMode==='unlock'?'Enter your PIN.':'Enter a 4 digit PIN.';return;}if(lockMode!=='unlock'&&pin!==$('pinConfirm').value){$('pinError').textContent='The PINs do not match.';return;}try{if(lockMode==='change'){await saveQueue;vaultSalt=crypto.getRandomValues(new Uint8Array(16));cryptoKey=await deriveKey(pin,vaultSalt);await save();$('lockDialog').close();toast('PIN changed');}else{await loadVault(pin);if(pin.length!==4)showPin('change');
      else {
        $('lockDialog').close();
        // Offer biometric if available and not yet enabled
        if (!settings.biometricEnabled) {
          biometricAvailable().then(ok => {
            if (ok) {
              const row = $('biometricRow'); if (row) row.style.display = 'flex';
            }
          });
        }
      }}}catch{$('pinError').textContent=lockMode==='unlock'?'That PIN could not unlock this ledger. Try again.':'Could not protect the ledger. Please try again.';$('pinInput').value='';$('pinInput').focus();}});
  $('backupButton').addEventListener('click',()=>$('backupDialog').showModal());
  $('exportButton').addEventListener('click',async()=>{const a=window.prompt('Enter a 4 digit PIN to encrypt this backup. Use your ledger PIN if you want to restore it easily.');if(!a)return;const b=window.prompt('Enter the same PIN again.');if(a!==b){toast('The PINs did not match');return;}if(!/^\d{4}$/.test(a)){toast('Use a 4 digit PIN');return;}const salt=crypto.getRandomValues(new Uint8Array(16)),key=await deriveKey(a,salt),box=await encryptPayload(payload(),key,salt);download(JSON.stringify(box,null,2),`ledger-backup-${today()}.json`,'application/json');toast('Encrypted backup downloaded');});
  $('csvButton').addEventListener('click',()=>{const rows=[['Person','Direction','Transfer date','Amount INR','Repaid INR','Remaining INR','Status','Note','Repayment date','Repayment amount INR','Repayment note']];entries.forEach(e=>{const paid=(e.payments||[]).reduce((n,p)=>n+(+p.amount||0),0);if(!(e.payments||[]).length)rows.push([e.name,e.direction==='toYou'?'They owe you':'You owe them',e.date,e.amount,paid,remaining(e),remaining(e)===0?'Settled':'Open',e.note||'','','','']);else (e.payments||[]).forEach((p,i)=>rows.push([e.name,e.direction==='toYou'?'They owe you':'You owe them',e.date,i===0?e.amount:'',i===0?paid:'',i===0?remaining(e):'',i===0?(remaining(e)===0?'Settled':'Open'):'',i===0?(e.note||''):'',p.date,p.amount,p.note||'']));});const csv=rows.map(row=>row.map(v=>`"${String(v).replace(/"/g,'""')}"`).join(',')).join('\r\n');download('\ufeff'+csv,`ledger-${today()}.csv`,'text/csv');toast('CSV exported');});
  function download(content,name,type){const blob=new Blob([content],{type}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
  $('importFile').addEventListener('change',async e=>{const file=e.target.files[0];if(!file)return;try{let raw=JSON.parse(await file.text()),data;if(raw.format==='ledger-encrypted-v2'){const pin=window.prompt('Enter the PIN used to encrypt this backup.');if(!pin)throw Error('cancel');data=(await decryptPayload(raw,pin)).data;}else{data=raw;if(!Array.isArray(data.entries))throw Error('invalid');}if(!Array.isArray(data.entries)||!data.entries.every(x=>x.id&&x.name&&Number.isFinite(+x.amount)&&['toYou','youOwe'].includes(x.direction)))throw Error('invalid');if(confirm(`Restore ${data.entries.length} transfers? Your current ledger will be replaced.`)){entries=data.entries.map(x=>({...x,payments:x.payments||[]}));aliases=data.aliases||{};settings=data.settings||{};await save();render();toast('Backup restored');$('backupDialog').close();}}catch{toast('Backup could not be restored. Check the file and PIN.');}e.target.value='';});
  $('repaymentForm').addEventListener('submit',async e=>{e.preventDefault();const item=entries.find(x=>x.id===$('repaymentEntryId').value);if(!item)return;const amount=Math.round(Number($('repaymentAmount').value)*100)/100;if(amount<=0||amount>remaining(item)+.001){toast('Enter an amount up to the remaining balance');return;}item.payments=item.payments||[];item.payments.push({id:crypto.randomUUID(),amount,date:$('repaymentDate').value,note:$('repaymentNote').value.trim()});if(remaining(item)===0)item.status='paid';await save();$('repaymentDialog').close();render();openPerson(item.personId);toast('Repayment saved');});
  $('addAliasButton').addEventListener('click',()=>{const p=people().find(x=>x.id===selectedPersonId),value=$('aliasInput').value.trim();if(!p||!value)return;const existing=[p.name,...p.aliases].some(a=>normalize(a)===normalize(value));if(existing){toast('That name is already linked');return;}aliases[p.id]=aliases[p.id]||[];aliases[p.id].push(value);$('aliasInput').value='';void save();renderAliases(p);toast('Alias saved');});
  $('mergeForm').addEventListener('submit',e=>{e.preventDefault();const from=$('mergeDialog').dataset.source,toId=$('mergeSelect').value,to=people().find(x=>x.id===toId),source=people().find(x=>x.id===from);if(!to||!source)return;const movedNames=[source.name,...(aliases[from]||[])];entries.forEach(item=>{if(item.personId===from){item.personId=toId;item.name=to.name;}});aliases[toId]=[...new Set([...(aliases[toId]||[]),...movedNames].filter(n=>normalize(n)!==normalize(to.name)))];delete aliases[from];void save();$('mergeDialog').close();$('personDialog').close();render();toast('People merged');});
  function armAutoLock(){clearTimeout(lockTimer);lockTimer=setTimeout(()=>{if(document.visibilityState==='hidden'&&cryptoKey){void saveQueue.then(()=>{for(const id of ['personDialog','entryDialog','backupDialog','repaymentDialog','aliasDialog','mergeDialog'])if($(id).open)$(id).close();$('personDetail').innerHTML='';entries=[];aliases={};cryptoKey=null;vaultSalt=null;render();showPin('unlock');});}},120000);}document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='hidden')armAutoLock();else clearTimeout(lockTimer);});
  document.addEventListener('contextmenu',e=>{if(!e.target.closest('input,textarea,select'))e.preventDefault();});
  $('todayLabel').textContent=new Intl.DateTimeFormat(undefined,{weekday:'long',month:'long',day:'numeric'}).format(new Date()).toUpperCase();
  
  function pushUndo(action) {
    undoStack.push(action);
    if (undoStack.length > 15) undoStack.shift();
  }
  function performUndo() {
    if (!undoStack.length) { toast('Nothing to undo'); return; }
    const action = undoStack.pop();
    if (action.type === 'settleAll') {
      action.entries.forEach(e => {
        const item = entries.find(x => x.id === e.id);
        if (item) { item.status = e.status; item.payments = e.payments; }
      });
      void save(); render(); if (selectedPersonId) openPerson(selectedPersonId);
      toast('Undid settle all');
    } else if (action.type === 'delete') {
      entries.push(action.entry);
      void save(); render();
      toast('Undid delete');
    } else if (action.type === 'settle') {
      const item = entries.find(x => x.id === action.id);
      if (item) { item.status = action.prevStatus; item.payments = action.prevPayments; void save(); render(); if (selectedPersonId) openPerson(selectedPersonId); }
      toast('Undid settle');
    }
  }

  
  function renderAnalytics() {
    const ps = people();
    if (!ps.length) {
      const el = $('analyticsCard');
      if (el) el.innerHTML = '';
      return;
    }
    const topOwed = [...ps].filter(p => p.toYou > 0).sort((a,b) => b.toYou - a.toYou)[0];
    const topYouOwe = [...ps].filter(p => p.youOwe > 0).sort((a,b) => b.youOwe - a.youOwe)[0];
    const oldest = entries.filter(e => remaining(e) > 0).sort((a,b) => a.date.localeCompare(b.date))[0];
    let html = '<div class="analytics-card"><div class="card-label"><span class="label-icon">◇</span> INSIGHTS</div>';
    if (topOwed) html += `<div class="insight-row">Highest owed to you · <b>${esc(topOwed.name)}</b> ${money(topOwed.toYou)}</div>`;
    if (topYouOwe) html += `<div class="insight-row">You owe most to · <b>${esc(topYouOwe.name)}</b> ${money(topYouOwe.youOwe)}</div>`;
    if (oldest) html += `<div class="insight-row">Oldest open · ${dateText(oldest.date)} · ${esc(oldest.name)}</div>`;
    html += '</div>';
    const el = $('analyticsCard');
    if (el) el.innerHTML = html;
  }

  
  // Theme chips
  document.querySelectorAll('.theme-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const t = chip.dataset.theme;
      settings.theme = t;
      localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
      applyTheme();
      document.querySelectorAll('.theme-chip').forEach(c => c.classList.toggle('active', c.dataset.theme === t));
      toast('Theme updated');
    });
  });
  // Highlight current theme when settings open
  $('settingsButton').addEventListener('click', () => {
    const t = settings.theme || 'system';
    document.querySelectorAll('.theme-chip').forEach(c => c.classList.toggle('active', c.dataset.theme === t));
  });
  // Undo button
  const undoBtn = $('undoButton');
  if (undoBtn) undoBtn.addEventListener('click', () => { performUndo(); $('settingsDialog').close(); });

  
  function checkBackupReminder() {
    const last = settings.lastBackup || 0;
    const now = Date.now();
    const days = (now - last) / (1000*60*60*24);
    if (days > 14 && entries.length > 0) {
      setTimeout(() => {
        if (confirm('It has been a while since your last backup. Would you like to create an encrypted backup now?')) {
          $('backupButton').click();
        }
        settings.lastBackup = now; // soft update so it does not nag every launch
        localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
      }, 1800);
    }
  }

  
  async function biometricAvailable() {
    try {
      return !!(window.PublicKeyCredential && await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable());
    } catch { return false; }
  }
  async function tryBiometric() {
    if (!await biometricAvailable()) { toast('Biometric not available on this device'); return false; }
    try {
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      await navigator.credentials.get({
        publicKey: {
          challenge,
          timeout: 60000,
          userVerification: 'required',
          rpId: location.hostname || 'localhost'
        }
      });
      return true;
    } catch (e) {
      if (e.name !== 'NotAllowedError') toast('Biometric failed');
      return false;
    }
  }
  async function enableBiometricFlow() {
    if (!await biometricAvailable()) { toast('Biometric not available'); return; }
    const ok = await tryBiometric();
    if (ok) {
      settings.biometricEnabled = true;
      localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
      toast('Biometric unlock enabled');
      const row = $('biometricRow'); if (row) row.style.display = 'none';
      const btn = $('enableBiometric'); if (btn) btn.textContent = 'Enabled';
    }
  }

  
  // Biometric buttons
  const bioBtn = $('biometricButton');
  if (bioBtn) bioBtn.addEventListener('click', async () => {
    const ok = await tryBiometric();
    if (ok) {
      // Biometric verified – if we still need PIN, focus it; otherwise this is a convenience gate
      toast('Verified – enter your PIN to unlock');
      $('pinInput').focus();
    }
  });
  const enableBio = $('enableBiometric');
  if (enableBio) enableBio.addEventListener('click', () => enableBiometricFlow());
  // Show biometric row in settings when available and not enabled
  $('settingsButton').addEventListener('click', () => {
    const row = $('biometricRow');
    if (row) {
      biometricAvailable().then(ok => {
        row.style.display = (ok && !settings.biometricEnabled) ? 'flex' : 'none';
      });
    }
  });

  
  const clearDue = $('clearDueDate');
  if (clearDue) clearDue.addEventListener('click', () => { $('dueDate').value = ''; });

  
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if ((settings.theme || 'system') === 'system') applyTheme();
  });

  void initializeVault();
  if('serviceWorker' in navigator && location.protocol.startsWith('http')) navigator.serviceWorker.register('sw.js').catch(()=>{});
})();


