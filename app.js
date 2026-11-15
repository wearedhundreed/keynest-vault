const DB_KEY = 'keynest-encrypted-vault-v1';
const DB_SALT = 'keynest-kdf-salt-v1';
const ITERATIONS = 310000;
const encoder = new TextEncoder();
let cryptoKey = null;
let entries = [];
let editingId = null;
let rulesData = {};
let changeUrls = {};
let toastTimer;
const $ = (id) => document.getElementById(id);

async function loadResources() {
  const getResource = async (url) => {
    try { const response = await fetch(url, { cache: 'no-cache' }); return response.ok ? await response.json() : {}; }
    catch { return {}; }
  };
  [rulesData, changeUrls] = await Promise.all([
    getResource('/resources/password-rules.json'),
    getResource('/resources/change-password-URLs.json')
  ]);
}

function deriveKey(password, salt) {
  return crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']).then(key =>
    crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' }, key,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']));
}
function getSalt() {
  const saved = localStorage.getItem(DB_SALT);
  if (saved) return Uint8Array.from(atob(saved), c => c.charCodeAt(0));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  localStorage.setItem(DB_SALT, btoa(String.fromCharCode(...salt)));
  return salt;
}
async function encryptVault() {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, encoder.encode(JSON.stringify(entries)));
  localStorage.setItem(DB_KEY, JSON.stringify({ iv: btoa(String.fromCharCode(...iv)), data: btoa(String.fromCharCode(...new Uint8Array(cipher))) }));
}
async function decryptVault(key) {
  const stored = localStorage.getItem(DB_KEY);
  if (!stored) return [];
  const vault = JSON.parse(stored);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: Uint8Array.from(atob(vault.iv), c => c.charCodeAt(0)) }, key,
    Uint8Array.from(atob(vault.data), c => c.charCodeAt(0)));
  return JSON.parse(new TextDecoder().decode(plain));
}
function showUnlock() {
  $('unlock-screen').classList.remove('hidden');
  const exists = Boolean(localStorage.getItem(DB_KEY));
  $('confirm-wrap').classList.toggle('hidden', exists);
  $('unlock-title').textContent = exists ? 'Unlock your vault' : 'Create your vault';
  $('unlock-copy').textContent = exists ? 'Enter your master password to decrypt this browser’s vault.' : 'Choose a strong master password. It cannot be recovered if lost.';
  $('unlock-submit').textContent = exists ? 'Unlock vault' : 'Create vault';
  $('master-password').setAttribute('autocomplete', exists ? 'current-password' : 'new-password');
}
function lockVault() {
  cryptoKey = null; entries = [];
  $('entry-list').replaceChildren();
  $('unlock-form').reset(); $('unlock-error').textContent = '';
  showUnlock();
}
$('unlock-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const password = $('master-password').value;
  const exists = Boolean(localStorage.getItem(DB_KEY));
  if (password.length < 12) { $('unlock-error').textContent = 'Use a master password with at least 12 characters.'; return; }
  if (!exists && password !== $('confirm-password').value) { $('unlock-error').textContent = 'The passwords do not match.'; return; }
  $('unlock-submit').disabled = true; $('unlock-error').textContent = '';
  try {
    cryptoKey = await deriveKey(password, getSalt());
    if (exists) entries = await decryptVault(cryptoKey);
    else { entries = []; await encryptVault(); }
    $('unlock-screen').classList.add('hidden');
    renderEntries(); $('unlock-form').reset();
  } catch {
    cryptoKey = null; $('unlock-error').textContent = 'Could not unlock. Check the master password and try again.';
  } finally { $('unlock-submit').disabled = false; }
});

function normalizedDomain(value) {
  let text = value.trim().toLowerCase();
  if (!text) return '';
  try { if (!text.includes('://')) text = `https://${text}`; return new URL(text).hostname.replace(/^www\./, ''); }
  catch { return text.replace(/^www\./, '').split('/')[0].split(':')[0]; }
}
function findDomainRecord(data, domain) {
  const host = normalizedDomain(domain);
  if (!host) return null;
  const labels = host.split('.');
  for (let i = 0; i < labels.length - 1; i++) {
    const key = labels.slice(i).join('.');
    if (Object.hasOwn(data, key)) return data[key];
  }
  return null;
}
function passwordRequirements(domain) {
  const record = findDomainRecord(rulesData, domain);
  const raw = record && (record['password-rules'] || record);
  if (!raw || typeof raw !== 'string') return { min: 20, max: 32, groups: [] };
  const min = Number(raw.match(/minlength:\s*(\d+)/i)?.[1] || 12);
  const max = Number(raw.match(/maxlength:\s*(\d+)/i)?.[1] || 32);
  const groups = [];
  if (/required:\s*[^;]*\blower\b/i.test(raw)) groups.push('lower');
  if (/required:\s*[^;]*\bupper\b/i.test(raw)) groups.push('upper');
  if (/required:\s*[^;]*\bdigit\b/i.test(raw)) groups.push('digit');
  if (/required:\s*[^;]*(?:special|\[[^\]]+\])/i.test(raw)) groups.push('special');
  return { min: Math.max(1, Math.min(min, 128)), max: Math.max(min, Math.min(max, 128)), groups };
}
function randomIndex(max) { const limit = Math.floor(0x100000000 / max) * max; const values = new Uint32Array(1); do { crypto.getRandomValues(values); } while (values[0] >= limit); return values[0] % max; }
function generatePassword(domain) {
  const policy = passwordRequirements(domain);
  const chars = { lower: 'abcdefghijkmnopqrstuvwxyz', upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ', digit: '23456789', special: '!@#$%&*+-=?_' };
  const all = Object.values(chars).join('');
  const length = Math.max(policy.min, Math.min(policy.max, 20));
  const out = policy.groups.map(group => chars[group][randomIndex(chars[group].length)]);
  while (out.length < length) out.push(all[randomIndex(all.length)]);
  for (let i = out.length - 1; i > 0; i--) { const j = randomIndex(i + 1); [out[i], out[j]] = [out[j], out[i]]; }
  return out.join('');
}
function openEditor(entry = null) {
  editingId = entry?.id || null; $('entry-form').reset(); $('form-error').textContent = '';
  $('modal-title').textContent = entry ? 'Edit login' : 'Add a login';
  $('entry-title').value = entry?.title || ''; $('entry-website').value = entry?.website || '';
  $('entry-username').value = entry?.username || ''; $('entry-password').value = entry?.password || '';
  $('entry-notes').value = entry?.notes || ''; $('entry-password').type = 'password'; $('toggle-password').textContent = 'Show';
  updateSiteHint(); $('entry-modal').classList.remove('hidden'); $('entry-title').focus();
}
function closeEditor() { $('entry-modal').classList.add('hidden'); editingId = null; }
function updateSiteHint() {
  const domain = normalizedDomain($('entry-website').value);
  const hint = $('site-hint'); const rules = findDomainRecord(rulesData, domain); const change = findDomainRecord(changeUrls, domain);
  if (!domain || (!rules && !change)) { hint.classList.add('hidden'); hint.replaceChildren(); return; }
  hint.classList.remove('hidden'); hint.replaceChildren();
  if (rules) { const p = document.createElement('div'); p.textContent = `Apple password rules: ${rules['password-rules'] || 'available'}`; hint.append(p); }
  if (change && /^https:\/\//i.test(change)) { const a = document.createElement('a'); a.href = change; a.target = '_blank'; a.rel = 'noopener noreferrer'; a.textContent = 'Open password-change page ↗'; hint.append(a); }
}
$('entry-website').addEventListener('input', updateSiteHint);
$('generate-button').addEventListener('click', () => { $('entry-password').value = generatePassword($('entry-website').value); $('entry-password').type = 'text'; $('toggle-password').textContent = 'Hide'; });
$('toggle-password').addEventListener('click', () => { const input = $('entry-password'); input.type = input.type === 'password' ? 'text' : 'password'; $('toggle-password').textContent = input.type === 'password' ? 'Show' : 'Hide'; });
$('entry-form').addEventListener('submit', async (event) => {
  event.preventDefault(); $('form-error').textContent = '';
  if (!cryptoKey) { $('form-error').textContent = 'Unlock the vault to save entries.'; return; }
  const website = $('entry-website').value.trim();
  if (website && !normalizedDomain(website)) { $('form-error').textContent = 'Enter a valid website host.'; return; }
  const item = { id: editingId || crypto.randomUUID(), title: $('entry-title').value.trim(), website, username: $('entry-username').value.trim(), password: $('entry-password').value, notes: $('entry-notes').value.trim(), updatedAt: Date.now() };
  if (editingId) entries = entries.map(e => e.id === editingId ? item : e); else entries.unshift(item);
  try { await encryptVault(); closeEditor(); renderEntries(); notify('Login saved in your encrypted vault.'); }
  catch { $('form-error').textContent = 'Could not save. Browser storage may be full.'; }
});
function notify(message) { const toast = $('toast'); toast.textContent = message; toast.classList.add('visible'); clearTimeout(toastTimer); toastTimer = setTimeout(() => toast.classList.remove('visible'), 2300); }
async function copyText(value, label) { try { await navigator.clipboard.writeText(value); notify(`${label} copied.`); } catch { notify('Clipboard access is unavailable in this context.'); } }
function makeButton(label, title, action) { const button = document.createElement('button'); button.className = 'icon-button'; button.type = 'button'; button.textContent = label; button.title = title; button.setAttribute('aria-label', title); button.addEventListener('click', action); return button; }
function renderEntries() {
  const query = $('search').value.trim().toLowerCase();
  const filtered = entries.filter(e => [e.title, e.website, e.username].some(v => (v || '').toLowerCase().includes(query)));
  const list = $('entry-list'); list.replaceChildren();
  $('item-count').textContent = String(entries.length); $('total-label').textContent = `${entries.length} saved ${entries.length === 1 ? 'item' : 'items'}`;
  $('empty-state').classList.toggle('hidden', entries.length > 0);
  if (entries.length && !filtered.length) { const p = document.createElement('p'); p.className = 'empty-state'; p.textContent = 'No matching logins.'; list.append(p); }
  for (const entry of filtered) {
    const card = document.createElement('article'); card.className = 'entry-card';
    const icon = document.createElement('div'); icon.className = 'entry-icon'; icon.textContent = (entry.title || '?').slice(0, 1).toUpperCase();
    const info = document.createElement('div'); info.className = 'entry-info';
    const title = document.createElement('div'); title.className = 'entry-title'; title.textContent = entry.title;
    const sub = document.createElement('div'); sub.className = 'entry-sub'; sub.textContent = entry.username || entry.website || 'No username'; info.append(title, sub);
    const actions = document.createElement('div'); actions.className = 'entry-actions';
    actions.append(makeButton('⧉', 'Copy username', () => copyText(entry.username, 'Username')));
    actions.append(makeButton('◉', 'Copy password', () => copyText(entry.password, 'Password')));
    actions.append(makeButton('✎', 'Edit login', () => openEditor(entry)));
    actions.append(makeButton('×', 'Delete login', () => deleteEntry(entry.id)));
    card.append(icon, info, actions); list.append(card);
  }
}
async function deleteEntry(id) {
  const entry = entries.find(e => e.id === id);
  if (!entry || !confirm(`Delete “${entry.title}” from this vault?`)) return;
  entries = entries.filter(e => e.id !== id);
  try { await encryptVault(); renderEntries(); notify('Login deleted.'); } catch { notify('Could not update vault storage.'); }
}
$('search').addEventListener('input', renderEntries);
$('add-top').addEventListener('click', () => openEditor()); $('add-empty').addEventListener('click', () => openEditor());
$('close-modal').addEventListener('click', closeEditor); $('cancel-entry').addEventListener('click', closeEditor);
$('entry-modal').addEventListener('click', e => { if (e.target === $('entry-modal')) closeEditor(); });
$('lock-button').addEventListener('click', lockVault);
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeEditor(); });
(async function init() {
  if (!window.crypto?.subtle || location.protocol === 'file:') { $('unlock-error').textContent = 'Open this app through its local web server to use browser encryption.'; }
  await loadResources(); showUnlock(); $('master-password').focus();
})();
