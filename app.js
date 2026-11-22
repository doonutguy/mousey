// =============================================================================
//  Pico God Mouse control panel: the phone side
// =============================================================================
//  Flow:  Connect (Web Bluetooth)  ->  PIN unlock (HMAC challenge-response)
//         -> read CATALOG (features + settings)  -> build the page from it
//         -> send the phone's time, then any changes saved while offline
//         -> read STATUS every 1.5 s and update the page
//
//  SECURITY RULES this file follows:
//   - The PIN is never stored and never sent; only a one-time HMAC proof is.
//   - Text from the Pico is only ever put on the page with textContent,
//     never as HTML, so even a malicious device can't inject code.
//   - All Bluetooth operations go through one queue (gatt()), one at a time.
// =============================================================================
'use strict';

const SERVICE = 'ddae0000-e1da-4235-afa8-1a38c80198b6';
const UUID = {
  auth:    'ddae0001-e1da-4235-afa8-1a38c80198b6',
  catalog: 'ddae0002-e1da-4235-afa8-1a38c80198b6',
  status:  'ddae0003-e1da-4235-afa8-1a38c80198b6',
  command: 'ddae0004-e1da-4235-afa8-1a38c80198b6',
};
const POLL_MS = 1500;
const SEND_DELAY_MS = 700;     // wait this long after the last tap before sending
const TIME_STEP_MIN = 15;      // -/+ on a clock time moves it by 15 minutes
const STORE = { catalog: 'pgm.catalog.v1', values: 'pgm.values.v1', pending: 'pgm.pending.v1' };

const enc = new TextEncoder();
const dec = new TextDecoder();
const $ = (id) => document.getElementById(id);

// ---- State --------------------------------------------------------------------
let device = null;         // the BluetoothDevice chosen in Chrome's picker
let chars = null;          // { auth, catalog, status, command } characteristics
let unlocked = false;
let catalog = load(STORE.catalog, null);   // last catalog seen (works offline)
let values = load(STORE.values, {});       // { featureId: { on, values: [] } }
let pending = load(STORE.pending, {});     // { key: command } changes not yet sent
let polling = false;
const controls = {};                       // featureId -> { card, toggle, status, params: [...] }

// ---- Small helpers --------------------------------------------------------------
function load(key, fallback) {
  try { const v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; }
  catch { return fallback; }
}
function save(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* storage off: fine */ }
}
function bytes(dataView) {
  return new Uint8Array(dataView.buffer, dataView.byteOffset, dataView.byteLength);
}
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
function pad2(n) { return String(n).padStart(2, '0'); }

function say(text, kind = '') {
  const m = $('msg');
  m.textContent = text;
  m.className = 'msg' + (kind ? ' ' + kind : '');
}

function setPill(text, kind) {
  const p = $('pill');
  p.lastChild.textContent = text;          // keep the little LED dot (first child)
  p.className = 'pill pill-' + kind;
}

// Bluetooth allows one operation at a time: chain them in a queue.
let chain = Promise.resolve();
function gatt(op) {
  const p = chain.then(op);
  chain = p.catch(() => {});
  return p;
}

// =============================================================================
//  Connecting and unlocking
// =============================================================================
async function connect() {
  say('');
  try {
    if (!device) {
      // Chrome shows a list of nearby devices offering OUR service only.
      device = await navigator.bluetooth.requestDevice({ filters: [{ services: [SERVICE] }] });
      device.addEventListener('gattserverdisconnected', onDisconnected);
    }
    setPill('Connecting', 'warn');
    const server = await device.gatt.connect();
    const svc = await server.getPrimaryService(SERVICE);
    chars = {
      auth:    await svc.getCharacteristic(UUID.auth),
      catalog: await svc.getCharacteristic(UUID.catalog),
      status:  await svc.getCharacteristic(UUID.status),
      command: await svc.getCharacteristic(UUID.command),
    };
    // Step 2: make sure the link is paired + encrypted BEFORE asking for the PIN.
    // On a new phone this first protected read makes Android show its pairing
    // prompt (type the 6-digit passkey). We wait for it and retry a few times.
    setPill('Securing', 'warn');
    say('Securing the link… If Android asks, enter your 6-digit passkey.');
    let secured = false;
    for (let attempt = 0; attempt < 4 && !secured; attempt++) {
      try {
        await gatt(() => chars.auth.readValue());
        secured = true;
      } catch (err) {
        if (!device.gatt.connected) break;      // the Pico hung up on us
        await sleep(2500);                       // pairing prompt still open: wait, retry
      }
    }
    if (!secured) {
      if (device.gatt.connected) device.gatt.disconnect();
      setPill('Offline', 'off');
      say('This phone is not paired with the Pico yet. Hold the Pico\'s BOOTSEL button 3 s, ' +
          'then tap Connect and enter the passkey when Android asks.', 'error');
      return;
    }

    setPill('Locked', 'warn');
    showStep('pin');
    say('Secure link ready. Enter your PIN.');
    $('pin').focus();
  } catch (err) {
    if (err && err.name === 'NotFoundError') { say(''); setPill('Offline', 'off'); return; } // picker cancelled
    setPill('Offline', 'off');
    say('Could not connect: ' + friendly(err), 'error');
  }
}

// Prove we know the PIN without sending it:
//   key = SHA-256("PGM-PIN-v1:" + PIN)
//   proof = HMAC-SHA256(key, challenge(16 bytes) + "auth")
async function unlock(pin) {
  say('Checking PIN…');
  try {
    // A fresh one-time challenge (the link is already paired at this point).
    const challenge = bytes(await gatt(() => chars.auth.readValue()));
    if (challenge.length !== 16) throw new Error('unexpected challenge');

    const keyBytes = await crypto.subtle.digest('SHA-256', enc.encode('PGM-PIN-v1:' + pin));
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' },
                                              false, ['sign']);
    const msg = new Uint8Array(20);
    msg.set(challenge, 0);
    msg.set(enc.encode('auth'), 16);
    const proof = await crypto.subtle.sign('HMAC', key, msg);

    await gatt(() => chars.auth.writeValueWithResponse(proof));
  } catch (err) {
    if (!device || !device.gatt.connected) {
      say('Disconnected after 3 wrong PINs. The Pico is locked for a while; try again later.', 'error');
    } else {
      say('Wrong PIN, or the Pico is locked for a moment. Try again.', 'error');
      $('pin').focus();
    }
    return;
  }

  unlocked = true;
  setPill('Connected', 'ok');
  showStep('connected');
  say('Unlocked.', 'good');

  try {
    await loadCatalog();
    await sendTime();
    await flushPending();
  } catch (err) {
    say('Problem after unlock: ' + friendly(err), 'error');
  }
  startPolling();
}

function onDisconnected() {
  unlocked = false;
  polling = false;
  chars = null;
  setPill('Offline', 'off');
  showStep('connect');
  $('btn-connect').textContent = 'Reconnect';
  say('Disconnected. Changes you make now are saved and sent next time.');
  for (const ui of Object.values(controls)) updateActions(ui);
  renderPendingCard();
}

function disconnect() {
  if (device && device.gatt.connected) device.gatt.disconnect();
}

function showStep(step) {
  $('connect-step').hidden   = step !== 'connect';
  $('pin-step').hidden       = step !== 'pin';
  $('connected-step').hidden = step !== 'connected';
}

function friendly(err) {
  const text = (err && err.message) ? err.message : String(err);
  if (/GATT operation failed|NotSupported/i.test(text)) return 'the Pico refused (locked or not paired).';
  return text;
}

// =============================================================================
//  Reading data
// =============================================================================
// Android cuts any single Bluetooth value off at 600 bytes, so the Pico hands
// out its JSON in 480-byte pages: write "page <name> N", read, repeat until a
// page comes back shorter than 480. Page 0 makes the Pico take a fresh snapshot.
const PAGE_SIZE = 480;
async function readJson(characteristic, name) {
  const parts = [];
  let total = 0;
  for (let page = 0; page < 16; page++) {
    const raw = await gatt(async () => {
      await chars.command.writeValueWithResponse(enc.encode(`page ${name} ${page}`));
      return bytes(await characteristic.readValue()).slice();
    });
    parts.push(raw);
    total += raw.length;
    if (raw.length < PAGE_SIZE) break;
  }
  const all = new Uint8Array(total);
  let at = 0;
  for (const p of parts) { all.set(p, at); at += p.length; }
  return JSON.parse(dec.decode(all));
}

// Only accept data shaped like we expect; anything else is ignored.
function validCatalog(c) {
  return c && Array.isArray(c.features) && c.features.every((f) =>
    typeof f.id === 'string' && typeof f.name === 'string' && Array.isArray(f.params) &&
    f.params.every((p) => typeof p.id === 'string' && typeof p.label === 'string' &&
      ['number', 'choice', 'time', 'switch'].includes(p.type) &&
      Number.isFinite(p.min) && Number.isFinite(p.max) && Number.isFinite(p.step) && p.step > 0 &&
      (p.type !== 'choice' || (Array.isArray(p.choices) && p.choices.every((c) => typeof c === 'string'))) &&
      // optional "only show me when <p> = <v>" rule
      (p.if === undefined || (typeof p.if === 'object' && p.if !== null &&
                              typeof p.if.p === 'string' && Number.isFinite(p.if.v))) &&
      // optional digits after the dot (0..3)
      (p.dec === undefined || (Number.isInteger(p.dec) && p.dec >= 0 && p.dec <= 3))) &&
    // optional buttons
    (f.actions === undefined || (Array.isArray(f.actions) && f.actions.every((a) =>
      a && typeof a.id === 'string' && /^[a-z0-9_]{1,24}$/.test(a.id) && typeof a.label === 'string'))));
}

async function loadCatalog() {
  const c = await readJson(chars.catalog, 'catalog');
  if (!validCatalog(c)) throw new Error('catalog has an unexpected format');
  catalog = c;
  save(STORE.catalog, catalog);
  render();
}

async function readStatus() {
  const s = await readJson(chars.status, 'status');
  if (!s || !Array.isArray(s.features)) return;

  $('sys-pc').textContent = String(s.pc ?? '–');
  $('sys-clock').textContent = s.clock ? String(s.clock) : 'not set';
  const up = Number(s.uptime) || 0;
  $('sys-uptime').textContent = `${Math.floor(up / 3600)}h ${pad2(Math.floor(up / 60) % 60)}m`;
  $('sys-temp').textContent = Number.isFinite(s.temp) ? `${s.temp.toFixed(1)} °C` : '–';
  $('sys-fw').textContent = String(s.fw ?? '–');

  for (const f of s.features) {
    if (typeof f.id !== 'string' || !Array.isArray(f.values)) continue;
    values[f.id] = { on: !!f.on, values: f.values.map(Number) };
    const ui = controls[f.id];
    if (!ui) continue;
    ui.status.textContent = String(f.text ?? '');
    if (!ui.toggleBusy) setToggle(ui, !!f.on);
    ui.params.forEach((pc, i) => {
      // Don't overwrite a setting the user is changing right now.
      if (!pc.busy() && i < f.values.length) pc.set(Number(f.values[i]));
    });
    updateVisibility(ui);
  }
  save(STORE.values, values);
}

function startPolling() {
  if (polling) return;
  polling = true;
  (async () => {
    while (polling && unlocked && device && device.gatt.connected) {
      try { await readStatus(); } catch { /* one missed update is fine */ }
      await sleep(POLL_MS);
    }
    polling = false;
  })();
}

// =============================================================================
//  Sending commands (live, or saved for later)
// =============================================================================
async function writeCommand(text) {
  await gatt(() => chars.command.writeValueWithResponse(enc.encode(text)));
}

// key identifies WHAT is being changed, so a newer offline change replaces an older one.
async function send(key, text) {
  if (unlocked && device && device.gatt.connected) {
    try {
      await writeCommand(text);
      delete pending[key];
      save(STORE.pending, pending);
      say('Sent: ' + text, 'good');
      readStatus().catch(() => {});
    } catch (err) {
      say('The Pico rejected "' + text + '"', 'error');
    }
  } else {
    pending[key] = text;
    save(STORE.pending, pending);
    say('Saved on this phone. It will be sent when you connect.');
  }
  renderPendingCard();
}

async function sendTime() {
  const d = new Date();
  await writeCommand(`time ${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`);
}

async function flushPending() {
  const entries = Object.entries(pending);
  for (const [key, text] of entries) {
    try { await writeCommand(text); } catch { /* invalid now (e.g. feature changed): drop it */ }
    delete pending[key];
  }
  save(STORE.pending, pending);
  renderPendingCard();
  if (entries.length) say(`Applied ${entries.length} saved change(s).`, 'good');
}

function renderPendingCard() {
  const n = Object.keys(pending).length;
  $('pending-card').hidden = n === 0;
  $('pending-count').textContent = String(n);
  for (const [fid, ui] of Object.entries(controls)) {
    ui.params.forEach((pc) => pc.row.classList.toggle('pending', `${fid}.${pc.def.id}` in pending));
  }
}

// =============================================================================
//  Building the page from the catalog
// =============================================================================
//  No sliders: every setting is changed by TAPPING.
//    number -> [ − ]  60 s  [ + ]   (hold a button to go faster; tap the number to type it)
//    choice -> a row of buttons, tap the one you want
//    time   -> [ − ]  18:00  [ + ]  (15-minute steps; tap the time to pick it exactly)
//    switch -> an on/off switch next to the setting's name
// =============================================================================
function prettyChoice(name) { return name.replace(/-/g, ' '); }   // "after-duration" -> "after duration"
function timeText(v) { return `${pad2(Math.floor(v / 60))}:${pad2(v % 60)}`; }

// Keep a number inside its limits and on its step grid (same rule as the Pico).
function snap(def, v) {
  v = Math.round((v - def.min) / def.step) * def.step + def.min;
  return Math.min(def.max, Math.max(def.min, v));
}

// Numbers with decimals are stored scaled: with dec = 1, 75 means 7.5.
function scaleOf(def) { return 10 ** (def.dec || 0); }
function numberText(def, v) { return (v / scaleOf(def)).toFixed(def.dec || 0); }

// The value as the Pico's command expects it, e.g. "square", "18:00", "60", "7.5".
function valueText(def, v) {
  if (def.type === 'switch') return v ? 'on' : 'off';
  if (def.type === 'choice') return def.choices[v] ?? String(v);
  if (def.type === 'time') return timeText(v);
  return numberText(def, v);
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

// A button that repeats while held, getting faster the longer you hold it.
// onStep(multiplier) is called once per "tick".
function holdButton(btn, onStep) {
  let timer = null;
  let ticks = 0;
  const stop = () => { clearTimeout(timer); timer = null; };
  const tick = () => {
    onStep(ticks < 8 ? 1 : ticks < 20 ? 2 : 6);
    ticks++;
    timer = setTimeout(tick, ticks === 1 ? 420 : 90);
  };
  btn.addEventListener('pointerdown', (e) => {
    e.preventDefault();
    stop();
    ticks = 0;
    tick();
  });
  for (const ev of ['pointerup', 'pointercancel', 'pointerleave']) btn.addEventListener(ev, stop);
  btn.addEventListener('contextmenu', (e) => e.preventDefault());   // no long-press menu
  btn.addEventListener('keydown', (e) => {                          // keyboard users
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onStep(1); }
  });
}

function keyButton(symbol, label) {
  const b = el('button', 'key', symbol);
  b.type = 'button';
  b.setAttribute('aria-label', label);
  return b;
}

// ---- One control per setting --------------------------------------------------
// Each returns { el, set(v) } and calls commit(v) when the user changes the value.

function stepperControl(def, commit) {
  const wrap = el('div', 'stepper');
  const minus = keyButton('−', 'Decrease ' + def.label);
  const plus = keyButton('+', 'Increase ' + def.label);
  const screen = el('label', 'readout');
  const input = el('input');
  input.type = 'text';
  input.inputMode = def.dec ? 'decimal' : 'numeric';
  input.setAttribute('aria-label', def.label);
  input.setAttribute('enterkeyhint', 'done');
  const unit = el('span', 'unit', def.unit || '');
  screen.append(input, unit);
  wrap.append(minus, screen, plus);

  let value = def.min;
  const show = () => { input.value = numberText(def, value); };
  const change = (v) => { v = snap(def, v); if (v !== value) { value = v; show(); commit(value); } };

  // Decimal settings move in tiny steps (0.1 s): holding speeds up more.
  const fast = (m) => (def.dec && m > 1 ? m * 5 : m);
  holdButton(minus, (m) => change(value - def.step * fast(m)));
  holdButton(plus,  (m) => change(value + def.step * fast(m)));

  // Tap the number to type it with the phone's keypad.
  input.addEventListener('focus', () => input.select());
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') input.blur(); });
  input.addEventListener('blur', () => {
    // Accept "7.5" and "7,5" (comma keypads); scale to the stored whole number.
    const typed = Number(input.value.replace(',', '.').replace(/[^\d.-]/g, ''));
    if (input.value.trim() !== '' && Number.isFinite(typed)) change(Math.round(typed * scaleOf(def)));
    show();                                   // also undoes nonsense input
  });

  return {
    el: wrap,
    focused: () => document.activeElement === input,
    set(v) { value = snap(def, v); if (document.activeElement !== input) show(); },
  };
}

function segmentedControl(def, commit) {
  const wrap = el('div', 'segments');
  wrap.setAttribute('role', 'radiogroup');
  wrap.setAttribute('aria-label', def.label);
  if (def.choices.length > 3) wrap.classList.add('many');
  let value = 0;
  const buttons = def.choices.map((name, idx) => {
    const b = el('button', 'seg', prettyChoice(name));
    b.type = 'button';
    b.setAttribute('role', 'radio');
    b.addEventListener('click', () => {
      if (idx === value) return;
      value = idx; show(); commit(value);
    });
    wrap.append(b);
    return b;
  });
  const show = () => buttons.forEach((b, idx) => b.setAttribute('aria-checked', String(idx === value)));
  show();
  return { el: wrap, focused: () => false, set(v) { value = v; show(); } };
}

function timeControl(def, commit) {
  const wrap = el('div', 'stepper');
  const minus = keyButton('−', `${def.label}: ${TIME_STEP_MIN} minutes earlier`);
  const plus = keyButton('+', `${def.label}: ${TIME_STEP_MIN} minutes later`);
  const screen = el('label', 'readout readout-time');
  const input = el('input');
  input.type = 'time';                         // tap it: Android's clock picker
  input.setAttribute('aria-label', def.label);
  screen.append(input);
  wrap.append(minus, screen, plus);

  let value = 0;
  const show = () => { input.value = timeText(value); };
  const change = (v) => { v = ((v % 1440) + 1440) % 1440; if (v !== value) { value = v; show(); commit(value); } };

  // -/+ jump to the next 15-minute mark (17:52 + -> 18:00, then 18:15 ...).
  holdButton(minus, (m) => change((Math.ceil(value / TIME_STEP_MIN) - m) * TIME_STEP_MIN));
  holdButton(plus,  (m) => change((Math.floor(value / TIME_STEP_MIN) + m) * TIME_STEP_MIN));

  input.addEventListener('change', () => {
    const m = /^(\d{2}):(\d{2})$/.exec(input.value);
    if (m) change(Number(m[1]) * 60 + Number(m[2]));
    else show();
  });

  return {
    el: wrap,
    focused: () => document.activeElement === input,
    set(v) { value = ((v % 1440) + 1440) % 1440; if (document.activeElement !== input) show(); },
  };
}

function switchControl(def, commit) {
  const sw = el('label', 'switch switch-small');
  const input = el('input');
  input.type = 'checkbox';
  input.setAttribute('role', 'switch');
  input.setAttribute('aria-label', def.label);
  sw.append(input, el('span'));
  input.addEventListener('change', () => commit(input.checked ? 1 : 0));
  return { el: sw, focused: () => false, set(v) { input.checked = !!v; } };
}

// Hide settings whose "only show if" rule isn't met (e.g. Stop at, when Stop rule = never).
function updateVisibility(ui) {
  for (const pc of ui.params) {
    const rule = pc.def.if;
    if (!rule) continue;
    const other = ui.params.find((o) => o.def.id === rule.p);
    pc.row.hidden = !!other && other.value !== rule.v;
  }
}

// Keep the phone's copy of the values up to date, so an offline change is still
// shown after the page is closed and reopened (not just queued to be sent).
function rememberValue(fid, index, v) {
  const entry = values[fid] || (values[fid] = { on: false, values: [] });
  if (index === '$on') entry.on = !!v;
  else entry.values[index] = v;
  save(STORE.values, values);
}

function setToggle(ui, on) {
  ui.toggle.checked = on;
  ui.card.classList.toggle('is-on', on);
  updateActions(ui);
}

// Buttons only work live: connected, unlocked, and the feature switched ON.
function updateActions(ui) {
  if (!ui.actions) return;
  const live = unlocked && !!device && device.gatt.connected && ui.toggle.checked;
  for (const b of ui.actions) b.disabled = !live;
  if (ui.actionHint) {
    ui.actionHint.textContent = !unlocked ? 'Connect to use the buttons.'
      : !ui.toggle.checked ? 'Switch on to use the buttons.' : '';
  }
}

// Press a button: sent right away, NEVER saved for later (an old key press
// arriving hours later would be a nasty surprise).
async function pressAction(f, a, btn) {
  if (!unlocked || !device || !device.gatt.connected) { say('Connect first.', 'error'); return; }
  btn.disabled = true;
  try {
    await writeCommand(`do ${f.id} ${a.id}`);
    say('Sent ' + a.label, 'good');
  } catch {
    let why = '';
    try { const s = await readJson(chars.status, 'status'); why = typeof s.last === 'string' ? s.last : ''; } catch { /* ignore */ }
    say('Not sent' + (why ? ': ' + why : '.'), 'error');
  }
  setTimeout(() => updateActions(controls[f.id]), 300);   // short pause stops double taps
}

function render() {
  const box = $('features');
  box.replaceChildren();
  for (const k of Object.keys(controls)) delete controls[k];
  if (!catalog) { $('stop-card').hidden = true; return; }

  catalog.features.forEach((f, fi) => {
    const card = el('section', 'card feature');
    const head = el('div', 'feat-head');
    const title = el('div', 'feat-title');
    title.append(el('span', 'idx', pad2(fi + 1)), el('h2', '', f.name));
    head.append(title);

    const sw = el('label', 'switch');
    const toggle = el('input');
    toggle.type = 'checkbox';
    toggle.setAttribute('role', 'switch');
    toggle.setAttribute('aria-label', f.name + ' on/off');
    sw.append(toggle, el('span'));
    head.append(sw);

    const status = el('p', 'feat-status', unlocked ? '' : 'Offline: showing last known settings');
    card.append(head, status);

    const ui = { card, toggle, status, params: [], toggleBusy: false };
    const saved = values[f.id];
    setToggle(ui, saved ? !!saved.on : false);
    toggle.addEventListener('change', () => {
      // Features that press keys can only be switched on LIVE, never queued
      // offline (so nothing starts typing by surprise on the next connect).
      if (f.risky && !(unlocked && device && device.gatt.connected)) {
        toggle.checked = !toggle.checked;
        say(`Connect first: ${f.name} presses keys, so it can only be switched live.`, 'error');
        return;
      }
      setToggle(ui, toggle.checked);
      rememberValue(f.id, '$on', toggle.checked);
      send(`${f.id}.$on`, `${toggle.checked ? 'on' : 'off'} ${f.id}`);
    });

    const list = el('div', 'params');
    f.params.forEach((def, i) => {
      const row = el('div', 'param');
      const top = el('div', 'param-top');
      top.append(el('span', 'param-label', def.label));
      row.append(top);

      // pc = everything about this one setting on the page
      const pc = { def, row, value: def.min, timer: null, busyUntil: 0 };

      // Called on every tap: update the page now, send to the Pico once the taps stop.
      const commit = (v) => {
        pc.value = v;
        rememberValue(f.id, i, v);
        pc.busyUntil = Date.now() + SEND_DELAY_MS + POLL_MS;
        updateVisibility(ui);
        clearTimeout(pc.timer);
        pc.timer = setTimeout(() =>
          send(`${f.id}.${def.id}`, `set ${f.id} ${def.id} ${valueText(def, pc.value)}`), SEND_DELAY_MS);
      };

      const ctl = def.type === 'choice' ? segmentedControl(def, commit)
                : def.type === 'time'   ? timeControl(def, commit)
                : def.type === 'switch' ? switchControl(def, commit)
                :                         stepperControl(def, commit);
      pc.busy = () => ctl.focused() || Date.now() < pc.busyUntil;
      pc.set = (v) => {
        if (!Number.isFinite(v)) return;
        pc.value = def.type === 'number' ? snap(def, v) : v;
        ctl.set(pc.value);
      };
      if (def.type === 'switch') { row.classList.add('param-switch'); top.append(ctl.el); }
      else row.append(ctl.el);
      list.append(row);
      ui.params.push(pc);

      const start = saved && Number.isFinite(saved.values?.[i]) ? saved.values[i] : def.min;
      pc.set(start);
    });
    if (f.params.length) card.append(list);

    // Buttons (e.g. Ctrl+Enter, F, N)
    if (f.actions && f.actions.length) {
      const row = el('div', 'actions');
      ui.actions = f.actions.map((a) => {
        const b = el('button', 'btn btn-action', a.label);
        b.type = 'button';
        b.addEventListener('click', () => pressAction(f, a, b));
        row.append(b);
        return b;
      });
      ui.actionHint = el('p', 'hint', '');
      card.append(row, ui.actionHint);
      updateActions(ui);
    }

    updateVisibility(ui);
    controls[f.id] = ui;
    box.append(card);
  });
  $('stop-card').hidden = false;
  renderPendingCard();
}

// =============================================================================
//  Start-up
// =============================================================================
function init() {
  if (!('bluetooth' in navigator)) {
    $('unsupported').hidden = false;
    $('btn-connect').disabled = true;
  }
  $('btn-connect').addEventListener('click', connect);
  $('btn-disconnect').addEventListener('click', disconnect);
  $('pin-step').addEventListener('submit', (e) => {
    e.preventDefault();
    const pinInput = $('pin');
    const pin = pinInput.value;
    pinInput.value = '';                 // don't leave the PIN on screen
    if (pin.length >= 6) unlock(pin);
    else say('PIN is at least 6 characters.', 'error');
  });
  $('btn-stopall').addEventListener('click', () => {
    if (confirm('Switch every feature off?')) send('$stopall', 'stopall');
  });
  $('btn-clear-pending').addEventListener('click', () => {
    pending = {};
    save(STORE.pending, pending);
    renderPendingCard();
    say('Saved changes discarded.');
  });

  showStep('connect');
  render();          // shows last known settings, editable offline
}

init();
