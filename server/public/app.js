'use strict';

const $app = document.getElementById('app');
const $nav = document.getElementById('nav');
const $brand = document.getElementById('brand');
const $toast = document.getElementById('toast');
const state = { user: null, tab: 'documents' };

// Password rules. The server checks the same rules again; this is only for feedback.
const MIN_LENGTH = 6; // change to 8 here AND in server/src/routes/auth.js
const RULES = [
  ['At least ' + MIN_LENGTH + ' characters', (p) => p.length >= MIN_LENGTH],
  ['An uppercase letter (A-Z)', (p) => /[A-Z]/.test(p)],
  ['A lowercase letter (a-z)', (p) => /[a-z]/.test(p)],
  ['A number (0-9)', (p) => /[0-9]/.test(p)],
  ['A special character (! @ # $ ...)', (p) => /[^A-Za-z0-9\s]/.test(p)],
];

const DEMOS = [
  { role: 'admin', label: 'Admin', icon: 'key', email: 'admin@trustvault.test', password: 'AdminDemo#2026', text: 'Approves accounts and watches the audit trail. Cannot open files.' },
  { role: 'owner', label: 'Owner', icon: 'upload', email: 'owner@trustvault.test', password: 'OwnerDemo#2026', text: 'Uploads documents and shares them with named people.' },
  { role: 'viewer', label: 'Viewer', icon: 'eye', email: 'viewer@trustvault.test', password: 'ViewerDemo#2026', text: 'Sees only the documents shared with them.' },
];

const ROLE_INFO = {
  admin: ['Administration', 'Approve new accounts, watch activity and verify the audit chain. File contents stay private.'],
  owner: ['Your document space', 'Upload documents and decide exactly who may open them.'],
  viewer: ['Shared with you', 'Documents that owners have given you access to appear here.'],
  pending: ['Almost there', 'An administrator has to give your account a role first.'],
};

// ---------- helpers ----------
// Builds an element. Text is always inserted as text, never as HTML.
function el(tag, attrs = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else node.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    node.append(kid);
  }
  return node;
}

// Replaces everything inside a parent, skipping empty values and flattening lists.
function setKids(parent, ...kids) {
  parent.replaceChildren(...kids.flat().filter((k) => k !== null && k !== undefined && k !== false));
}

const SVG_NS = 'http://www.w3.org/2000/svg';
const ICONS = {
  eye: [['path', { d: 'M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z' }], ['circle', { cx: 12, cy: 12, r: 3 }]],
  eyeOff: [
    ['path', { d: 'M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24' }],
    ['line', { x1: 1, y1: 1, x2: 23, y2: 23 }],
  ],
  shield: [['path', { d: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' }], ['path', { d: 'M9 12l2 2 4-4' }]],
  check: [['path', { d: 'M20 6L9 17l-5-5' }]],
  file: [['path', { d: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z' }], ['path', { d: 'M14 2v6h6' }]],
  lock: [['rect', { x: 3, y: 11, width: 18, height: 11, rx: 2, ry: 2 }], ['path', { d: 'M7 11V7a5 5 0 0 1 10 0v4' }]],
  users: [
    ['path', { d: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2' }], ['circle', { cx: 9, cy: 7, r: 4 }],
    ['path', { d: 'M23 21v-2a4 4 0 0 0-3-3.87' }], ['path', { d: 'M16 3.13a4 4 0 0 1 0 7.75' }],
  ],
  activity: [['polyline', { points: '22 12 18 12 15 21 9 3 6 12 2 12' }]],
  upload: [
    ['path', { d: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4' }], ['polyline', { points: '17 8 12 3 7 8' }],
    ['line', { x1: 12, y1: 3, x2: 12, y2: 15 }],
  ],
  key: [['path', { d: 'M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4' }]],
};
function icon(name, size = 18) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  const set = { viewBox: '0 0 24 24', width: size, height: size, fill: 'none', stroke: 'currentColor', 'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' };
  for (const [k, v] of Object.entries(set)) svg.setAttribute(k, v);
  for (const [tag, attrs] of ICONS[name]) {
    const n = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    svg.append(n);
  }
  return svg;
}

let toastTimer;
function toast(message, bad) {
  $toast.textContent = message;
  $toast.className = 'show' + (bad ? ' bad' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { $toast.className = ''; }, 4000);
}

function shake(node) {
  node.classList.remove('shake');
  void node.offsetWidth; // restart the animation
  node.classList.add('shake');
}

async function withBusy(button, fn) {
  button.classList.add('busy');
  button.disabled = true;
  try { return await fn(); } finally { button.classList.remove('busy'); button.disabled = false; }
}

async function api(path, { method = 'GET', json, form, blob } = {}) {
  const opts = { method, credentials: 'same-origin', headers: {} };
  if (json !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(json);
  }
  if (form) opts.body = form;
  const res = await fetch(path, opts);
  const isJson = (res.headers.get('content-type') || '').includes('application/json');
  let data = null;
  if (isJson) data = await res.json();
  else if (blob && res.ok) data = await res.blob();
  if (!res.ok) {
    if (res.status === 401 && path !== '/api/auth/login') {
      state.user = null;
      render();
    }
    const err = new Error((data && data.error) || 'Request failed (' + res.status + ')');
    err.status = res.status;
    throw err;
  }
  return { data, res };
}

const fmtDate = (v) => (v ? new Date(v).toLocaleString() : '');
function fmtSize(n) {
  n = Number(n);
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(1) + ' MB';
}

function table(headers, rows) {
  return el('div', { class: 'scroll' },
    el('table', {},
      el('thead', {}, el('tr', {}, headers.map((h) => el('th', { text: h })))),
      el('tbody', {}, rows.map((r) => el('tr', {}, r.map((c) => el('td', {}, c)))))));
}

// Counts a number up from 0, unless the person asked for less motion.
function countUp(node, to) {
  to = Number(to) || 0;
  if (to === 0 || window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    node.textContent = String(to);
    return;
  }
  const start = performance.now();
  const duration = 700;
  function tick(now) {
    const p = Math.min(1, (now - start) / duration);
    node.textContent = String(Math.round(to * (1 - Math.pow(1 - p, 3))));
    if (p < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

function tile(label, iconName) {
  const value = el('strong', { text: '-' });
  const node = el('div', { class: 'tile' },
    el('span', { class: 'tile-icon' }, icon(iconName, 18)),
    el('span', { class: 'tile-text' }, value, el('span', { text: label })));
  return {
    node,
    set(v, tone) {
      if (typeof v === 'number') countUp(value, v); else value.textContent = String(v);
      node.dataset.tone = tone || '';
    },
  };
}

// The coloured banner at the top of each dashboard.
function welcome(tiles) {
  const [eyebrow, text] = ROLE_INFO[state.user.role] || ROLE_INFO.viewer;
  const first = (state.user.name || '').split(' ')[0] || 'there';
  return el('section', { class: 'welcome' },
    el('div', { class: 'welcome-text' },
      el('span', { class: 'eyebrow', text: eyebrow }),
      el('h2', { text: 'Welcome back, ' + first }),
      el('p', { text })),
    el('div', { class: 'tiles' }, tiles.map((t) => t.node)));
}

// ---------- login and registration ----------
function passwordField(autocomplete) {
  const input = el('input', { type: 'password', required: true, autocomplete, placeholder: 'Your password' });
  const eye = el('button', { type: 'button', class: 'eye', 'aria-label': 'Show password', 'aria-pressed': 'false' }, icon('eye'));
  eye.addEventListener('click', () => {
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    eye.setAttribute('aria-pressed', String(show));
    eye.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    setKids(eye, icon(show ? 'eyeOff' : 'eye'));
  });
  return { input, node: el('label', {}, 'Password', el('div', { class: 'pw' }, input, eye)) };
}

function heroPanel() {
  const art = el('img', { class: 'art', src: '/vault.svg', alt: 'A shield protecting documents, with an audit log beside it', width: '520', height: '420' });
  const hero = el('section', { class: 'hero' },
    el('span', { class: 'blob b1' }), el('span', { class: 'blob b2' }), el('span', { class: 'grid-lines' }),
    el('div', { class: 'hero-inner' },
      el('div', { class: 'brand-chip' }, icon('shield', 18), el('span', { text: 'TrustVault' })),
      el('h2', {}, 'Only the right people.', el('br'), el('span', { class: 'grad', text: 'Every access on record.' })),
      el('p', { class: 'lead', text: 'Share confidential documents with permissions that hold, and an audit trail you can prove.' }),
      el('div', { class: 'art-wrap' }, art),
      el('ul', { class: 'pills' },
        ['Checked on the server', 'Tamper-evident log', 'Revoke instantly'].map((t) => el('li', {}, icon('check', 16), el('span', { text: t }))))));
  hero.addEventListener('mousemove', (e) => {
    const r = hero.getBoundingClientRect();
    const x = (e.clientX - r.left) / r.width - 0.5;
    const y = (e.clientY - r.top) / r.height - 0.5;
    art.style.transform = 'translate(' + (x * 18).toFixed(1) + 'px,' + (y * 12).toFixed(1) + 'px)';
  });
  hero.addEventListener('mouseleave', () => { art.style.transform = ''; });
  return hero;
}

function loginView() {
  // ----- front of the card: log in -----
  const email = el('input', { type: 'email', required: true, autocomplete: 'username', placeholder: 'you@company.com' });
  const pw = passwordField('current-password');
  const loginBtn = el('button', { type: 'submit' }, el('span', { text: 'Log in' }));
  const forgot = el('button', { type: 'button', class: 'link', text: 'Forgot password?', onclick: () => { authScreen = 'forgot'; render(); } });
  const demoNote = el('p', { class: 'muted demo-note', text: 'Pick a role and its demo login is filled in for you.' });
  const chips = DEMOS.map((d) => {
    const chip = el('button', { type: 'button', class: 'demo-chip ' + d.role, title: d.text, 'aria-pressed': 'false' }, icon(d.icon, 20), el('span', { text: d.label }));
    chip.addEventListener('click', () => {
      email.value = d.email;
      pw.input.value = d.password;
      chips.forEach((c) => { c.classList.remove('active'); c.setAttribute('aria-pressed', 'false'); });
      chip.classList.add('active');
      chip.setAttribute('aria-pressed', 'true');
      demoNote.textContent = d.text;
      loginBtn.focus();
    });
    return chip;
  });

  const front = el('form', { class: 'card face front' },
    el('div', { class: 'face-head' },
      el('h2', { text: 'Welcome back' }),
      el('p', { class: 'muted', text: 'Log in to open your documents.' })),
    el('label', {}, 'Email', email),
    pw.node,
    el('div', { class: 'forgot' }, forgot),
    loginBtn,
    el('div', { class: 'divider' }, el('span', { text: 'or try a demo role' })),
    el('div', { class: 'demo-row' }, chips),
    demoNote,
    el('button', { type: 'button', class: 'link', text: 'New here? Create an account', onclick: () => flip(true) }));

  // ----- back of the card: create an account -----
  const rName = el('input', { type: 'text', required: true, maxlength: '100', autocomplete: 'name', placeholder: 'Your full name' });
  const rEmail = el('input', { type: 'email', required: true, autocomplete: 'username', placeholder: 'you@company.com' });
  const rPw = passwordField('new-password');
  const rPolicy = policyBlock();
  const rBtn = el('button', { type: 'submit', disabled: true }, el('span', { text: 'Create account' }));
  rPw.input.addEventListener('input', () => { rBtn.disabled = !rPolicy.update(rPw.input.value); });

  const back = el('form', { class: 'card face back' },
    el('div', { class: 'face-head' },
      el('h2', { text: 'Create your account' }),
      el('p', { class: 'muted', text: 'An administrator approves new accounts before documents can be shared with you.' })),
    el('label', {}, 'Full name', rName),
    el('label', {}, 'Email', rEmail),
    rPw.node,
    rPolicy.node,
    rBtn,
    el('button', { type: 'button', class: 'link', text: 'Already have an account? Log in', onclick: () => flip(false) }));

  const card = el('div', { class: 'flip pop' }, el('div', { class: 'flip-inner' }, front, back));
  back.inert = true;
  function flip(toRegister) {
    card.classList.toggle('flipped', toRegister);
    front.inert = toRegister;
    back.inert = !toRegister;
    setTimeout(() => (toRegister ? rName : email).focus(), 450);
  }

  front.addEventListener('submit', async (e) => {
    e.preventDefault();
    await withBusy(loginBtn, async () => {
      try {
        const { data } = await api('/api/auth/login', { method: 'POST', json: { email: email.value, password: pw.input.value } });
        state.user = data;
        state.tab = data.role === 'admin' ? 'admin' : 'documents';
        render();
      } catch (err) {
        toast(err.message, true);
        shake(card);
      }
    });
  });

  back.addEventListener('submit', async (e) => {
    e.preventDefault();
    await withBusy(rBtn, async () => {
      try {
        const { data } = await api('/api/auth/register', {
          method: 'POST', json: { email: rEmail.value, name: rName.value, password: rPw.input.value },
        });
        toast(data.message);
        email.value = rEmail.value;
        rPw.input.value = '';
        rPolicy.update('');
        flip(false);
      } catch (err) {
        toast(err.message, true);
        shake(card);
      }
    });
    rBtn.disabled = !rPolicy.update(rPw.input.value);
  });

  return el('div', { class: 'auth-wrap' }, heroPanel(), el('section', { class: 'panel' }, card));
}

// ---------- documents ----------
async function download(id, filename) {
  try {
    const { data } = await api('/api/documents/' + id + '/download', { blob: true });
    const url = URL.createObjectURL(data);
    const a = el('a', { href: url, download: filename });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  } catch (err) {
    toast(err.message, true);
  }
}

function fileBadge(mime) {
  const map = {
    'application/pdf': 'PDF',
    'image/png': 'PNG',
    'image/jpeg': 'JPG',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'DOC',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'XLS',
  };
  return el('span', { class: 'ftype', text: map[mime] || 'FILE' });
}

const fact = (k, v) => el('div', {}, el('dt', { text: k }), el('dd', { text: String(v) }));

async function sharingPanel(docId) {
  let directory = [];
  let access = new Map(); // user id -> the level they hold now
  let shownIds = [];
  const selected = new Set();

  const search = el('input', { type: 'search', placeholder: 'Search people by name or email' });
  const people = el('div', { class: 'people' });
  const listBox = el('div');
  const level = el('select', {}, el('option', { value: 'read', text: 'Can read' }), el('option', { value: 'edit', text: 'Can edit' }));
  const expires = el('input', { type: 'datetime-local', 'aria-label': 'Optional expiry' });
  const grantBtn = el('button', { type: 'button', text: 'Share with selected', disabled: true });

  function updateCount() {
    grantBtn.textContent = selected.size ? 'Share with ' + selected.size + ' selected' : 'Share with selected';
    grantBtn.disabled = selected.size === 0;
  }

  function drawPeople() {
    const term = search.value.trim().toLowerCase();
    const shown = directory.filter((p) => !term || p.name.toLowerCase().includes(term) || p.email.toLowerCase().includes(term));
    shownIds = shown.map((p) => p.id);
    setKids(people, shown.length === 0
      ? el('p', { class: 'muted', text: directory.length === 0 ? 'No approved people to share with yet. An administrator has to approve new accounts first.' : 'Nobody matches that search.' })
      : shown.map((p) => {
          const box = el('input', { type: 'checkbox', checked: selected.has(p.id) });
          box.addEventListener('change', () => {
            if (box.checked) selected.add(p.id); else selected.delete(p.id);
            updateCount();
          });
          const has = access.get(p.id);
          return el('label', { class: 'person' }, box,
            el('span', { class: 'grow' }, el('strong', { text: p.name }), el('span', { class: 'muted', text: p.email })),
            has && el('span', { class: 'badge ' + has, text: 'has ' + has }));
        }));
  }

  async function refresh() {
    try {
      const { data } = await api('/api/documents/' + docId + '/grants');
      access = new Map(data.map((g) => [g.user_id, g.level]));
      setKids(listBox, data.length === 0
        ? el('p', { class: 'muted', text: 'Nobody else has access.' })
        : table(['Person', 'Level', 'Expires', ''], data.map((g) => [
            g.name + ' (' + g.email + ')',
            el('span', { class: 'badge ' + g.level, text: g.level }),
            g.expires_at ? fmtDate(g.expires_at) : 'never',
            el('button', {
              type: 'button', class: 'danger small', text: 'Revoke',
              onclick: async () => {
                try {
                  await api('/api/documents/' + docId + '/grants/' + g.id, { method: 'DELETE' });
                  toast('Access revoked');
                  refresh();
                } catch (err) { toast(err.message, true); }
              },
            }),
          ])));
      drawPeople();
    } catch (err) { toast(err.message, true); }
  }

  search.addEventListener('input', drawPeople);

  grantBtn.addEventListener('click', async () => {
    const chosen = directory.filter((p) => selected.has(p.id));
    if (chosen.length === 0) return;
    const body = { level: level.value };
    if (expires.value) body.expires_at = new Date(expires.value).toISOString();
    await withBusy(grantBtn, async () => {
      let done = 0;
      const failed = [];
      for (const p of chosen) {
        try {
          await api('/api/documents/' + docId + '/grants', { method: 'POST', json: { ...body, email: p.email } });
          done++;
        } catch (err) { failed.push(p.name + ': ' + err.message); }
      }
      toast(done + ' shared' + (failed.length ? ', ' + failed.length + ' failed (' + failed[0] + ')' : ''), failed.length > 0);
      selected.clear();
      await refresh();
    });
    updateCount();
  });

  try {
    const { data } = await api('/api/directory');
    directory = data;
  } catch (err) { toast(err.message, true); }
  await refresh();
  updateCount();

  return el('div', { class: 'card pop' },
    el('h3', { class: 'section-title' }, icon('users', 20), 'Share this document'),
    search,
    el('div', { class: 'actions' },
      el('button', { type: 'button', class: 'link', text: 'Select all shown', onclick: () => { shownIds.forEach((id) => selected.add(id)); drawPeople(); updateCount(); } }),
      el('button', { type: 'button', class: 'link', text: 'Clear', onclick: () => { selected.clear(); drawPeople(); updateCount(); } })),
    people,
    el('div', { class: 'filters' }, level, expires, grantBtn),
    el('h3', { text: 'Who has access' }),
    listBox);
}

async function documentsView() {
  if (state.user.role === 'pending') {
    return el('div', { class: 'stack view' },
      welcome([]),
      el('div', { class: 'empty' }, icon('shield', 36),
        el('h2', { text: 'Waiting for approval' }),
        el('p', { text: 'Your account was created. An administrator has to give it a role before documents can be shared with you.' })));
  }

  const isOwner = state.user.role === 'owner';
  const tiles = isOwner
    ? [tile('Documents you can open', 'file'), tile('Owned by you', 'upload'), tile('Shared with you', 'users')]
    : [tile('Shared with you', 'users'), tile('You can edit', 'key'), tile('Read only', 'eye')];

  const emptyDetail = () => el('div', { class: 'empty' }, icon('file', 36), el('p', { text: 'Select a document to see its details.' }));
  const detail = el('div', { class: 'stack sticky' }, emptyDetail());
  const list = el('div', { class: 'list' });
  const count = el('span', { class: 'pill', text: '...' });

  const q = el('input', { type: 'search', placeholder: 'Title or file name' });
  const owner = el('input', { type: 'search', placeholder: 'Owner name' });
  const category = el('input', { type: 'search', placeholder: 'Category' });
  const from = el('input', { type: 'date', 'aria-label': 'From date' });
  const to = el('input', { type: 'date', 'aria-label': 'To date' });
  const searchBtn = el('button', { type: 'submit', text: 'Search' });
  const filters = el('form', { class: 'card filters' }, q, owner, category, from, to, searchBtn,
    el('button', {
      type: 'button', class: 'link', text: 'Clear',
      onclick: () => { for (const i of [q, owner, category, from, to]) i.value = ''; load(); },
    }));
  filters.addEventListener('submit', (e) => { e.preventDefault(); load(); });

  async function load() {
    setKids(list, el('div', { class: 'skeleton' }), el('div', { class: 'skeleton' }), el('div', { class: 'skeleton' }));
    const params = new URLSearchParams();
    for (const [k, i] of Object.entries({ q, owner, category, from, to })) {
      if (i.value.trim()) params.set(k, i.value.trim());
    }
    try {
      const { data, res } = await api('/api/documents?' + params);
      const total = Number(res.headers.get('X-Total-Count') || 0);
      count.textContent = String(total);
      if (params.toString() === '') {
        const owned = data.filter((d) => d.access === 'owner').length;
        if (isOwner) {
          tiles[0].set(total);
          tiles[1].set(owned);
          tiles[2].set(data.length - owned);
        } else {
          tiles[0].set(total);
          tiles[1].set(data.filter((d) => d.access === 'edit').length);
          tiles[2].set(data.filter((d) => d.access === 'read').length);
        }
      }
      if (data.length === 0) {
        setKids(list, el('div', { class: 'empty' }, icon('file', 36),
          el('p', { text: isOwner ? 'No documents found. Upload one above.' : 'Nothing has been shared with you yet.' })));
        return;
      }
      setKids(list, data.map((d, i) => {
        const row = el('button', {
          type: 'button', class: 'row', 'data-access': d.access,
          onclick: () => {
            list.querySelectorAll('.row.active').forEach((r) => r.classList.remove('active'));
            row.classList.add('active');
            openDoc(d.id);
          },
        },
        fileBadge(d.mime_type),
        el('span', { class: 'grow' },
          el('strong', { text: d.title }),
          el('span', { class: 'muted', text: d.category + ' · ' + d.owner_name + ' · ' + fmtDate(d.created_at) })),
        el('span', { class: 'badge ' + d.access, text: d.access }));
        row.style.setProperty('--i', i);
        return row;
      }));
    } catch (err) {
      setKids(list);
      toast(err.message, true);
    }
  }

  async function openDoc(id) {
    try {
      const { data: d } = await api('/api/documents/' + id);
      const mine = d.owner_id === state.user.id;
      const canEdit = mine || d.access === 'grant:edit';
      const downloadBtn = el('button', { type: 'button', text: 'Download' });
      downloadBtn.addEventListener('click', () => withBusy(downloadBtn, () => download(d.id, d.original_filename)));
      setKids(detail,
        el('div', { class: 'card pop' },
          el('h2', {}, d.title, ' ', el('span', { class: 'badge', text: 'v' + d.version })),
          el('dl', { class: 'facts' },
            fact('File', d.original_filename), fact('Type', d.mime_type), fact('Size', fmtSize(d.size_bytes)),
            fact('Category', d.category), fact('Your access', d.access), fact('Added', fmtDate(d.created_at)),
            fact('Last changed', fmtDate(d.updated_at))),
          el('div', { class: 'actions' },
            downloadBtn,
            mine && el('button', {
              type: 'button', class: 'danger', text: 'Delete',
              onclick: async () => {
                if (!confirm('Delete this document?')) return;
                try {
                  await api('/api/documents/' + d.id, { method: 'DELETE' });
                  toast('Deleted');
                  setKids(detail, emptyDetail());
                  load();
                } catch (err) { toast(err.message, true); }
              },
            }))),
        canEdit && editPanel(d, async () => { await openDoc(d.id); await load(); }),
        mine && (await sharingPanel(d.id)),
        mine && (await historyPanel(d)));
    } catch (err) {
      toast(err.message, true);
      load();
    }
  }

  function uploadForm() {
    const defaultText = 'Drop a file here or click to choose (PDF, PNG, JPG, DOCX or XLSX, up to 10 MB)';
    const title = el('input', { type: 'text', required: true, maxlength: '200', placeholder: 'Title' });
    const cat = el('input', { type: 'text', maxlength: '50', placeholder: 'Category (e.g. hr)' });
    const file = el('input', { type: 'file', required: true });
    const fileText = el('span', { text: defaultText });
    const drop = el('label', { class: 'drop' }, icon('upload', 22), fileText, file);
    const uploadBtn = el('button', { type: 'submit', text: 'Upload' });
    const form = el('form', { class: 'card filters' }, title, cat, drop, uploadBtn);

    file.addEventListener('change', () => { fileText.textContent = file.files[0] ? file.files[0].name : defaultText; });
    ['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); }));
    ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
    drop.addEventListener('drop', (e) => {
      if (e.dataTransfer.files.length) {
        file.files = e.dataTransfer.files;
        file.dispatchEvent(new Event('change'));
      }
    });

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (file.files[0].size > 10 * 1024 * 1024) return toast('That file is over 10 MB', true);
      const fd = new FormData();
      fd.append('title', title.value);
      fd.append('category', cat.value.trim() || 'general');
      fd.append('file', file.files[0]);
      await withBusy(uploadBtn, async () => {
        try {
          await api('/api/documents', { method: 'POST', form: fd });
          toast('Uploaded');
          form.reset();
          fileText.textContent = defaultText;
          await load();
        } catch (err) { toast(err.message, true); }
      });
    });
    return form;
  }

  await load();
  return el('div', { class: 'stack view' },
    welcome(tiles),
    isOwner && uploadForm(),
    filters,
    el('div', { class: 'grid' },
      el('div', {}, el('div', { class: 'list-head' }, el('h3', { text: 'Documents' }), count), list),
      detail));
}

// ---------- admin ----------
ICONS.download = [
  ['path', { d: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4' }],
  ['polyline', { points: '7 10 12 15 17 10' }],
  ['line', { x1: 12, y1: 15, x2: 12, y2: 3 }],
];

async function saveCsv(path, filename) {
  const { data } = await api(path, { blob: true });
  const url = URL.createObjectURL(data);
  const a = el('a', { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

async function adminView() {
  const tiles = [
    tile('Events, 24 hours', 'activity'),
    tile('Refused, 24 hours', 'lock'),
    tile('Waiting approval', 'users'),
    tile('Audit chain', 'shield'),
  ];
  const summary = el('div', { class: 'card' });
  const auditBox = el('div', { class: 'card' });
  const usersBox = el('div', { class: 'card' });
  const panels = { overview: summary, activity: auditBox, users: usersBox };
  let allUsers = [];

  // ----- sub tabs and the export button -----
  const usersCount = el('span', { class: 'pill warn hidden', text: '0' });
  const tabs = {
    overview: el('button', { type: 'button', class: 'subtab' }, icon('shield', 16), el('span', { text: 'Overview' })),
    activity: el('button', { type: 'button', class: 'subtab' }, icon('activity', 16), el('span', { text: 'Activity' })),
    users: el('button', { type: 'button', class: 'subtab' }, icon('users', 16), el('span', { text: 'Users' }), usersCount),
  };
  const exportLabel = el('span', { text: 'Export' });
  const exportBtn = el('button', { type: 'button', class: 'ghost' }, icon('download', 16), exportLabel);

  function showTab(id) {
    state.adminTab = id;
    for (const [k, node] of Object.entries(panels)) node.classList.toggle('hidden', k !== id);
    for (const [k, b] of Object.entries(tabs)) b.classList.toggle('active', k === id);
    exportBtn.classList.toggle('hidden', id === 'overview');
    exportLabel.textContent = id === 'users' ? 'Export users' : 'Export activity';
  }
  for (const [id, b] of Object.entries(tabs)) b.addEventListener('click', () => showTab(id));

  // ----- overview -----
  async function loadSummary() {
    try {
      const { data } = await api('/api/admin/summary');
      const r = data.notable;
      const total = data.last24h.reduce((s, x) => s + x.n, 0);
      const denied = data.last24h.filter((x) => x.outcome === 'denied').reduce((s, x) => s + x.n, 0);
      tiles[0].set(total);
      tiles[1].set(denied, denied ? 'warn' : '');
      tiles[3].set(data.chain.ok ? 'Intact' : 'BROKEN', data.chain.ok ? 'ok' : 'bad');

      const verifyBtn = el('button', { type: 'button', class: 'ghost small', text: 'Verify now' });
      verifyBtn.addEventListener('click', () => withBusy(verifyBtn, async () => {
        try {
          const { data: v } = await api('/api/admin/audit/verify');
          toast(v.ok ? 'Chain intact (' + v.checked + ' entries)' : 'CHAIN BROKEN at entry ' + v.brokenAt, !v.ok);
          loadSummary();
        } catch (err) { toast(err.message, true); }
      }));

      const nothing = r.repeated_refused_access.length + r.repeated_failed_logins.length === 0;
      setKids(summary,
        el('h2', { class: 'section-title' }, icon('shield', 20), 'Worth noticing (last 24 hours)'),
        el('p', {},
          'Audit chain: ',
          el('span', { class: data.chain.ok ? 'ok-text' : 'bad-text', text: data.chain.ok ? 'intact, ' + data.chain.checked + ' entries checked' : 'BROKEN at entry ' + data.chain.brokenAt }),
          ' ', verifyBtn),
        nothing && el('p', { class: 'muted', text: 'Nothing unusual: no account has 5 or more refused accesses or failed logins.' }),
        r.repeated_refused_access.length > 0 && table(['Repeated refused document access', 'Count', 'Last'],
          r.repeated_refused_access.map((x) => [x.actor_email || '(unknown)', String(x.refused), fmtDate(x.last_at)])),
        r.repeated_failed_logins.length > 0 && table(['Repeated failed logins', 'Count', 'Last'],
          r.repeated_failed_logins.map((x) => [x.actor_email || '(unknown)', String(x.failures), fmtDate(x.last_at)])));
    } catch (err) { toast(err.message, true); }
  }

  // ----- activity -----
  const group = el('select', {}, ['', 'documents', 'permissions', 'auth', 'admin'].map((g) => el('option', { value: g, text: g || 'All activity' })));
  const outcome = el('select', {}, ['', 'allowed', 'denied'].map((o) => el('option', { value: o, text: o || 'Any outcome' })));
  const actor = el('input', { type: 'search', placeholder: 'Actor email contains' });
  const auditList = el('div');

  function auditParams() {
    const p = new URLSearchParams();
    if (group.value) p.set('group', group.value);
    if (outcome.value) p.set('outcome', outcome.value);
    if (actor.value.trim()) p.set('actor', actor.value.trim());
    return p;
  }

  async function loadAudit() {
    const params = auditParams();
    params.set('limit', '50');
    try {
      const { data, res } = await api('/api/admin/audit?' + params);
      setKids(auditList,
        el('p', { class: 'muted', text: 'Showing ' + data.length + ' of ' + (res.headers.get('X-Total-Count') || 0) }),
        table(['#', 'Time', 'Actor', 'Action', 'Outcome', 'Details'], data.map((r) => [
          String(r.seq), fmtDate(r.at), r.actor_email || '', r.action,
          el('span', { class: r.outcome === 'denied' ? 'bad-text' : 'ok-text', text: r.outcome }),
          JSON.stringify(r.details).slice(0, 120),
        ])));
    } catch (err) { toast(err.message, true); }
  }
  const auditForm = el('form', { class: 'filters' }, group, outcome, actor, el('button', { type: 'submit', text: 'Filter' }));
  auditForm.addEventListener('submit', (e) => { e.preventDefault(); loadAudit(); });
  setKids(auditBox, el('h2', { class: 'section-title' }, icon('activity', 20), 'Activity and permission changes'), auditForm, auditList);

  // ----- users -----
  const userSearch = el('input', { type: 'search', placeholder: 'Search name or email' });
  const roleFilter = el('select', {}, ['', 'pending', 'viewer', 'owner', 'admin'].map((r) => el('option', { value: r, text: r || 'All roles' })));
  const waitingNote = el('div');
  const usersTable = el('div');

  function drawUsers() {
    const term = userSearch.value.trim().toLowerCase();
    const shown = allUsers.filter((u) =>
      (!term || u.name.toLowerCase().includes(term) || u.email.toLowerCase().includes(term)) &&
      (!roleFilter.value || u.role === roleFilter.value));
    setKids(usersTable, shown.length === 0
      ? el('p', { class: 'muted', text: 'No users match.' })
      : table(['Name', 'Email', 'Role', 'Account'], shown.map((u) => {
          const self = u.id === state.user.id;
          const role = el('select', { disabled: self },
            ['pending', 'viewer', 'owner', 'admin'].map((r) => el('option', { value: r, text: r, selected: r === u.role })));
          role.addEventListener('change', () => patchUser(u.id, { role: role.value }));
          const approve = u.role === 'pending' && u.is_active
            ? el('button', { type: 'button', class: 'small', text: 'Approve as viewer', onclick: () => patchUser(u.id, { role: 'viewer' }) })
            : null;
          const lock = el('button', {
            type: 'button', disabled: self, class: (u.is_active ? 'danger' : 'ghost') + ' small',
            text: u.is_active ? 'Lock' : 'Unlock',
            onclick: () => patchUser(u.id, { is_active: !u.is_active }),
          });
          return [
            u.name,
            u.email,
            el('span', { class: 'rolecell' }, role, approve),
            el('span', {}, u.is_active ? 'active ' : 'LOCKED ', lock),
          ];
        })));
  }
  userSearch.addEventListener('input', drawUsers);
  roleFilter.addEventListener('change', drawUsers);
  setKids(usersBox,
    el('h2', { class: 'section-title' }, icon('users', 20), 'Users'),
    waitingNote,
    el('div', { class: 'filters' }, userSearch, roleFilter),
    usersTable);

  async function loadUsers() {
    try {
      const { data } = await api('/api/admin/users');
      allUsers = data;
      const waiting = data.filter((u) => u.role === 'pending' && u.is_active).length;
      tiles[2].set(waiting, waiting ? 'warn' : '');
      usersCount.textContent = String(waiting);
      usersCount.classList.toggle('hidden', waiting === 0);
      setKids(waitingNote, waiting > 0
        ? el('p', { class: 'note', text: waiting + (waiting === 1 ? ' account is' : ' accounts are') + ' waiting for approval. Give each one a role below.' })
        : el('p', { class: 'muted', text: 'No accounts are waiting for approval.' }));
      drawUsers();
    } catch (err) { toast(err.message, true); }
  }

  async function patchUser(id, body) {
    try {
      await api('/api/admin/users/' + id, { method: 'PATCH', json: body });
      toast('User updated');
    } catch (err) { toast(err.message, true); }
    loadUsers();
    loadAudit();
    loadSummary();
  }

  // ----- export: the current tab's data as a CSV file -----
  exportBtn.addEventListener('click', () => withBusy(exportBtn, async () => {
    try {
      if (state.adminTab === 'users') await saveCsv('/api/admin/users/export', 'trustvault-users.csv');
      else await saveCsv('/api/admin/audit/export?' + auditParams(), 'trustvault-activity.csv');
      toast('Export downloaded');
      loadAudit(); // the export itself now appears in the log
    } catch (err) { toast(err.message, true); }
  }));

  await Promise.all([loadSummary(), loadAudit(), loadUsers()]);
  showTab(state.adminTab || 'overview');
  return el('div', { class: 'stack view' },
    welcome(tiles),
    el('div', { class: 'subnav-row' }, el('div', { class: 'subnav' }, Object.values(tabs)), exportBtn),
    summary, auditBox, usersBox);
}

// ---------- shell ----------
async function logout() {
  try { await api('/api/auth/logout', { method: 'POST' }); } catch (err) { /* already logged out */ }
  state.user = null;
  render();
}

async function render() {
  document.body.classList.toggle('is-auth', !state.user);
  document.body.dataset.role = state.user ? state.user.role : '';
  $nav.replaceChildren();
  if (!state.user) {
    $app.replaceChildren(authScreen === 'forgot' ? forgotView() : loginView());
    return;
  }
  authScreen = 'login';
  const tabs = state.user.role === 'admin' ? [['admin', 'Admin', 'activity']] : [['documents', 'Documents', 'file']];
  tabs.push(['account', 'Account', 'key']);
  for (const [id, label, ico] of tabs) {
    $nav.append(el('button', {
      class: state.tab === id ? 'tab active' : 'tab',
      onclick: () => { state.tab = id; render(); },
    }, icon(ico, 16), el('span', { text: label })));
  }
  $nav.append(
    el('span', { class: 'who' },
      el('span', { class: 'avatar', text: (state.user.name || '?').charAt(0).toUpperCase() }),
      el('span', { text: state.user.name }),
      el('span', { class: 'badge ' + state.user.role, text: state.user.role })),
    el('button', { class: 'tab', text: 'Log out', onclick: logout }));

  let view;
  let banner = null;
  if (state.tab === 'account') {
    view = await accountView();
  } else {
    view = state.user.role === 'admin' ? await adminView() : await documentsView();
    banner = await recoveryBanner();
  }
  setKids($app, banner, view);
}

(async function start() {
  $brand.prepend(icon('shield', 22));
  try {
    const { data } = await api('/api/auth/me');
    state.user = data;
    state.tab = data.role === 'admin' ? 'admin' : 'documents';
  } catch (err) { /* not logged in */ }
  render();
})();