'use strict';
// Loaded before app.js. It only defines things; app.js calls them.

let authScreen = 'login'; // 'login' or 'forgot'

function policyBlock() {
  const bar = el('span');
  const meter = el('div', { class: 'meter' }, bar);
  const items = RULES.map(([text]) => el('li', { text }));
  const node = el('div', { class: 'policy' }, meter, el('ul', { class: 'checks' }, items));
  function update(p) {
    let passed = 0;
    RULES.forEach(([, test], i) => {
      const ok = test(p);
      items[i].classList.toggle('ok', ok);
      if (ok) passed++;
    });
    bar.style.width = (passed / RULES.length) * 100 + '%';
    meter.dataset.level = passed <= 2 ? 'weak' : passed < RULES.length ? 'fair' : 'strong';
    return passed === RULES.length;
  }
  return { node, update };
}

function pwField(label, autocomplete) {
  const f = passwordField(autocomplete);
  f.node.firstChild.textContent = label;
  return f;
}

function forgotView() {
  const email = el('input', { type: 'email', required: true, autocomplete: 'username', placeholder: 'you@company.com' });
  const code = el('input', { type: 'text', required: true, autocomplete: 'off', spellcheck: 'false', maxlength: '20', placeholder: 'XXXX-XXXX-XXXX' });
  const pw = pwField('New password', 'new-password');
  const policy = policyBlock();
  const submit = el('button', { type: 'submit', disabled: true }, el('span', { text: 'Set new password' }));
  pw.input.addEventListener('input', () => { submit.disabled = !policy.update(pw.input.value); });

  const form = el('form', { class: 'card auth-card pop' },
    el('div', { class: 'face-head' },
      el('h2', { text: 'Reset your password' }),
      el('p', { class: 'muted', text: 'Enter your email and one of the recovery codes you saved in your Account page.' })),
    el('label', {}, 'Email', email),
    el('label', {}, 'Recovery code', code),
    pw.node, policy.node, submit,
    el('p', { class: 'note', text: 'No codes left? By design nobody, not even an administrator, can reset a password for you.' }),
    el('button', { type: 'button', class: 'link', text: 'Back to log in', onclick: () => { authScreen = 'login'; render(); } }));

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    await withBusy(submit, async () => {
      try {
        await api('/api/auth/reset-with-code', {
          method: 'POST', json: { email: email.value, code: code.value, new_password: pw.input.value },
        });
        toast('Password changed. Please log in.');
        authScreen = 'login';
        render();
      } catch (err) {
        toast(err.message, true);
        shake(form);
      }
    });
    submit.disabled = !policy.update(pw.input.value);
  });
  return el('div', { class: 'auth-wrap' }, heroPanel(), el('section', { class: 'panel' }, form));
}

function showCodes(codes) {
  const text = codes.join('\n');
  const copy = el('button', { type: 'button', text: 'Copy all' });
  copy.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(text); toast('Codes copied'); } catch (e) { toast('Select the codes and press Ctrl+C', true); }
  });
  const save = el('button', { type: 'button', class: 'ghost', text: 'Download .txt' });
  save.addEventListener('click', () => {
    const body = 'TrustVault recovery codes for ' + state.user.email + '\nEach code works once.\n\n' + text + '\n';
    const url = URL.createObjectURL(new Blob([body], { type: 'text/plain' }));
    const a = el('a', { href: url, download: 'trustvault-recovery-codes.txt' });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  });
  const overlay = el('div', { class: 'overlay', role: 'dialog', 'aria-modal': 'true' },
    el('div', { class: 'card pop modal' },
      el('h3', { text: 'Your recovery codes' }),
      el('p', { class: 'muted', text: 'Save these now. They are shown once, each works once, and they replace any older codes. Anyone holding a code and your email can reset your password.' }),
      el('ul', { class: 'codes' }, codes.map((c) => el('li', { text: c }))),
      el('div', { class: 'actions' }, copy, save,
        el('button', { type: 'button', class: 'ghost', text: 'I have saved them', onclick: () => overlay.remove() }))));
  document.body.append(overlay);
}

async function accountView() {
  // ----- change password -----
  const current = pwField('Current password', 'current-password');
  const next = pwField('New password', 'new-password');
  const policy = policyBlock();
  const changeBtn = el('button', { type: 'submit', disabled: true }, el('span', { text: 'Change password' }));
  next.input.addEventListener('input', () => { changeBtn.disabled = !policy.update(next.input.value); });
  const changeForm = el('form', { class: 'card form-card' },
    el('h3', { class: 'section-title' }, icon('lock', 20), 'Change password'),
    el('p', { class: 'muted', text: 'Your other logins will end.' }),
    current.node, next.node, policy.node, changeBtn);
  changeForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    await withBusy(changeBtn, async () => {
      try {
        await api('/api/auth/change-password', {
          method: 'POST', json: { current_password: current.input.value, new_password: next.input.value },
        });
        toast('Password changed');
        current.input.value = '';
        next.input.value = '';
      } catch (err) { toast(err.message, true); }
    });
    changeBtn.disabled = !policy.update(next.input.value);
  });

  // ----- recovery codes -----
  const status = el('p', { class: 'muted', text: '...' });
  async function loadStatus() {
    try {
      const { data } = await api('/api/auth/recovery-codes');
      status.textContent = data.remaining + ' unused recovery code' + (data.remaining === 1 ? '' : 's') + ' left.';
    } catch (err) { toast(err.message, true); }
  }
  const codesPw = pwField('Current password', 'current-password');
  const codesBtn = el('button', { type: 'submit' }, el('span', { text: 'Generate new codes' }));
  const codesForm = el('form', { class: 'card form-card' },
    el('h3', { class: 'section-title' }, icon('key', 20), 'Recovery codes'),
    el('p', { class: 'muted', text: 'Eight one-time codes that let you reset a forgotten password yourself. New codes replace the old ones.' }),
    status, codesPw.node, codesBtn);
  codesForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    await withBusy(codesBtn, async () => {
      try {
        const { data } = await api('/api/auth/recovery-codes', {
          method: 'POST', json: { current_password: codesPw.input.value },
        });
        codesPw.input.value = '';
        showCodes(data.codes);
        await loadStatus();
      } catch (err) { toast(err.message, true); }
    });
  });

  await loadStatus();
  const profile = el('section', { class: 'card profile' },
    el('span', { class: 'avatar big', text: (state.user.name || '?').charAt(0).toUpperCase() }),
    el('div', { class: 'profile-text' }, el('h2', { text: state.user.name }), el('p', { class: 'muted', text: state.user.email })),
    el('span', { class: 'badge ' + state.user.role, text: state.user.role }));
  return el('div', { class: 'stack view' }, profile, el('div', { class: 'grid2' }, codesForm, changeForm));
}

// A reminder shown until the person has saved some codes.
async function recoveryBanner() {
  try {
    const { data } = await api('/api/auth/recovery-codes');
    if (data.remaining > 0) return null;
    return el('div', { class: 'note banner' },
      el('span', { text: 'You have no recovery codes, so a forgotten password cannot be reset.' }),
      el('button', { type: 'button', class: 'link', text: 'Create them now', onclick: () => { state.tab = 'account'; render(); } }));
  } catch (err) { return null; }
}