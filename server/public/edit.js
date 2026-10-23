'use strict';
// Loaded before app.js. Defines the edit and version-history panels.

function ensureIcons() {
  if (!ICONS.edit) ICONS.edit = [['path', { d: 'M12 20h9' }], ['path', { d: 'M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z' }]];
  if (!ICONS.clock) ICONS.clock = [['circle', { cx: 12, cy: 12, r: 10 }], ['polyline', { points: '12 6 12 12 16 14' }]];
}

function editPanel(d, onChanged) {
  ensureIcons();
  const title = el('input', { type: 'text', required: true, maxlength: '200', value: d.title, 'aria-label': 'Title' });
  const category = el('input', { type: 'text', required: true, maxlength: '50', value: d.category, 'aria-label': 'Category' });
  const saveBtn = el('button', { type: 'submit', text: 'Save details' });
  const form = el('form', { class: 'filters' }, title, category, saveBtn);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const body = {};
    if (title.value.trim() !== d.title) body.title = title.value;
    if (category.value.trim() !== d.category) body.category = category.value;
    if (Object.keys(body).length === 0) return toast('Nothing changed');
    await withBusy(saveBtn, async () => {
      try {
        await api('/api/documents/' + d.id, { method: 'PATCH', json: body });
        toast('Details saved');
        await onChanged();
      } catch (err) { toast(err.message, true); }
    });
  });

  const defaultText = 'Replace the file (the old one is kept as an earlier version)';
  const file = el('input', { type: 'file', required: true });
  const fileText = el('span', { text: defaultText });
  const drop = el('label', { class: 'drop' }, icon('upload', 22), fileText, file);
  const replaceBtn = el('button', { type: 'submit', text: 'Replace file' });
  const replaceForm = el('form', { class: 'filters' }, drop, replaceBtn);
  file.addEventListener('change', () => { fileText.textContent = file.files[0] ? file.files[0].name : defaultText; });
  replaceForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (file.files[0].size > 10 * 1024 * 1024) return toast('That file is over 10 MB', true);
    const fd = new FormData();
    fd.append('file', file.files[0]);
    await withBusy(replaceBtn, async () => {
      try {
        await api('/api/documents/' + d.id + '/replace', { method: 'POST', form: fd });
        toast('File replaced');
        await onChanged();
      } catch (err) { toast(err.message, true); }
    });
  });

  return el('div', { class: 'card pop' },
    el('h3', { class: 'section-title' }, icon('edit', 20), 'Edit this document'),
    form, replaceForm);
}

async function downloadVersion(d, v) {
  try {
    const { data } = await api('/api/documents/' + d.id + '/versions/' + v.version + '/download', { blob: true });
    const url = URL.createObjectURL(data);
    const a = el('a', { href: url, download: v.original_filename });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  } catch (err) { toast(err.message, true); }
}

async function historyPanel(d) {
  ensureIcons();
  const box = el('div');
  try {
    const { data } = await api('/api/documents/' + d.id + '/versions');
    setKids(box, data.length === 0
      ? el('p', { class: 'muted', text: 'No earlier versions yet. Replacing the file keeps the old one here.' })
      : table(['Version', 'File', 'Replaced', 'By', ''], data.map((v) => [
          'v' + v.version,
          v.original_filename + ' (' + fmtSize(v.size_bytes) + ')',
          fmtDate(v.replaced_at),
          v.replaced_by_name,
          el('button', { type: 'button', class: 'ghost small', text: 'Download', onclick: () => downloadVersion(d, v) }),
        ])));
  } catch (err) { toast(err.message, true); }
  return el('div', { class: 'card pop' },
    el('h3', { class: 'section-title' }, icon('clock', 20), 'Version history'),
    el('p', { class: 'muted', text: 'Current version: v' + d.version }),
    box);
}