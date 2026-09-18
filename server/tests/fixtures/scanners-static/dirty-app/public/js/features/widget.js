// Fixture: browser-side DOM rules (CONTRACTS §3).
export function renderNote(note) {
  const el = document.getElementById('note');
  el.innerHTML = note.html;
}

export function legacyWrite(html) {
  document.write(html);
}

export function goTo(target) {
  window.location.href = target;
}

function handleMessage(data) {
  return data;
}

window.addEventListener('message', (event) => {
  handleMessage(event.data);
});
