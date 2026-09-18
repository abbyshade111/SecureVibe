/*
 * Progressive enhancement only. The app works fully without JavaScript; this file adds confirmation prompts on
 * destructive forms and "copy" buttons. It is loaded with the per-request nonce; there are no inline scripts.
 * Generated features may add their own files under public/js/features/.
 */
(function () {
  'use strict';

  // Ask before destructive actions (forms marked with data-confirm).
  document.addEventListener('submit', function (event) {
    var form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    var message = form.getAttribute('data-confirm');
    if (message && !window.confirm(message)) event.preventDefault();
  });

  function copyText(text, trigger) {
    if (!navigator.clipboard) return;
    navigator.clipboard.writeText(text).then(function () {
      var original = trigger.textContent;
      trigger.textContent = 'Copied';
      window.setTimeout(function () {
        trigger.textContent = original;
      }, 1500);
    });
  }

  // Click-to-copy on secrets (setup keys, invitation links).
  document.querySelectorAll('[data-copy]').forEach(function (element) {
    element.setAttribute('title', 'Click to copy');
    element.style.cursor = 'pointer';
    element.addEventListener('click', function () {
      copyText(element.textContent.trim(), element);
    });
  });

  // "Copy all codes" for recovery codes.
  document.querySelectorAll('[data-copy-all]').forEach(function (button) {
    button.addEventListener('click', function () {
      var codes = Array.prototype.map.call(document.querySelectorAll('[data-copy-list] code'), function (code) {
        return code.textContent.trim();
      });
      copyText(codes.join('\n'), button);
    });
  });
})();
