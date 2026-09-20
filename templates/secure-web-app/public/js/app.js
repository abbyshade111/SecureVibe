/*
 * Progressive enhancement only. The app works fully without JavaScript; this file adds confirmation prompts on
 * destructive forms, "copy" buttons, and a working state on forms that take a while. It is loaded with the
 * per-request nonce; there are no inline scripts. Generated features may add their own files under
 * public/js/features/.
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

  /*
   * A form that takes a while says so (data-working="Asking the assistant…").
   *
   * An owner pressing a button that answers in thirty seconds cannot tell a slow answer from a broken button, and
   * the first thing anybody does about that is press it again — which, when the button costs money, pays twice for
   * one answer. So the button is disabled for the rest of the page's life and says what is happening, and the
   * sentence goes into a live region so it is announced rather than only shown.
   *
   * The form still submits normally: this changes what the page says, never what it does. Without JavaScript the
   * button stays enabled and the request is identical, which is why the page also carries the waiting time in
   * plain text — that sentence is the part that works for everybody.
   */
  document.addEventListener('submit', function (event) {
    var form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (event.defaultPrevented) return;
    var working = form.getAttribute('data-working');
    if (!working) return;
    var button = form.querySelector('button[type="submit"], button:not([type])');
    if (button) {
      button.disabled = true;
      button.textContent = working;
    }
    var status = form.querySelector('[data-working-status]');
    if (status) status.textContent = working;
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
