/* Light/dark theme for the Black MIDI site.
 *
 * The theme is one attribute - <html data-theme="light|dark"> - set before the
 * first paint by the inline script in src/templates/base.html, and every colour
 * difference lives in the dark block at the foot of public/static/style.css.
 * This file only decides *which* theme is on, remembers the choice, and keeps
 * the controls that show it in step with each other.
 *
 * The choice is per browser (localStorage) rather than per account, so it also
 * works for visitors who are not signed in, and it survives a reload without the
 * server knowing anything about it. Until somebody picks a theme explicitly the
 * site follows the operating system's own light/dark preference, and keeps
 * following it if that changes while the page is open.
 */
(function () {
  'use strict';

  var KEY = 'smm-theme';
  var root = document.documentElement;
  var media = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

  function stored() {
    try {
      return localStorage.getItem(KEY);
    } catch (e) {
      return null;  // private mode / storage disabled: the choice lasts the page
    }
  }

  function current() {
    return root.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
  }

  function sync(theme) {
    root.setAttribute('data-theme', theme);
    each('[data-theme-choice]', function (button) {
      var on = button.getAttribute('data-theme-choice') === theme;
      button.setAttribute('aria-pressed', on ? 'true' : 'false');
      button.classList.toggle('active', on);
    });
    each('[data-theme-current]', function (node) {
      node.textContent = theme;
    });
    each('[data-theme-toggle]', function (button) {
      var label = theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
      button.setAttribute('title', label);
      button.setAttribute('aria-label', label);
    });
  }

  function each(selector, fn) {
    var nodes = document.querySelectorAll(selector);
    for (var i = 0; i < nodes.length; i++) {
      fn(nodes[i]);
    }
  }

  function apply(theme, remember) {
    if (remember) {
      try {
        localStorage.setItem(KEY, theme);
      } catch (e) {
        // Nothing to do: the theme still applies to this page.
      }
    }
    sync(theme);
  }

  // One delegated listener rather than a handler per control, so the buttons on
  // the settings page and the one in the top bar need no setup of their own.
  document.addEventListener('click', function (event) {
    var node = event.target;
    if (!node || !node.closest) {
      return;
    }
    var control = node.closest('[data-theme-choice],[data-theme-toggle]');
    if (!control) {
      return;
    }
    var choice = control.getAttribute('data-theme-choice');
    apply(choice || (current() === 'dark' ? 'light' : 'dark'), true);
  });

  sync(current());

  if (media && !stored()) {
    var followSystem = function () {
      if (!stored()) {
        sync(media.matches ? 'dark' : 'light');
      }
    };
    if (media.addEventListener) {
      media.addEventListener('change', followSystem);
    } else if (media.addListener) {
      media.addListener(followSystem);  // Safari < 14
    }
  }
})();
