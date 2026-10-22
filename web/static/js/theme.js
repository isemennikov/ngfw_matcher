/* ngfw-matcher — theme switching (light / dark / system) */
(function () {
  var KEY = 'theme';
  var MODES = ['light', 'dark', 'system'];

  function readCookie() {
    var m = document.cookie.match(/(?:^|;\s*)theme=([^;]+)/);
    return m ? decodeURIComponent(m[1]) : 'system';
  }
  function writeCookie(mode) {
    document.cookie = KEY + '=' + mode + ';path=/;max-age=31536000;SameSite=Lax';
  }
  function systemMode() {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
      ? 'dark' : 'light';
  }
  function resolve(mode) {
    return mode === 'system' ? systemMode() : mode;
  }
  function apply(mode) {
    var resolved = resolve(mode);
    document.documentElement.setAttribute('data-theme', resolved);
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', resolved === 'dark' ? '#0B0D0F' : '#F4F5F7');
    document.querySelectorAll('[data-theme-icon]').forEach(function (el) {
      el.textContent = resolved === 'dark' ? '☀' : '☾';
    });
    document.querySelectorAll('[data-theme-label]').forEach(function (el) {
      el.textContent = mode === 'system' ? 'Системная'
                      : mode === 'dark' ? 'Тёмная' : 'Светлая';
    });
  }

  window.ngfwTheme = {
    current: readCookie,
    apply: function (mode) { apply(mode); },
    cycle: function () {
      var mode = readCookie();
      var next = MODES[(MODES.indexOf(mode) + 1) % MODES.length];
      writeCookie(next);
      apply(next);
    },
  };

  function init() {
    apply(readCookie());
    document.querySelectorAll('[data-theme-toggle]').forEach(function (btn) {
      btn.addEventListener('click', function () { window.ngfwTheme.cycle(); });
    });
    if (window.matchMedia) {
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () {
        if (readCookie() === 'system') apply('system');
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
