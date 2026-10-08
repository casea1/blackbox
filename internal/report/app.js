// Blackbox report: page switching, Search and the event pages. The events
// are in data files next to report.html (data/<page>-<day>.js), loaded only
// when a page needs them. Each file calls BB.put with gzip-compressed JSON.
(function () {
  'use strict';
  var meta = JSON.parse(document.getElementById('bb-meta').textContent);
  var waiting = {}, store = {};

  // BB.put is called by each data file once it has loaded.
  window.BB = {
    put: function (key, b64) {
      store[key] = b64;
      if (waiting[key]) { waiting[key].forEach(function (f) { f(); }); delete waiting[key]; }
    }
  };

  function loadScript(key, file) {
    return new Promise(function (resolve, reject) {
      if (store[key] !== undefined) { resolve(); return; }
      (waiting[key] = waiting[key] || []).push(resolve);
      if (waiting[key].length > 1) return;
      var s = document.createElement('script');
      s.src = 'data/' + file;
      s.onerror = function () { reject(new Error('could not read data/' + file)); };
      document.head.appendChild(s);
    });
  }

  function unpack(key) {
    var bin = atob(store[key]), bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    var ds = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
    return new Response(ds).text().then(JSON.parse);
  }

  var checked = {};
  function getData(key, file) {
    return loadScript(key, file).then(function () {
      if (!checked[file] && meta.sums && meta.sums[file] && window.crypto && crypto.subtle) {
        checked[file] = true;
        crypto.subtle.digest('SHA-256', new TextEncoder().encode(store[key])).then(function (h) {
          var hex = Array.prototype.map.call(new Uint8Array(h), function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
          if (hex !== meta.sums[file]) tampered(file);
        }).catch(function () {});
      }
      return unpack(key);
    });
  }

  // ---- Formatting ----
  var MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  var DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  function pad(n) { return n < 10 ? '0' + n : '' + n; }
  // t is seconds (UTC); off the event's own UTC offset (DST1).
  function when(t, off) {
    var d = new Date((t + off) * 1000);
    return pad(d.getUTCDate()) + ' ' + MONTHS[d.getUTCMonth()] + ' ' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ':' + pad(d.getUTCSeconds());
  }
  // The zone shown with one event's time: the report's zone name when the
  // event has the offset that name stands for, else UTC±hh:mm (DST1).
  function zoneOf(off) {
    if (off === meta.zoneOff) return meta.zone;
    var a = Math.abs(off);
    return 'UTC' + (off < 0 ? '-' : '+') + pad(Math.floor(a / 3600)) + ':' + pad(Math.floor(a % 3600 / 60));
  }
  function dayLabel(day) {
    var d = new Date(Date.UTC(+day.slice(0, 4), +day.slice(4, 6) - 1, +day.slice(6, 8)));
    return DAYS[d.getUTCDay()] + ' ' + d.getUTCDate() + ' ' + MONTHS[d.getUTCMonth()];
  }
  // CSV: a field starting with = + - @ (or a tab or return) is a formula to
  // a spreadsheet, so a user name like =HYPERLINK(…) must stay text
  // (csvSafe, as exports.go does); toCSV quotes and joins the rows.
  function csvSafe(v) {
    var s = String(v == null ? '' : v);
    return /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
  }
  function toCSV(rows) {
    return rows.map(function (r) {
      return r.map(function (v) { var s = String(v == null ? '' : v); return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }).join(',');
    }).join('\r\n') + '\r\n';
  }
  function save(name, text) {
    var a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob(['\ufeff' + text], { type: 'text/csv' }));
    a.download = name; document.body.appendChild(a); a.click(); a.remove();
  }
  var stamp = (document.title.match(/\d{1,2} \w{3} \d{4}$/) || [''])[0].replace(/ /g, '-');
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; });
  }
  // Only High and Medium are flagged; other rows show a dash.
  var SEV = { high: 'High', medium: 'Medium' };
  function sevCell(s) { return SEV[s] ? '<span class="sv ' + s + '">' + SEV[s] + '</span>' : '<span class="mute">—</span>'; }

  // ---- People (UI-R1): the list's search box and All / Detections /
  // Admins; a person named in a link by any spelling ("SRV-DC02\jlee",
  // a people_aliases spelling) opens their row ----
  // "0-17" (a weekday-hour in a Search link) as "Mondays 17:00–18:00".
  function slotLabel(slot) {
    var p = slot.split('-'), h = +p[1];
    return ['Mondays', 'Tuesdays', 'Wednesdays', 'Thursdays', 'Fridays', 'Saturdays', 'Sundays'][+p[0]] + ' ' + pad(h) + ':00–' + pad((h + 1) % 24) + ':00';
  }
  BB.personKey = function (u) {
    u = (u || '').toLowerCase();
    var i = u.lastIndexOf('\\');
    if (i >= 0) u = u.slice(i + 1);
    i = u.indexOf('@');
    if (i > 0) u = u.slice(0, i);
    return (meta.palias && meta.palias[u]) || u;
  };
  document.querySelectorAll('[data-plist]').forEach(function (list) {
    var box = list.querySelector('[data-pfind]'), tab = '';
    function apply() {
      var q = box.value.trim().toLowerCase(), any = false;
      list.classList.toggle('pfx', !!(q || tab));
      list.querySelectorAll('[data-pick]').forEach(function (a) {
        var text = (a.textContent + ' ' + (a.getAttribute('data-alias') || '')).toLowerCase();
        a.hidden = !!(q && text.indexOf(q) < 0) || !!(tab && (' ' + a.getAttribute('data-pt') + ' ').indexOf(' ' + tab + ' ') < 0);
      });
      list.querySelectorAll('[data-pg]').forEach(function (g) {
        g.hidden = !g.querySelector('[data-pick]:not([hidden])');
        if (!g.hidden) any = true;
      });
      list.querySelector('[data-pnone]').hidden = any;
    }
    box.addEventListener('input', apply);
    list.querySelectorAll('[data-ptab]').forEach(function (b) {
      b.addEventListener('click', function () {
        tab = b.getAttribute('data-ptab');
        list.querySelectorAll('[data-ptab]').forEach(function (x) {
          x.classList.toggle('on', x === b);
          x.setAttribute('aria-pressed', x === b ? 'true' : 'false');
        });
        apply();
      });
    });
  });

  // ---- Sidebar (UI-R1): its groups are always open. On a narrow window
  // it is a bar with a Menu button that opens the pages and the report
  // card; choosing a page closes it again. ----
  var aside = document.querySelector('aside'), menuBtn = document.querySelector('[data-menu]');
  function menu(open) {
    if (!aside || !menuBtn) return;
    aside.classList.toggle('open', open);
    menuBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
  }
  if (menuBtn) menuBtn.addEventListener('click', function () { menu(!aside.classList.contains('open')); });
  if (aside) aside.addEventListener('click', function (e) { if (e.target.closest('nav a, .allrep')) menu(false); });

  // ---- Folded quiet items (UI-R1 foldrow): Show opens data-folded="ID" ----
  document.addEventListener('click', function (e) {
    var b = e.target.closest && e.target.closest('[data-foldbtn]');
    if (!b) return;
    e.preventDefault();
    var id = b.getAttribute('data-foldbtn'), box = document.querySelector('[data-folded="' + id.replace(/["\\]/g, '\\$&') + '"]');
    if (!box) return;
    if (!b.hasAttribute('data-show')) b.setAttribute('data-show', b.textContent);
    box.hidden = !box.hidden;
    b.textContent = b.getAttribute(box.hidden ? 'data-show' : 'data-hide') || b.textContent;
    b.setAttribute('aria-expanded', box.hidden ? 'false' : 'true');
  });

  // ---- Pages ----
  var views = document.querySelectorAll('.view');
  function show() {
    var id = (location.hash || '#overview').slice(1).split(/[/?]/)[0];
    // A page that became part of a kind (#failed?host=X): its kind's
    // page showing that part (#logons?part=failed&host=X).
    var moved = movedTo(id);
    if (moved) {
      var oh = location.hash, oq = oh.indexOf('?'), otext = oq < 0 ? oh.split('/').slice(1).join('/') : '';
      var nh = '#' + moved + '?part=' + id + (oq >= 0 && oh.length > oq + 1 ? '&' + oh.slice(oq + 1) : '') + (otext ? '&text=' + otext : '');
      if (history.replaceState) history.replaceState(null, '', nh); else location.hash = nh;
      id = moved;
    }
    if (!document.querySelector('.view[data-view="' + id + '"]')) id = 'overview';
    views.forEach(function (v) { v.hidden = v.getAttribute('data-view') !== id; });
    document.querySelectorAll('[data-nav]').forEach(function (a) {
      var on = a.getAttribute('data-nav') === id;
      a.classList.toggle('on', on);
      if (on) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
    });
    var view = document.querySelector('.view[data-view="' + id + '"]');
    var fd = finders[id];
    if (fd) {
      var h = location.hash, qi = h.indexOf('?');
      if (qi >= 0) fd.query(h.slice(qi + 1));
      else fd.open(decodeURIComponent(h.split('/').slice(1).join('/')));
    }
    var to = null;
    if (id === 'systems') showSystem(view, decodeURIComponent(location.hash.split('/').slice(1).join('/')));
    else if (id === 'health' || id === 'logs') to = showHealth(view, decodeURIComponent(location.hash.split('/').slice(1).join('/')));
    else if (view.querySelector('[data-pick]')) {
      var pk = decodeURIComponent(location.hash.split('/').slice(1).join('/'));
      if (id === 'people' && pk) pk = BB.personKey(pk);
      showPick(view, pk);
    }
    if (id === 'inventory') inv.load();
    if (to) to.scrollIntoView();
    else window.scrollTo(0, 0);
    scrollCues();
  }

  // ---- Systems (UI-R1): the list, or one system (#systems/NAME) ----
  function showSystem(view, key) {
    var list = view.querySelector('[data-syslist]'), found = null;
    if (!list) return;
    view.querySelectorAll('[data-sys]').forEach(function (d) {
      var on = !!key && d.getAttribute('data-sys').toLowerCase() === key.toLowerCase();
      d.hidden = !on;
      if (on) found = d;
    });
    list.hidden = !!found;
  }
  (function () {
    var bar = document.querySelector('[data-sysfilter]');
    if (!bar) return;
    var view = bar.closest('.view'), lv = '';
    var find = bar.querySelector('[data-sysfind]'), os = bar.querySelector('[data-sysos]'), kind = bar.querySelector('[data-syskind]');
    function apply() {
      var q = find.value.trim().toLowerCase(), shown = 0;
      view.querySelectorAll('[data-sysrow]').forEach(function (tr) {
        var ok = (!q || tr.getAttribute('data-sysrow').toLowerCase().indexOf(q) >= 0) && (!lv || tr.getAttribute('data-lv') === lv) &&
          (!os.value || tr.getAttribute('data-os') === os.value) && (!kind.value || tr.getAttribute('data-kind') === kind.value);
        tr.hidden = !ok; if (ok) shown++;
      });
      view.querySelectorAll('[data-sysgroup]').forEach(function (g) { g.hidden = !g.querySelector('[data-sysrow]:not([hidden])'); });
      view.querySelector('[data-sysnone]').hidden = shown > 0;
    }
    bar.addEventListener('click', function (e) {
      var b = e.target.closest('[data-syslv]');
      if (!b) return;
      lv = b.getAttribute('data-syslv');
      bar.querySelectorAll('[data-syslv]').forEach(function (x) { x.classList.toggle('on', x === b); x.setAttribute('aria-pressed', x === b ? 'true' : 'false'); });
      apply();
    });
    find.addEventListener('input', apply);
    os.addEventListener('change', apply);
    kind.addEventListener('change', apply);
    // A click anywhere on a row (not on one of its links) opens the system.
    view.querySelector('.syst').addEventListener('click', function (e) {
      var tr = e.target.closest('[data-sysrow]');
      if (tr && !e.target.closest('a')) location.hash = '#systems/' + encodeURIComponent(tr.getAttribute('data-sysrow'));
    });
  })();

  // ---- Inventory (UI-R1): each system shows five accounts; the rest, and
  // the Export's account rows, are in data/inventory-accounts.js, read when
  // the page is opened ----
  var inv = (function () {
    var root = document.querySelector('[data-inv]'), data = null, loading = null;
    function load() {
      if (!root || data || loading) return loading;
      loading = getData('inventory/accounts', 'inventory-accounts.js').then(function (d) { data = d; return d; }).catch(function () { loading = null; });
      return loading;
    }
    function row(a) {
      return '<a href="#search?user=' + encodeURIComponent(a[4]) + '" title="This account’s events in this report"><span><b>' + esc(a[0]) + '</b>' +
        (a[5] ? ' <small class="mono">' + esc(a[5]) + '</small>' : '') + '</span><span class="r">' + esc(a[1]) + (a[2] ? ' · disabled' : '') + ' <em>' + esc(a[3]) + '</em></span></a>';
    }
    if (root) root.addEventListener('click', function (e) {
      var b = e.target.closest('[data-invall]');
      if (!b) return;
      var host = b.getAttribute('data-invall'), box = b.closest('.inva').querySelector('[data-invaccts]');
      b.disabled = true;
      Promise.resolve(load()).then(function () {
        if (!data || !data.h[host]) { b.disabled = false; b.textContent = 'Could not read the accounts file'; return; }
        box.innerHTML = data.h[host].map(row).join('');
        b.parentNode.remove();
      });
    });
    // Export: the drives (in this page) and every account (the data file).
    function exporter() {
      var f = meta.pagecsv && meta.pagecsv.inventory;
      if (!f) return null;
      if (!data) load();
      return { label: data ? f.label : 'Drives (accounts still loading)', file: f.file, rows: data ? f.rows.concat(data.csv) : f.rows };
    }
    return { load: load, exporter: exporter };
  })();

  // A wide table that still scrolls sideways says "more →" until its end
  // is in view (UI3).
  function scrollCues() {
    document.querySelectorAll('[data-scrollcue]').forEach(function (w) {
      var box = w.parentNode;
      var mark = function () {
        box.classList.toggle('scrolls', w.scrollWidth > w.clientWidth + 2);
        box.classList.toggle('end', w.scrollLeft + w.clientWidth >= w.scrollWidth - 2);
      };
      if (!w._cue) { w._cue = true; w.addEventListener('scroll', mark); window.addEventListener('resize', mark); }
      mark();
    });
  }

  // ---- List pages (Systems, Detections, People): one item shown at a
  // time, the first in the list unless one is named in the link ----
  function showPick(view, key) {
    var links = view.querySelectorAll('[data-pick]');
    var has = Array.prototype.some.call(view.querySelectorAll('[data-pane]'), function (d) { return d.getAttribute('data-pane') === key; });
    if (!has) {
      var first = Array.prototype.find.call(links, function (a) { return !a.hidden; }) || links[0];
      key = first.getAttribute('data-pick');
    }
    links.forEach(function (a) { a.classList.toggle('sel', a.getAttribute('data-pick') === key); });
    view.querySelectorAll('[data-pane]').forEach(function (d) { d.hidden = d.getAttribute('data-pane') !== key; });
  }
  // Audit health: the grid of every system (A1), or one system's settings
  // (A3) when one is named; a report of one system opens its settings.
  // It returns the part of the page to scroll to, if not the top.
  function showHealth(view, key) {
    var a1 = view.querySelector('[data-a1]'), a3 = view.querySelector('[data-a3]');
    if (!a1) return null;
    key = key || a1.getAttribute('data-single') || '';
    // "#health/HOST/scap" opens the system and goes to its open STIG rules (SC3).
    // "#health/@av" opens the Antivirus tab (UI-R1: @settings, @systems,
    // @scap, @av, @logs); "#health" the first.
    if (key.charAt(0) === '@' || (!key && view.querySelector('[data-htabs]'))) { a1.hidden = false; a3.hidden = true; healthTab(view, key.slice(1)); return null; }
    var scap = /\/scap$/.test(key);
    if (scap) key = key.replace(/\/scap$/, '');
    a1.hidden = !!key; a3.hidden = !key;
    if (key) showPick(a3, key);
    if (scap) return a3.querySelector('[data-pane="' + key.replace(/["\\]/g, '\\$&') + '"] [data-scapopen]');
    return null;
  }
  // Audit health's tabs (UI-R1): one shown at a time; arrow keys move
  // between them.
  function healthTab(view, name) {
    var bar = view.querySelector('[data-htabs]');
    if (!bar) return null;
    var tabs = bar.querySelectorAll('[data-htab]');
    if (!Array.prototype.some.call(tabs, function (t) { return t.getAttribute('data-htab') === name; })) name = tabs[0].getAttribute('data-htab');
    tabs.forEach(function (t) {
      var on = t.getAttribute('data-htab') === name;
      t.setAttribute('aria-selected', on ? 'true' : 'false');
      t.tabIndex = on ? 0 : -1;
    });
    bar.querySelectorAll('[data-hpane]').forEach(function (p) { p.hidden = p.getAttribute('data-hpane') !== name; });
    scrollCues();
    return bar;
  }
  document.querySelectorAll('[data-htabs]').forEach(function (bar) {
    var view = bar.closest('.view');
    bar.addEventListener('click', function (e) {
      var t = e.target.closest('[data-htab]');
      if (!t) return;
      var name = t.getAttribute('data-htab');
      healthTab(view, name);
      if (history.replaceState) history.replaceState(null, '', '#health/@' + name);
    });
    bar.addEventListener('keydown', function (e) {
      var t = e.target.closest('[data-htab]');
      if (!t || (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft' && e.key !== 'Home' && e.key !== 'End')) return;
      var tabs = Array.prototype.slice.call(bar.querySelectorAll('[data-htab]')), i = tabs.indexOf(t);
      i = e.key === 'Home' ? 0 : e.key === 'End' ? tabs.length - 1 : (i + (e.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
      e.preventDefault();
      tabs[i].focus();
      tabs[i].click();
    });
  });
  // Original logs (UI-R1): All / Gaps and missing.
  document.querySelectorAll('[data-lt]').forEach(function (box) {
    box.addEventListener('click', function (e) {
      var b = e.target.closest('[data-lfilter]');
      if (!b) return;
      var gaps = b.getAttribute('data-lfilter') === 'gaps', any = false;
      box.querySelectorAll('[data-lfilter]').forEach(function (x) { x.setAttribute('aria-pressed', x === b ? 'true' : 'false'); });
      box.querySelectorAll('tbody').forEach(function (tb) {
        var shown = 0;
        tb.querySelectorAll('[data-lrow]').forEach(function (r) { r.hidden = gaps && r.hasAttribute('data-ok'); if (!r.hidden) shown++; });
        tb.hidden = shown === 0;
        if (shown) any = true;
      });
      box.querySelector('[data-lnone]').hidden = any;
    });
  });
  // Hide group headings with nothing left under them.
  function tidyHeads(list, head) {
    list.querySelectorAll(head).forEach(function (h) {
      var el = h.nextElementSibling, any = false;
      while (el && !el.matches(head)) { if (!el.hidden) any = true; el = el.nextElementSibling; }
      h.hidden = !any;
    });
  }
  document.querySelectorAll('[data-find]').forEach(function (box) {
    box.addEventListener('input', function () {
      var q = box.value.toLowerCase(), list = box.closest('[data-picklist]');
      var shown = 0;
      list.querySelectorAll('[data-pick]').forEach(function (a) {
        a.hidden = q && (a.textContent + ' ' + (a.getAttribute('data-keys') || '')).toLowerCase().indexOf(q) < 0;
        if (!a.hidden) shown++;
      });
      tidyHeads(list, '.grp2');
      var none = list.querySelector('[data-findnone]');
      if (none) none.hidden = shown > 0;
    });
  });
  // ---- Detections (UI-R1): severity, system, person and servers /
  // workstations filter the list; a group heading counts what is left. If
  // the detection shown is filtered out, the first one left is shown. ----
  var detSev = '';
  function detFilter() {
    var view = document.querySelector('.view[data-view="detections"]'), list = view && view.querySelector('.dlist2');
    if (!list) return;
    var f = {};
    view.querySelectorAll('[data-detf]').forEach(function (s) { f[s.getAttribute('data-detf')] = s.value; });
    var n = 0, sel = null, first = null;
    list.querySelectorAll('[data-pick]').forEach(function (a) {
      var ok = (!detSev || a.getAttribute('data-sev') === detSev) && (!f.host || a.getAttribute('data-host') === f.host) &&
        (!f.user || a.getAttribute('data-user') === f.user) && (!f.kind || a.getAttribute('data-kind') === f.kind);
      a.hidden = !ok;
      if (ok) { n++; if (!first) first = a; if (a.classList.contains('sel')) sel = a; }
    });
    list.querySelectorAll('[data-dethead]').forEach(function (h) {
      var k = 0, el = h.nextElementSibling;
      while (el && el.hasAttribute('data-pick')) { if (!el.hidden) k++; el = el.nextElementSibling; }
      h.hidden = !k;
      h.textContent = h.getAttribute('data-dethead') + ' · ' + k;
    });
    list.querySelector('[data-detnone]').hidden = n > 0;
    if (!sel && first) {
      var key = first.getAttribute('data-pick');
      try { history.replaceState(null, '', '#detections/' + key); } catch (e) {}
      showPick(view, key);
    }
  }
  document.querySelectorAll('[data-detsev] button').forEach(function (b) {
    b.addEventListener('click', function () {
      detSev = b.getAttribute('data-sev');
      b.parentNode.querySelectorAll('button').forEach(function (c) { c.classList.toggle('on', c === b); c.setAttribute('aria-pressed', c === b ? 'true' : 'false'); });
      detFilter();
    });
  });
  document.querySelectorAll('[data-detf]').forEach(function (s) { s.addEventListener('change', detFilter); });

  // ---- Event rows ----
  // Rows are kept as compact arrays: [index, time, host, sev, action, user,
  // target, source, summary, eventID, log, process, command, outcome, flags,
  // day, offset, kind, extra, page], strings already looked up.
  // pageByID: the events' parts, each with its data files (meta.pages);
  // kindByID: the five kinds of event, the event pages and Search's Kind,
  // each showing its parts (owner, UI-R1). A row's r[19] is its part.
  var pageByID = {}, kindByID = {};
  (meta.pages || []).forEach(function (p) { pageByID[p.ID] = p; });
  (meta.kinds || []).forEach(function (k) { kindByID[k.ID] = k; });
  // Sub-kinds the absorbed parts had on their own pages, for old links
  // (#failed?sub=Bad password).
  var OLDSUB = {
    failed: { 'Bad password': 'Failed: bad password', 'Expired': 'Failed: expired', 'Locked out': 'Failed: locked out' },
    usb: { 'Blocked': 'USB blocked', 'Files copied': 'USB files copied', 'Connected or removed': 'USB connected or removed' },
    accounts: { 'Created': 'Account created', 'Changed': 'Account changed', 'Added to group': 'Account added to group', 'Disabled': 'Account disabled' }
  };
  // movedTo is the kind page an old part's link (#failed, #usb,
  // #accounts) now opens, or ''.
  function movedTo(id) { return !kindByID[id] && pageByID[id] ? pageByID[id].Kind : ''; }

  // rowOf turns one row of a data file (chunk c, day, page p) into a row.
  function rowOf(c, r, day, p) {
    var d = c.dict, dz = r[17] || 0; // dz: this row's UTC offset from the day's (DST1)
    return [r[0], c.base + r[1] - dz, d[r[2]], d[r[3]], d[r[4]], d[r[5]], r[6], d[r[7]], r[8], r[9], d[r[10]], d[r[11]], r[12], d[r[13]], r[14], day, c.off + dz, d[r[15]] || '', d[r[16]] || '', p.ID];
  }

  // loadRows reads all of one page's data files into row arrays (once;
  // the event page and Search share them). progress(done, total) is
  // called as each day arrives.
  var loaded = {};
  function loadRows(p, progress) {
    if (loaded[p.ID]) return loaded[p.ID];
    var rows = [], done = 0;
    loaded[p.ID] = Promise.all((p.Days || []).map(function (day) {
      return getData(p.ID + '/' + day, p.ID + '-' + day + '.js').then(function (c) {
        c.rows.forEach(function (r) { rows.push(rowOf(c, r, day, p)); });
        done++;
        if (progress) progress(done, p.Days.length);
      });
    })).then(function () {
      rows.sort(function (a, b) { return b[1] - a[1] || b[0] - a[0]; });
      return rows;
    });
    loaded[p.ID].catch(function () { delete loaded[p.ID]; });
    return loaded[p.ID];
  }
  var tooOld = typeof DecompressionStream === 'undefined';
  var TOO_OLD = 'This browser is too old to show the events. Open events.zip in this report\'s folder instead, or use a current version of Edge, Chrome or Firefox.';

  // A person's key, as People and summary.json have it: lower case,
  // without a domain or host, with people_aliases applied (BB.personKey).
  function key(u) { return BB.personKey(u); }
  function actLabel(a) { a = (a || '').replace(/_/g, ' '); return a.charAt(0).toUpperCase() + a.slice(1); }
  function sevBucket(s) { return s === 'high' || s === 'medium' ? s : 'li'; }
  var SEVWORD = { high: 'High', medium: 'Medium', li: 'Low / info' };
  function commas(n) { return n.toLocaleString('en-US'); }
  function hourOf(r) { return new Date((r[1] + r[16]) * 1000).getUTCHours(); }
  function afterHours(r) {
    var h = meta.hours;
    if (!h) return false;
    var d = new Date((r[1] + r[16]) * 1000), wd = d.getUTCDay(), m = d.getUTCHours() * 60 + d.getUTCMinutes();
    if (h.start <= h.end) return !(h.days[wd] && m >= h.start && m < h.end);
    if (m >= h.start) return !h.days[wd];
    return !(m < h.end && h.days[(wd + 6) % 7]);
  }
  // A weekday-hour of the People heatmap: "0-17" is Mondays 17:00-18:00.
  function inSlot(r, slot) {
    var d = new Date((r[1] + r[16]) * 1000), p = slot.split('-');
    return (d.getUTCDay() + 6) % 7 === +p[0] && d.getUTCHours() === +p[1];
  }
  function hourLabel(v) { var h = +v.slice(8, 10); return dayLabel(v.slice(0, 8)) + ' ' + pad(h) + ':00–' + pad((h + 1) % 24) + ':00'; }
  var allDays = [];
  (meta.pages || []).forEach(function (p) { (p.Days || []).forEach(function (d) { if (allDays.indexOf(d) < 0) allDays.push(d); }); });
  allDays.sort();

  // ---- Search and the event pages (UI-R1 designs 03 and 10) ----
  // One Finder per page: Search (data-sq="") or an event page
  // (data-sq="<page>", its kind of event preset). The search box looks in
  // every field; the filters, field counts (click filters, Alt-click
  // excludes), events per hour and results follow it. The page's link
  // keeps the search (#search?… or #privileged?…), so it can be shared.
  //
  // Link parameters (all optional; see docs/reports.md):
  //   page   the kind of event (an event page's ID; Search only; an old
  //          part's ID, page=failed, opens its kind with part= set)
  //   part   one part of a kind: failed, usb, accounts (and logons,
  //          other, privileged, their kinds' own part)
  //   user   a person's key; host  a system; role  server|workstation|vm
  //          (host=@server and the like still work)
  //   sev    high|medium|hm (high or medium)|li (low or info)|low|info
  //   when   YYYYMMDD a day, YYYYMMDDHH an hour, @after outside working
  //          hours, @slot:D-H a weekday hour (People's heatmap)
  //   at, span  a time (Unix seconds) and seconds either side of it
  //   text   the search box; event  an action (e.g. log_cleared);
  //   sub    an event page's kind (e.g. "Admin logon"); flag  a flag
  //          ("New device"); not  field:value to leave out (repeatable)
  //   group  host|user|event|sub; sort  new|sev|src (sort=host groups by
  //          system); preset  a common search's name
  var PS_DOWNLOAD = /downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|net\.webclient|start-bitstransfer|wget|curl/i;
  var PRESETS = {
    person: { label: 'Everything one person did', set: function () { return { user: meta.firstPerson || '' }; } },
    usbservers: { label: 'USB devices on servers', set: function () { return { page: 'other', part: 'usb', role: 'server' }; } },
    afterhours: { label: 'Admin work after hours', set: function () { return { page: 'privileged', when: '@after' }; } },
    failedsource: { label: 'Failed logons by source', set: function () { return { page: 'logons', part: 'failed', sort: 'src' }; } },
    admingroups: { label: 'Changes to admin groups', set: function () { return { page: 'privileged', part: 'accounts' }; }, test: function (r) { return /^group_member/.test(r[4]); } },
    audit: { label: 'Logs cleared or audit changed', set: function () { return { page: 'integrity' }; } },
    psdownload: { label: 'PowerShell that downloads', set: function () { return { page: 'powershell' }; }, test: function (r) { return PS_DOWNLOAD.test(r[12] + ' ' + r[8]); } },
    rdp: { label: 'Remote Desktop logons', set: function () { return { page: 'logons', part: 'logons' }; }, test: function (r) { return r[17] === 'Remote Desktop'; } }
  };
  var CHIPS = ['event', 'sub', 'flag', 'part'];
  var FIELD = {
    host: function (r) { return r[2]; },
    user: function (r) { return r[5] ? key(r[5]) : ''; },
    event: function (r) { return r[4]; },
    sub: function (r) { return r[17]; },
    part: function (r) { return r[19]; },
    sev: function (r) { return sevBucket(r[3]); }
  };
  var finders = {};

  function Finder(root) {
    var self = this;
    this.root = root;
    this.kind = root.getAttribute('data-sq');
    this.view = root.closest('.view').getAttribute('data-view');
    this.q = {};
    root.querySelectorAll('[data-q]').forEach(function (el) { self.q[el.getAttribute('data-q')] = el; });
    this.rows = []; this.list = []; this.limit = 50; this.seq = 0; this.ran = false;
    this.reset();
    this.filled = false;
    var timer = null;
    Object.keys(this.q).forEach(function (k) {
      var el = self.q[k];
      if (k === 'text') {
        el.addEventListener('input', function () { clearTimeout(timer); timer = setTimeout(function () { self.run(); }, 200); });
      } else if (k === 'group') {
        el.addEventListener('change', function () { self.order(); self.draw(); self.sync(); });
      } else {
        el.addEventListener('change', function () { if (k === 'page') { self.preset = ''; self.inc.part = ''; } self.run(); });
      }
    });
    root.addEventListener('click', function (e) {
      var t = e.target.closest('button, [data-hr], tr[data-i]');
      if (!t || !root.contains(t)) return;
      if (t.hasAttribute('data-fk')) { self.facet(t.getAttribute('data-fk'), t.getAttribute('data-fv'), e.altKey); return; }
      if (t.hasAttribute('data-chip')) { self.unchip(t.getAttribute('data-chip')); return; }
      if (t.hasAttribute('data-hr')) { self.hour(t.getAttribute('data-hr')); return; }
      if (t.hasAttribute('data-qmore')) { self.limit += 50; self.drawRows(); return; }
      if (t.hasAttribute('data-kindclear')) { location.hash = '#search' + self.params(true); return; }
      if (t.hasAttribute('data-common')) { self.menu(); return; }
      if (t.hasAttribute('data-preset')) { self.menu(false); self.usePreset(t.getAttribute('data-preset')); return; }
      if (t.hasAttribute('data-i')) self.openRow(+t.getAttribute('data-i'));
    });
    root.addEventListener('keydown', function (e) {
      var t = e.target.closest && e.target.closest('tr[data-i]');
      if (t && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); self.openRow(+t.getAttribute('data-i')); }
      if (e.key === 'Escape' && self.menuOpen) { self.menu(false); root.querySelector('[data-common]').focus(); }
    });
    document.addEventListener('click', function (e) { if (self.menuOpen && !e.target.closest('.sq-common')) self.menu(false); });
    BB.exportPage(this.view, function () {
      if (!self.list.length) return null;
      var p = kindByID[self.kind];
      return { label: (p ? p.Title : 'Search results') + ' shown', file: self.kind ? self.kind + '-events' : 'search', rows: self.csvRows() };
    });
  }

  Finder.prototype.reset = function () {
    this.inc = {}; this.not = []; this.preset = ''; this.at = 0; this.span = 0;
    this.sortBy = this.kind ? 'sev' : 'new';
  };

  // fill puts the systems, people and days in the dropdowns (once).
  Finder.prototype.fill = function () {
    if (this.filled) return;
    this.filled = true;
    var add = function (sel, v, text, group) { var o = document.createElement('option'); o.value = v; o.textContent = text; (group || sel).appendChild(o); };
    var groups = {}, hk = meta.hostKind || {}, host = this.q.host;
    var names = Object.keys(meta.os || hk).sort(function (a, b) { return a.localeCompare(b, undefined, { numeric: true }); });
    [['server', 'Servers'], ['workstation', 'Workstations'], ['vm', 'Virtual machines']].forEach(function (k) {
      var list = names.filter(function (n) { return (hk[n] || 'workstation') === k[0]; });
      if (!list.length) return;
      var g = document.createElement('optgroup'); g.label = k[1]; host.appendChild(g);
      list.forEach(function (n) { add(host, n, n, g); });
      groups[k[0]] = g;
    });
    var user = this.q.user;
    (meta.people || []).forEach(function (grp) {
      var g = document.createElement('optgroup'); g.label = grp[0]; user.appendChild(g);
      grp[1].forEach(function (p) { add(user, p[0], p[1], g); });
    });
    if (allDays.length) {
      var g = document.createElement('optgroup'); g.label = 'Day'; this.q.when.appendChild(g);
      allDays.forEach(function (d) { add(null, d, dayLabel(d), g); });
    }
  };

  // set chooses a value in a dropdown, adding it when it is not there
  // (an account not on People, an hour from the chart).
  Finder.prototype.set = function (k, v) {
    var el = this.q[k];
    if (!el) return;
    v = v || '';
    if (el.tagName === 'SELECT' && v && !Array.prototype.some.call(el.options, function (o) { return o.value === v; })) {
      var o = document.createElement('option'); o.value = v;
      o.textContent = k === 'when' ? (v.indexOf('@slot:') === 0 ? slotLabel(v.slice(6)) : /^\d{10}$/.test(v) ? hourLabel(v) : v) : v;
      el.appendChild(o);
    }
    el.value = v;
  };

  // An event page shows When only when it is set (design 10 has none).
  Finder.prototype.whenShown = function () {
    if (this.kind) this.q.when.closest('label').hidden = !this.q.when.value;
  };

  Finder.prototype.pages = function () {
    var k = this.kind || this.q.page.value, part = this.inc.part;
    return (meta.pages || []).filter(function (p) { return (!k || p.Kind === k) && (!part || p.ID === part) && p.Days && p.Days.length; });
  };

  Finder.prototype.run = function () {
    var self = this;
    this.fill();
    this.ran = true;
    this.sync();
    this.whenShown();
    if (tooOld) { this.message(TOO_OLD); return; }
    var my = ++this.seq, pages = this.pages();
    this.message('Searching…');
    var all = [];
    Promise.all(pages.map(function (p) {
      return loadRows(p, function (d, n) { if (my === self.seq && pages.length === 1) self.message('Loading events… ' + d + ' of ' + n + ' days'); }).then(function (rows) { all.push(rows); });
    })).then(function () {
      if (my !== self.seq) return;
      var test = self.test(), out = [];
      all.forEach(function (rows) { for (var i = 0; i < rows.length; i++) if (test(rows[i])) out.push(rows[i]); });
      self.rows = out;
      self.order();
      self.draw();
    }).catch(function (err) { self.message('The events could not be read: ' + err.message + '. Open events.zip in this report\'s folder instead.'); });
  };

  // test is the filter of the current search, as one function.
  Finder.prototype.test = function () {
    var q = this.q, user = q.user.value, host = q.host.value, role = q.role.value, sev = q.sev.value, when = q.when.value;
    var text = q.text.value.trim().toLowerCase(), inc = this.inc, not = this.not, at = this.at, span = this.span;
    var pre = PRESETS[this.preset] && PRESETS[this.preset].test, kinds = meta.hostKind || {};
    return function (r) {
      if (user && key(r[5]) !== user) return false;
      if (host && r[2] !== host) return false;
      if (role && (kinds[r[2]] || 'workstation') !== role) return false;
      if (sev && !(sev === r[3] || sev === 'hm' && (r[3] === 'high' || r[3] === 'medium') || sev === 'li' && sevBucket(r[3]) === 'li')) return false;
      if (when) {
        if (when === '@after') { if (!afterHours(r)) return false; }
        else if (when.indexOf('@slot:') === 0) { if (!inSlot(r, when.slice(6))) return false; }
        else if (when.length === 10) { if (r[15] !== when.slice(0, 8) || hourOf(r) !== +when.slice(8)) return false; }
        else if (r[15] !== when) return false;
      }
      if (at && Math.abs(r[1] - at) > span) return false;
      if (inc.event && r[4] !== inc.event) return false;
      if (inc.sub && r[17] !== inc.sub) return false;
      if (inc.part && r[19] !== inc.part) return false;
      if (inc.flag && (',' + r[14] + ',').indexOf(',' + inc.flag + ',') < 0) return false;
      for (var k = 0; k < not.length; k++) if (FIELD[not[k][0]](r) === not[k][1]) return false;
      if (pre && !pre(r)) return false;
      if (text) {
        var hay = (r[8] + ' ' + r[2] + ' ' + r[5] + ' ' + r[6] + ' ' + r[7] + ' ' + r[9] + ' ' + r[4] + ' ' + r[10] + ' ' + r[11] + ' ' + r[12] + ' ' + r[13] + ' ' + r[17] + ' ' + r[18] + ' ' + r[14]).toLowerCase();
        if (hay.indexOf(text) < 0) return false;
      }
      return true;
    };
  };

  var SEVRANK = { high: 0, medium: 1 };
  Finder.prototype.order = function () {
    var by = this.sortBy, g = this.q.group.value, list = this.rows.slice();
    if (by === 'sev') list.sort(function (a, b) { return (SEVRANK[a[3]] === undefined ? 2 : SEVRANK[a[3]]) - (SEVRANK[b[3]] === undefined ? 2 : SEVRANK[b[3]]) || b[1] - a[1] || b[0] - a[0]; });
    else if (by === 'src') list.sort(function (a, b) { return (a[7] || 'local').localeCompare(b[7] || 'local', undefined, { numeric: true }) || b[1] - a[1]; });
    else list.sort(function (a, b) { return b[1] - a[1] || b[0] - a[0]; });
    if (g) {
      // Biggest group first; the rows keep their order within it.
      var f = this.groupKey(), n = {};
      list.forEach(function (r, i) { var k = f(r); n[k] = (n[k] || 0) + 1; r.pos = i; });
      list.sort(function (a, b) { var ka = f(a), kb = f(b); return ka === kb ? a.pos - b.pos : n[kb] - n[ka] || ka.localeCompare(kb, undefined, { numeric: true }); });
      this.groupN = n;
    }
    this.list = list;
    this.limit = 50;
  };
  Finder.prototype.groupKey = function () {
    var g = this.q.group.value;
    if (g === 'user') return function (r) { return r[5] || '(no person)'; };
    if (g === 'event') return function (r) { return actLabel(r[4]); };
    if (g === 'sub') return function (r) { return r[17] || '—'; };
    return function (r) { return r[2]; };
  };

  Finder.prototype.message = function (text) {
    var cols = this.root.querySelectorAll('thead th').length;
    this.root.querySelector('[data-qrows]').innerHTML = '<tr><td colspan="' + cols + '" class="sq-msg">' + esc(text) + '</td></tr>';
    this.root.querySelector('[data-qmore]').hidden = true;
    this.root.querySelector('[data-qleft]').textContent = '';
  };

  Finder.prototype.draw = function () {
    var rows = this.rows, hosts = {}, high = 0, med = 0, p = kindByID[this.kind];
    if (this.inc.part && pageByID[this.inc.part] && pageByID[this.inc.part].Unit) p = pageByID[this.inc.part]; // "891 failed logons"
    rows.forEach(function (r) { hosts[r[2]] = 1; if (r[3] === 'high') high++; else if (r[3] === 'medium') med++; });
    var nh = Object.keys(hosts).length, unit = p && p.Unit ? p.Unit : 'events';
    if (rows.length === 1) unit = unit.replace(/s$/, '');
    var head = commas(rows.length) + ' ' + unit + ' · ' + nh + (nh === 1 ? ' system' : ' systems');
    if (high || med) head += ' · ' + [high ? high + ' high' : '', med ? med + ' medium' : ''].filter(Boolean).join(', ');
    this.root.querySelector('[data-qhead]').textContent = head;
    this.chips();
    this.facets();
    this.hist();
    this.drawRows();
  };

  // A row's cells: Search's columns, or an event page's.
  Finder.prototype.cells = function (r, i) {
    var cls = r[3] === 'high' ? ' class="hi"' : '', t = '<td class="mono">' + when(r[1], r[16]) + '</td><td><b>' + esc(r[2]) + '</b></td><td>' + esc(r[5] || r[6] || '—') + '</td>';
    if (this.kind) {
      var c = (r[12] || '').split('\n')[0];
      t += c ? '<td class="cmd"><code title="' + esc(c) + '">' + esc(c) + '</code></td>' : '<td class="what">' + flags(r) + esc(r[8]) + '</td>';
    } else {
      t += '<td><b class="ev">' + esc(actLabel(r[4])) + '</b></td><td class="what">' + flags(r) + esc(r[8]) + '</td><td class="mono mute">' + esc(r[9] || '') + '</td>';
    }
    return '<tr tabindex="0" data-i="' + i + '"' + cls + '>' + t + '<td>' + (SEV[r[3]] ? '<span class="chip-sev ' + r[3] + '">' + SEV[r[3]] + '</span>' : '<span class="mute">—</span>') + '</td></tr>';
  };
  // Flags ("×7", "Late", "First time") before the summary (UX1).
  function flags(r) { return r[14] ? '<i class="flag">' + esc(r[14].split(',').join(' · ')) + '</i> ' : ''; }

  Finder.prototype.drawRows = function () {
    var list = this.list, n = Math.min(this.limit, list.length), html = '', g = this.q.group.value, f = g && this.groupKey(), last = null;
    var cols = this.root.querySelectorAll('thead th').length;
    if (!list.length) { this.message(this.rows.length || !this.ran ? '' : 'Nothing matches this search.'); this.root.querySelector('[data-qnote]').textContent = ''; return; }
    for (var i = 0; i < n; i++) {
      var r = list[i];
      if (f) {
        var k = f(r);
        if (k !== last) { html += '<tr class="sq-g"><th colspan="' + cols + '" scope="rowgroup">' + esc(k) + ' · ' + commas(this.groupN[k]) + '</th></tr>'; last = k; }
      }
      html += this.cells(r, i);
    }
    this.root.querySelector('[data-qrows]').innerHTML = html;
    var order = this.sortBy === 'sev' ? 'High and medium first, then newest' : this.sortBy === 'src' ? 'By source address' : 'Newest first';
    this.root.querySelector('[data-qnote]').textContent = order + ' · showing ' + commas(n) + ' of ' + commas(list.length);
    var more = this.root.querySelector('[data-qmore]');
    more.hidden = n >= list.length;
    more.textContent = 'Show ' + Math.min(50, list.length - n) + ' more ↓';
    this.root.querySelector('[data-qleft]').textContent = n < list.length ? commas(list.length - n) + ' more' : '';
  };

  // The field counts on the left, for the results shown.
  Finder.prototype.facets = function () {
    var self = this, p = kindByID[this.kind];
    var fields = this.kind ? [['user', 'Person'], ['host', 'System'], ['sub', p.KindLabel || 'Kind']] : [['host', 'System'], ['event', 'Event'], ['sev', 'Severity']];
    var html = '';
    fields.forEach(function (fd) {
      var f = FIELD[fd[0]], n = {}, names = {};
      self.rows.forEach(function (r) { var v = f(r); if (v) { n[v] = (n[v] || 0) + 1; if (fd[0] === 'user' && !names[v]) names[v] = r[5]; } });
      var vals = Object.keys(n);
      if (fd[0] === 'sev') vals = ['high', 'medium', 'li'].filter(function (v) { return n[v]; });
      else vals.sort(function (a, b) { return n[b] - n[a] || a.localeCompare(b, undefined, { numeric: true }); });
      if (!vals.length) return;
      var top = Math.max.apply(null, vals.map(function (v) { return n[v]; })), on = self.current(fd[0]);
      html += '<div class="fg"><h2>' + esc(fd[1]) + '</h2>';
      vals.slice(0, 8).forEach(function (v) {
        var label = fd[0] === 'sev' ? SEVWORD[v] : fd[0] === 'event' ? actLabel(v) : fd[0] === 'user' ? names[v] : v;
        html += '<button type="button" class="fc' + (on === v ? ' on' : '') + '" data-fk="' + fd[0] + '" data-fv="' + esc(v) + '" aria-pressed="' + (on === v) + '" title="' + esc(label) + ': click to show only these, Alt-click to leave them out">' +
          '<span>' + esc(label) + '</span><b>' + commas(n[v]) + '</b><s style="width:' + Math.max(2, Math.round(n[v] / top * 100)) + '%"></s></button>';
      });
      if (vals.length > 8) html += '<p class="fmore">+ ' + (vals.length - 8) + ' more</p>';
      html += '</div>';
    });
    html += '<p class="pm fnote">Click a value to filter; Alt-click to exclude.</p>';
    this.root.querySelector('[data-facets]').innerHTML = html;
  };
  Finder.prototype.current = function (k) {
    if (k === 'host' || k === 'user') return this.q[k].value;
    if (k === 'sev') return this.q.sev.value;
    return this.inc[k] || '';
  };
  Finder.prototype.facet = function (k, v, exclude) {
    if (exclude) {
      if (!this.not.some(function (x) { return x[0] === k && x[1] === v; })) this.not.push([k, v]);
    } else if (k === 'host' || k === 'user' || k === 'sev') {
      this.set(k, this.q[k].value === v ? '' : v);
    } else {
      this.inc[k] = this.inc[k] === v ? '' : v;
    }
    this.run();
  };

  // The filters a dropdown doesn't show, as chips with a ×.
  Finder.prototype.chips = function () {
    var self = this, out = [];
    CHIPS.forEach(function (k) {
      if (!self.inc[k]) return;
      var v = k === 'event' ? actLabel(self.inc[k]) : k === 'part' ? (pageByID[self.inc[k]] || {}).Title || self.inc[k] : self.inc[k];
      out.push([k, ({ event: 'Event', sub: 'Kind', flag: 'Only', part: 'Only' })[k] + ': ' + v]);
    });
    if (this.at) out.push(['at', '±' + Math.round(this.span / 60) + ' min around ' + when(this.at, this.atOff || meta.zoneOff || 0).slice(7)]);
    if (this.preset && PRESETS[this.preset]) out.push(['preset', PRESETS[this.preset].label]);
    this.not.forEach(function (x, i) { out.push(['not' + i, 'Not ' + (x[0] === 'sev' ? SEVWORD[x[1]] : x[0] === 'event' ? actLabel(x[1]) : x[1])]); });
    if (this.sortBy === 'src') out.push(['sort', 'By source address']);
    var box = this.root.querySelector('[data-qchips]');
    box.hidden = !out.length;
    box.innerHTML = out.map(function (c) { return '<span class="sq-chip">' + esc(c[1]) + '<button type="button" data-chip="' + c[0] + '" aria-label="Remove: ' + esc(c[1]) + '">×</button></span>'; }).join('');
  };
  Finder.prototype.unchip = function (c) {
    if (c === 'at') this.at = this.span = 0;
    else if (c === 'preset') this.preset = '';
    else if (c === 'sort') this.sortBy = this.kind ? 'sev' : 'new';
    else if (c.indexOf('not') === 0) this.not.splice(+c.slice(3), 1);
    else this.inc[c] = '';
    this.run();
  };

  // Events per hour across the period; a bar shows that hour.
  Finder.prototype.hist = function () {
    var box = this.root.querySelector('[data-hist]'), days = allDays, rows = this.rows;
    if (!days.length) { box.innerHTML = ''; return; }
    var n = days.length * 24, b = new Array(n).fill(0), top = 1;
    rows.forEach(function (r) {
      var d = days.indexOf(r[15]);
      if (d < 0) return;
      var i = d * 24 + hourOf(r);
      b[i]++; if (b[i] > top) top = b[i];
    });
    var W = 1000, H = 64, bw = W / n, gap = n <= 48 ? 3 : 1, svg = '';
    b.forEach(function (v, i) {
      var x = (i * bw + gap / 2).toFixed(1), w = Math.max(1, bw - gap).toFixed(1), d = days[Math.floor(i / 24)], h = i % 24;
      svg += '<rect x="' + x + '" y="' + (H - 2) + '" width="' + w + '" height="2" fill="#E3E8F2"/>';
      if (v) {
        var bh = Math.max(2, v / top * (H - 6));
        svg += '<rect class="hb" data-hr="' + d + pad(h) + '" x="' + x + '" y="' + (H - bh).toFixed(1) + '" width="' + w + '" height="' + bh.toFixed(1) + '" fill="#4A7DF8"><title>' +
          dayLabel(d) + ' ' + pad(h) + ':00–' + pad((h + 1) % 24) + ':00 · ' + commas(v) + '</title></rect>';
      }
    });
    var lab = '';
    if (days.length === 1) [0, 6, 12, 18, 24].forEach(function (h) { lab += '<span style="left:' + (h / 24 * 100).toFixed(2) + '%">' + pad(h) + ':00</span>'; });
    else {
      var step = Math.ceil(days.length / 8);
      days.forEach(function (d, k) { if (k % step === 0) lab += '<span style="left:' + (k / days.length * 100).toFixed(2) + '%">' + dayLabel(d) + '</span>'; });
    }
    box.innerHTML = '<svg viewBox="0 0 ' + W + ' ' + H + '" width="100%" height="' + H + '" preserveAspectRatio="none" role="img" aria-label="' +
      commas(rows.length) + ' events by hour over the period; click a bar for that hour">' + svg + '</svg><div class="sq-axis">' + lab + '</div>';
  };
  Finder.prototype.hour = function (h) { this.set('when', this.q.when.value === h ? '' : h); this.run(); };

  Finder.prototype.menu = function (open) {
    var m = this.root.querySelector('[data-commonmenu]'), b = this.root.querySelector('[data-common]');
    if (!m) return;
    if (open === undefined) open = m.hidden;
    m.hidden = !open; b.setAttribute('aria-expanded', open ? 'true' : 'false');
    this.menuOpen = open;
    if (open) m.querySelector('button').focus();
  };
  Finder.prototype.usePreset = function (name) {
    var pr = PRESETS[name];
    if (!pr) return;
    var self = this, v = pr.set();
    this.reset();
    ['page', 'user', 'host', 'role', 'sev', 'when', 'text'].forEach(function (k) { self.set(k, v[k]); });
    this.inc.part = v.part || '';
    this.q.group.value = '';
    if (v.sort) this.sortBy = v.sort;
    this.preset = pr.test ? name : '';
    this.run();
  };

  // params is the search as a link's query string ("?user=jlee&…").
  // forSearch: for Search, with this page's kind as page=.
  Finder.prototype.params = function (forSearch) {
    var q = this.q, out = [], add = function (k, v) { if (v) out.push(encodeURIComponent(k) + '=' + encodeURIComponent(v)); };
    if (!this.kind) add('page', q.page.value);
    ['user', 'host', 'role', 'sev', 'when'].forEach(function (k) { add(k, q[k].value); });
    if (this.at) { add('at', String(this.at)); add('span', String(this.span)); }
    add('text', q.text.value);
    var self = this;
    CHIPS.forEach(function (k) { add(k, self.inc[k]); });
    this.not.forEach(function (x) { add('not', x[0] + ':' + x[1]); });
    add('group', q.group.value);
    if (this.sortBy !== (this.kind ? 'sev' : 'new') && !(forSearch && this.sortBy === 'new')) add('sort', this.sortBy);
    add('preset', this.preset);
    return out.length ? '?' + out.join('&') : '';
  };
  Finder.prototype.sync = function () {
    var h = '#' + this.view + this.params(false);
    if (location.hash !== h && history.replaceState) history.replaceState(null, '', h);
  };

  // query sets the search from a link's query string and runs it.
  Finder.prototype.query = function (qs) {
    var self = this, p = {}, nots = [];
    this.fill();
    (qs || '').split('&').forEach(function (kv) {
      var i = kv.indexOf('=');
      if (i <= 0) return;
      var k = decodeURIComponent(kv.slice(0, i)), v = decodeURIComponent(kv.slice(i + 1).replace(/\+/g, ' '));
      if (k === 'not') nots.push(v); else p[k] = v;
    });
    this.reset();
    if (p.host && p.host.charAt(0) === '@') { p.role = p.host.slice(1); p.host = ''; }
    if (p.user) p.user = key(p.user); // any spelling: "SRV-DC02\\jlee", an alias
    if (p.sort === 'host') { p.group = 'host'; p.sort = ''; }
    // An old link to a part as a kind (page=failed): its kind, showing
    // that part, with the part's old sub-kind names (UI-R1).
    if (p.page && movedTo(p.page)) { p.part = p.page; p.page = movedTo(p.page); }
    if (p.part && p.sub && OLDSUB[p.part] && OLDSUB[p.part][p.sub]) p.sub = OLDSUB[p.part][p.sub];
    ['page', 'user', 'host', 'role', 'sev', 'when', 'text'].forEach(function (k) { self.set(k, p[k]); });
    this.q.group.value = Array.prototype.some.call(this.q.group.options, function (o) { return o.value === p.group; }) ? p.group : '';
    CHIPS.forEach(function (k) { self.inc[k] = p[k] || ''; });
    this.not = nots.map(function (v) { var i = v.indexOf(':'); return [v.slice(0, i), v.slice(i + 1)]; }).filter(function (x) { return FIELD[x[0]]; });
    if (p.at) { this.at = +p.at; this.span = +(p.span || 600); }
    if (p.sort) this.sortBy = p.sort;
    if (PRESETS[p.preset] && PRESETS[p.preset].test) this.preset = p.preset;
    this.run();
  };
  // open shows the page from a link without a query: "#search/<text>"
  // searches for the text; otherwise the last search stays.
  Finder.prototype.open = function (text) {
    if (text) { this.query('text=' + encodeURIComponent(text)); return; }
    if (!this.ran) this.query('');
    else this.sync();
  };

  Finder.prototype.openRow = function (i) {
    var t = this.root.closest('.view').querySelector('h1');
    openEvent({ shown: this.list, crumb: t ? t.firstChild.textContent.trim() : 'Search' }, i);
  };

  // csvRows is the rows shown, header first, every time with its zone
  // (ASSESS1): the page's Export CSV and the Export menu's "This page".
  Finder.prototype.csvRows = function () {
    var p = kindByID[this.kind], kind = ((p && p.KindLabel) || 'kind').toLowerCase();
    var rows = [['time', 'system', 'person', 'target', 'source', 'what happened', kind, 'severity', 'event id', 'log', 'process', 'command', 'outcome']];
    this.list.forEach(function (r) {
      rows.push([when(r[1], r[16]) + ' ' + zoneOf(r[16]), r[2], r[5], r[6], r[7], r[8], r[17], r[3], r[9], r[10], r[11], r[12], r[13]].map(csvSafe));
    });
    return rows;
  };

  // ---- Event panel (UI-R1 design 16) ----
  var ov = document.querySelector('.ov'), drawer = document.querySelector('.drawer'), lastFocus = null;
  drawer.setAttribute('role', 'dialog');
  drawer.setAttribute('aria-modal', 'true');
  drawer.setAttribute('aria-label', 'Event');
  function closeEvent() {
    if (drawer.hidden) return;
    ov.hidden = true; drawer.hidden = true;
    if (lastFocus && document.contains(lastFocus)) lastFocus.focus();
  }
  ov.addEventListener('click', closeEvent);
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeEvent(); });

  // Day files read for "Around it", kept for a few panels.
  var dayCache = {}, dayOrder = [];
  function dayChunk(p, day) {
    var k = p.ID + '/' + day;
    if (!dayCache[k]) {
      dayCache[k] = getData(k, p.ID + '-' + day + '.js');
      dayOrder.push(k);
      if (dayOrder.length > 24) delete dayCache[dayOrder.shift()];
    }
    return dayCache[k];
  }

  function openEvent(ctx, i) {
    var r = ctx.shown[i];
    if (!r) return;
    var p = pageByID[r[19]] || ctx.page, host = r[2], who = r[5] || '', pk = key(who);
    var det = meta.rowdet && meta.rowdet[r[0]];
    var rights = who && meta.rights && meta.rights[host] && meta.rights[host][pk];
    var acct = who ? (who.indexOf('\\') >= 0 ? who : host + '\\' + who) + (rights ? ' (' + rights + ')' : '') : '';
    var sys = host + (meta.os && meta.os[host] ? ' · ' + meta.os[host] : '');
    var zip = meta.archives && meta.archives[host];
    var crumb = (ctx.crumb || (p && p.Title) || 'Search') + ' › event' + (r[10] || r[9] ? ' · ' + [r[10], r[9]].filter(Boolean).join(' ') : '');
    var fact = function (k, label, v, html) { return v ? '<dt>' + esc(label) + '</dt><dd data-f="' + k + '">' + (html || esc(v)) + '</dd>' : ''; };
    var code = function (v) { return '<code>' + esc(v) + '</code>'; };
    var facts = fact('when', 'When', when(r[1], r[16]) + ' ' + zoneOf(r[16])) +
      fact('sys', 'System', sys, '<a class="link" href="#systems/' + encodeURIComponent(host) + '">' + esc(host) + '</a>' + esc(sys.slice(host.length))) +
      fact('who', 'Person', acct, '<a class="link" href="#people/' + encodeURIComponent(pk) + '">' + esc(acct) + '</a>') +
      fact('src', 'From', r[7], '<a class="link" href="#search?text=' + encodeURIComponent(r[7]) + '" title="Everything from ' + esc(r[7]) + '">' + esc(r[7]) + '</a>') +
      fact('x', (p && p.XLabel) || '', p && p.XLabel ? r[18] : '') +
      fact('prog', 'Program', r[11], code(r[11])) + fact('cmd', 'Command', r[12], code(r[12])) +
      '<dt hidden>Started by</dt><dd data-f="by" hidden></dd>' +
      fact('out', 'Outcome', r[13]) +
      fact('rec', 'Original record', zip ? zip + ' › ' + (r[10] || '') : r[10] || 'not known', code(zip ? zip + ' › ' + (r[10] || '') : r[10] || 'not known'));
    var btn = function (href, text) { return '<a class="btn" href="' + href + '">' + text + '</a>'; };
    var btns = (pk ? btn('#search?user=' + encodeURIComponent(pk), 'Everything ' + esc(who) + ' did') : '') +
      btn('#search?host=' + encodeURIComponent(host) + '&at=' + r[1] + '&span=600', '±10 min on ' + esc(host)) +
      '<button type="button" class="btn" data-ticket>Copy for a ticket</button>' +
      '<button type="button" class="btn" data-rawbtn aria-expanded="true" aria-controls="ev-raw">Raw record ▾</button>';
    drawer.innerHTML = '<button type="button" class="x" aria-label="Close">✕</button><div class="ecrumb">' + esc(crumb) + '</div>' +
      '<h3>' + esc(r[8]) + '</h3>' +
      (SEV[r[3]] || det !== undefined ? '<div class="epart">' + (SEV[r[3]] ? '<span class="chip-sev ' + r[3] + '">' + SEV[r[3]] + '</span>' : '') +
        (det !== undefined ? '<span>part of the detection <a class="link" href="#detections/' + det + '">' + esc(meta.dets[det]) + ' →</a></span>' : '') + '</div>' : '') +
      '<dl class="evf">' + facts + '</dl>' +
      '<div class="sub2">Around it on ' + esc(host) + '</div><div class="near">Loading…</div>' +
      '<div class="sub2">Context</div><dl class="evf ctx"><dt hidden>Seen before</dt><dd data-f="seen" hidden></dd>' +
      '<dt>ATT&amp;CK</dt><dd data-f="attack">—</dd>' + (r[12] ? '<dt>Same command</dt><dd data-f="same">counting…</dd>' : '') + '</dl>' +
      '<div class="dbtns">' + btns + '</div><div class="raw" id="ev-raw">Loading the original event data…</div>';
    lastFocus = document.activeElement;
    drawer.querySelector('.x').addEventListener('click', closeEvent);
    drawer.querySelectorAll('.dbtns a, dd a, .epart a').forEach(function (a) { a.addEventListener('click', closeEvent); });
    var raw = drawer.querySelector('.raw'), rb = drawer.querySelector('[data-rawbtn]');
    rb.addEventListener('click', function () { raw.hidden = !raw.hidden; rb.setAttribute('aria-expanded', raw.hidden ? 'false' : 'true'); });
    var ticket = { what: r[8], when: when(r[1], r[16]) + ' ' + zoneOf(r[16]), rec: zip ? zip + ' › ' + (r[10] || '') : r[10] || '' };
    drawer.querySelector('[data-ticket]').addEventListener('click', function (e) {
      var lines = [ticket.what, 'When: ' + ticket.when, 'System: ' + sys];
      if (acct) lines.push('Person: ' + acct);
      if (r[11]) lines.push('Program: ' + r[11]);
      if (r[12]) lines.push('Command: ' + r[12]);
      if (ticket.by) lines.push('Started by: ' + ticket.by);
      if (r[13]) lines.push('Outcome: ' + r[13]);
      lines.push('Original record: ' + ticket.rec + (ticket.as ? ' (' + ticket.as + ')' : ''));
      if (det !== undefined) lines.push('Detection: ' + meta.dets[det]);
      copyText(lines.join('\n') + '\n', e.target);
    });
    ov.hidden = false; drawer.hidden = false;
    drawer.scrollTop = 0;
    drawer.querySelector('.x').focus();
    getData('raw/' + p.ID + '/' + r[15], p.ID + '-' + r[15] + '-raw.js').then(function (rawd) {
      // The raw file lists the day's events in the same order as its data file.
      return dayChunk(p, r[15]).then(function (c) {
        for (var k = 0; k < c.rows.length; k++) if (c.rows[k][0] === r[0]) return rawd[k];
      });
    }).then(function (x) {
      if (!drawer.contains(raw)) return;
      if (!x) { raw.textContent = 'No original event data.'; return; }
      var ex = x[4] || {}, put = function (k, v) { var d = drawer.querySelector('[data-f="' + k + '"]'); if (d && v) { d.innerHTML = v; d.hidden = false; if (d.previousElementSibling) d.previousElementSibling.hidden = false; } };
      if (ex.when || x[3]) { ticket.when = ex.when || x[3]; put('when', esc(ticket.when)); }
      if (ex.by) { ticket.by = ex.by; put('by', esc(ex.by)); }
      if (ex.piece) ticket.rec = ex.piece;
      if (ex.rec) ticket.rec += ', record ' + commas(ex.rec);
      ticket.as = ex.rec ? '' : x[2] || '';
      put('rec', '<code>' + esc(ex.piece || ticket.rec.split(', record')[0]) + '</code>' + (ex.rec ? ', record ' + commas(ex.rec) : '') + (x[2] && !ex.rec ? '<small>' + esc(x[2]) + '</small>' : ''));
      put('attack', ex.attack ? esc(ex.attack) : '');
      put('seen', ex.seen ? esc(ex.seen) : '');
      var out = '';
      (x[0] || []).forEach(function (d) { out += '<span class="t">' + esc(d.label) + ':</span> <span class="v">' + esc(d.value) + '</span>\n'; });
      var f = x[1] || {};
      Object.keys(f).forEach(function (k) { out += '<span class="t">' + esc(k) + '</span> <span class="v">' + esc(f[k]) + '</span>\n'; });
      if (x[2]) out = '<span class="t">Recorded as:</span> <span class="v">' + esc(x[2]) + '</span>\n' + out;
      raw.innerHTML = out || 'No original event data.';
    }).catch(function (err) {
      if (drawer.contains(raw)) raw.textContent = 'The original event data could not be read: ' + err.message;
    });
    nearby(r);
    sameCommand(r, p);
  }

  // copyText puts text on the clipboard, saying so on the button.
  function copyText(text, b) {
    var done = function () { var t = b.textContent; b.textContent = 'Copied'; setTimeout(function () { b.textContent = t; }, 1500); };
    var old = function () {
      var ta = document.createElement('textarea'); ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); done(); } catch (e) { /* nothing more to try */ }
      ta.remove(); b.focus();
    };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, old);
    else old();
  }

  // Same command: how many other systems ran it this period.
  function sameCommand(r, p) {
    if (!r[12]) return;
    loadRows(p).then(function (rows) {
      var hosts = {};
      rows.forEach(function (x) { if (x[12] === r[12] && x[2] !== r[2]) hosts[x[2]] = 1; });
      var n = Object.keys(hosts).length, d = drawer.querySelector('[data-f="same"]');
      if (d) d.textContent = n + (n === 1 ? ' other system' : ' other systems') + ' this period';
    }).catch(function () {});
  }

  // nearby lists the events (on any page) on the same system just before
  // and after r: four either side.
  function nearby(r) {
    var host = r[2], found = [];
    var jobs = (meta.pages || []).filter(function (p) { return (p.Days || []).indexOf(r[15]) >= 0; }).map(function (p) {
      return dayChunk(p, r[15]).then(function (c) {
        var h = c.dict.indexOf(host);
        if (h < 0) return;
        c.rows.forEach(function (x) { if (x[2] === h) found.push(rowOf(c, x, r[15], p)); });
      });
    });
    Promise.all(jobs).then(function () {
      var box = drawer.querySelector('.near');
      if (!box) return;
      found.sort(function (a, b) { return a[1] - b[1] || a[0] - b[0]; });
      var at = 0;
      found.forEach(function (x, k) { if (x[0] === r[0] && x[19] === r[19]) at = k; });
      var list = found.slice(Math.max(0, at - 4), at + 5);
      box.innerHTML = list.map(function (x, k) {
        var me = x[0] === r[0] && x[19] === r[19];
        return '<button type="button"' + (me ? ' class="me" aria-current="true"' : '') + ' data-near="' + k + '"><span class="mono">' + when(x[1], x[16]).slice(7) + '</span><span>' + esc(x[8]) + '</span></button>';
      }).join('') || '<p class="pm">Nothing else on ' + esc(host) + ' that day.</p>';
      box.querySelectorAll('[data-near]').forEach(function (b) {
        b.addEventListener('click', function () { if (!b.classList.contains('me')) openEvent({ shown: list, crumb: 'Around it' }, +b.getAttribute('data-near')); });
      });
    }).catch(function () {
      var box = drawer.querySelector('.near');
      if (box) box.textContent = 'Could not read the nearby events.';
    });
  }

  // The report folder, as it was opened (a share shows as \\server\…).
  (function () {
    var p = decodeURIComponent(location.pathname).replace(/[^/]*$/, '');
    if (location.protocol !== 'file:') return;
    if (/^\/[A-Za-z]:/.test(p)) p = p.slice(1).replace(/\//g, '\\');
    else if (location.host) p = '\\\\' + location.host + p.replace(/\//g, '\\');
    document.querySelectorAll('[data-folder]').forEach(function (el) { el.textContent = p; });
  })();

  // ---- Export menu and Verified pop-up (UI-R1) ----
  // The Export menu's "This page" is what the page shown holds, as CSV.
  // A page gives it with BB.exportPage(view, fn), fn returning
  // { label, file, rows } (rows: header first, fields made safe with
  // csvSafe) or null. Without one: an event page or Search exports its
  // table's rows, any other page the file made for it (meta.pagecsv).
  var exporters = {};
  BB.exportPage = function (view, fn) { exporters[view] = fn; };
  function shownView() {
    var v = document.querySelector('.view:not([hidden])');
    return v ? v.getAttribute('data-view') : '';
  }
  function pageExport() {
    var id = shownView();
    if (exporters[id]) return exporters[id]();
    var f = meta.pagecsv && meta.pagecsv[id];
    return f ? { label: f.label, file: f.file, rows: f.rows } : null;
  }
  // Detections: the ones the filters show (data-pos is the row in the
  // detections file).
  BB.exportPage('detections', function () {
    var f = meta.pagecsv && meta.pagecsv.detections;
    if (!f) return null;
    var keep = {}, all = true;
    document.querySelectorAll('.dlist2 [data-pick]').forEach(function (a) { if (a.hidden) all = false; else keep[a.getAttribute('data-pos')] = 1; });
    var rows = f.rows.filter(function (r, i) { return i === 0 || all || keep[i]; });
    return { label: 'Detections shown', file: f.file + (all ? '' : '-filtered'), rows: rows };
  });
  BB.exportPage('inventory', inv.exporter);
  function exportPage() {
    var x = pageExport();
    if (x) save(x.file + (stamp ? '-' + stamp : '') + '.csv', toCSV(x.rows));
  }

  var openPop = null, openBtn = null;
  function closePop() {
    if (!openPop) return;
    openPop.hidden = true;
    if (openBtn) openBtn.setAttribute('aria-expanded', 'false');
    openPop = openBtn = null;
  }
  function placePop(pop, b) {
    var r = b.getBoundingClientRect(), w = pop.offsetWidth, h = pop.offsetHeight, W = window.innerWidth, H = window.innerHeight;
    var left = Math.max(8, Math.min(r.right, W - 8) - w), top = r.bottom + 6;
    var side = b.closest('aside') && b.closest('aside').getBoundingClientRect();
    if (side && side.right + 12 + w <= W - 8 && side.height > H / 2) {
      // From the sidebar's report card: beside the sidebar, level with
      // the card's bottom.
      left = side.right + 12; top = r.bottom - h + 8;
    } else if (top + h > H - 8 && r.top - h - 6 >= 8) {
      top = r.top - h - 6; // no room below: above the button
    }
    pop.style.left = left + 'px';
    pop.style.top = Math.max(8, Math.min(top, H - h - 8)) + 'px';
  }
  document.querySelectorAll('[data-open]').forEach(function (b) {
    b.setAttribute('aria-expanded', 'false');
    b.addEventListener('click', function (e) {
      e.stopPropagation();
      var pop = document.querySelector('[data-pop="' + b.getAttribute('data-open') + '"]');
      var was = openPop === pop;
      closePop();
      if (was || !pop) return;
      if (pop.getAttribute('data-pop') === 'export') {
        var x = pageExport(), box = pop.querySelector('[data-xpage]');
        box.hidden = !x;
        if (x) pop.querySelector('[data-xlabel]').textContent = x.label + ' (' + (x.rows.length - 1).toLocaleString('en-US') + ')';
      }
      pop.hidden = false;
      placePop(pop, b);
      b.setAttribute('aria-expanded', 'true');
      openPop = pop; openBtn = b;
      var first = pop.querySelector('a:not([hidden]), button');
      if (first && e.detail === 0) first.focus(); // opened from the keyboard
    });
  });
  document.addEventListener('click', function (e) { if (openPop && !openPop.contains(e.target)) closePop(); });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && openPop) { var b = openBtn; closePop(); if (b) b.focus(); }
  });
  window.addEventListener('scroll', closePop);
  window.addEventListener('resize', closePop);
  document.querySelectorAll('[data-act]').forEach(function (a) {
    a.addEventListener('click', function (e) {
      e.preventDefault(); closePop();
      var act = a.getAttribute('data-act'), f = meta.reportcsv && meta.reportcsv[act];
      if (act === 'print') window.print();
      else if (act === 'pagecsv') exportPage();
      else if (f) save(f.file + (stamp ? '-' + stamp : '') + '.csv', toCSV(f.rows));
    });
  });
  // A data file whose contents differ from the hash recorded in this page
  // turns Verified red: the report card's line, and the pop-up's title and
  // first check, with the file's name.
  function tampered(file) {
    document.querySelectorAll('[data-vline]').forEach(function (b) {
      b.className = 'vline bad';
      b.innerHTML = '<i aria-hidden="true">✕</i> <span>Not verified · a file was changed</span>';
    });
    var h = document.querySelector('[data-vhead]');
    if (h) { h.className = 'vh bad'; h.querySelector('i').textContent = '✕'; h.querySelector('b').textContent = 'This report has been changed'; }
    var l = document.querySelector('[data-vlist]');
    if (l) {
      var first = l.querySelector('li');
      if (first && /manifest/.test(first.textContent) && first.className === 'ok') first.remove();
      l.insertAdjacentHTML('afterbegin', '<li class="bad"><i aria-hidden="true">✕</i><span>Report files do not match the manifest<small>data/' + esc(file) + ' was changed after the report was written</small></span></li>');
    }
  }

  // ---- Links that open one event's panel (data-ev="page:index"), and
  // links to a part of the same page (data-scroll="id") ----
  function openEventAt(ref) {
    var parts = ref.split(':'), p = pageByID[parts[0]], idx = +parts[1];
    if (!p || tooOld) return;
    var t = document.querySelector('.view:not([hidden]) h1');
    loadRows(p).then(function (rows) {
      for (var k = 0; k < rows.length; k++) {
        if (rows[k][0] === idx) { openEvent({ shown: [rows[k]], page: p, crumb: t ? t.firstChild.textContent.trim() : '' }, 0); return; }
      }
    });
  }
  document.addEventListener('click', function (e) {
    var ev = e.target.closest('[data-ev]');
    if (ev && !e.target.closest('a[href]:not([href="#"])')) { e.preventDefault(); openEventAt(ev.getAttribute('data-ev')); return; }
    var mx = e.target.closest('[data-mxshow]');
    if (mx) {
      // Audit health: show the systems that match on every check.
      var ok = mx.closest('table').querySelector('[data-mxok]');
      if (!ok) return;
      if (!mx.hasAttribute('data-label')) mx.setAttribute('data-label', mx.textContent);
      ok.hidden = !ok.hidden;
      mx.textContent = mx.getAttribute(ok.hidden ? 'data-label' : 'data-hide');
      return;
    }
    var sc = e.target.closest('[data-scroll]');
    if (sc) {
      e.preventDefault();
      var el = document.getElementById(sc.getAttribute('data-scroll'));
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });

  // ---- Trends (UI-R1): the 4 / 8 / 12-week switch, its CSV and the
  // Monthly summary (the page at 4 weeks, printed) ----
  (function () {
    var view = document.querySelector('.view[data-view="trends"]');
    if (!view) return;
    var weeks = 8;
    function range(n) {
      var crumb = view.querySelector('.head .crumb'), was = view.querySelector('[data-trview]:not([hidden])');
      var to = view.querySelector('[data-trview="' + n + '"]');
      if (!to) return;
      if (crumb && was) crumb.textContent = crumb.textContent.replace(was.getAttribute('data-crumb'), to.getAttribute('data-crumb'));
      view.querySelectorAll('[data-trview]').forEach(function (v) { v.hidden = v !== to; });
      view.querySelectorAll('[data-trange]').forEach(function (b) {
        var on = +b.getAttribute('data-trange') === n;
        b.classList.toggle('on', on);
        b.setAttribute('aria-pressed', on ? 'true' : 'false');
      });
      weeks = n;
    }
    view.querySelectorAll('[data-trange]').forEach(function (b) {
      b.addEventListener('click', function () { range(+b.getAttribute('data-trange')); });
    });
    BB.exportPage('trends', function () {
      var f = meta.pagecsv && meta.pagecsv.trends;
      if (!f) return null;
      var rows = [f.rows[0]].concat(f.rows.slice(1).slice(-weeks));
      return { label: 'Weekly counts, ' + (rows.length - 1) + ' weeks', file: f.file + '-' + weeks + 'w', rows: rows };
    });
    var pb = view.querySelector('[data-trprint]');
    if (pb) pb.addEventListener('click', function () {
      var back = weeks;
      range(4);
      document.body.classList.add('trprint');
      var over = false, done = function () {
        if (over) return;
        over = true;
        document.body.classList.remove('trprint'); range(back); window.removeEventListener('afterprint', done);
      };
      window.addEventListener('afterprint', done);
      window.print();
      setTimeout(done, 1000);
    });
  })();

  // Search and the event pages (after BB.exportPage is set up).
  document.querySelectorAll('[data-sq]').forEach(function (root) {
    var f = new Finder(root);
    finders[f.view] = f;
  });

  // Another page (Back, a bookmark) closes the event panel.
  window.addEventListener('hashchange', function () { closeEvent(); show(); });
  show();
})();
