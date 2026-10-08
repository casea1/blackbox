// Blackbox report: page switching, and the event pages' tables. The events
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

  // "0-17" (a People heatmap cell) as "Mondays 17:00–18:00".
  function slotLabel(slot) {
    var p = slot.split('-'), h = +p[1];
    return ['Mondays', 'Tuesdays', 'Wednesdays', 'Thursdays', 'Fridays', 'Saturdays', 'Sundays'][+p[0]] + ' ' + pad(h) + ':00–' + pad((h + 1) % 24) + ':00';
  }

  // People heatmap: a red hour shows the person's detections in it.
  document.addEventListener('click', function (ev) {
    var a = ev.target.closest && ev.target.closest('[data-hslot]');
    if (!a) return;
    ev.preventDefault();
    var slot = a.getAttribute('data-hslot'), box = document.getElementById('pdet-' + a.getAttribute('data-person'));
    if (!box) return;
    var n = 0;
    box.querySelectorAll('.dc').forEach(function (c) {
      var on = (' ' + (c.getAttribute('data-slots') || '') + ' ').indexOf(' ' + slot + ' ') >= 0;
      c.hidden = !on;
      if (on) n++;
    });
    var note = box.querySelector('[data-slotnote]');
    if (note) {
      if (!note.hasAttribute('data-all')) note.setAttribute('data-all', note.textContent);
      note.innerHTML = esc(n + ' at ' + slotLabel(slot)) + ' · <a href="#" class="link" data-slotall>Show all</a>';
    }
    box.scrollIntoView({ block: 'start' });
  });
  document.addEventListener('click', function (ev) {
    var a = ev.target.closest && ev.target.closest('[data-slotall]');
    if (!a) return;
    ev.preventDefault();
    var box = a.closest('.panel'), note = box.querySelector('[data-slotnote]');
    box.querySelectorAll('.dc').forEach(function (c) { c.hidden = false; });
    note.textContent = note.getAttribute('data-all');
  });

  // A stat card above an event table filters it (data-cardfilter is a query
  // string; empty shows everything).
  document.addEventListener('click', function (ev) {
    var a = ev.target.closest && ev.target.closest('[data-cardfilter]');
    if (!a) return;
    var view = a.closest('.view'), t = view && tables[view.getAttribute('data-view')];
    if (!t) return;
    ev.preventDefault();
    var f = {};
    a.getAttribute('data-cardfilter').split('&').forEach(function (kv) {
      var i = kv.indexOf('=');
      if (i > 0) f[decodeURIComponent(kv.slice(0, i))] = decodeURIComponent(kv.slice(i + 1).replace(/\+/g, ' '));
    });
    t.apply(f);
    t.el.scrollIntoView({ block: 'start' });
  });

  document.addEventListener('click', function (ev) {
    var a = ev.target.closest && ev.target.closest('[data-flagclear]');
    if (!a) return;
    ev.preventDefault();
    var t = tables[a.closest('.view').getAttribute('data-view')];
    if (t) { t.flag = ''; a.parentNode.hidden = true; t.filter(); }
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
    if (!document.querySelector('.view[data-view="' + id + '"]')) id = 'overview';
    views.forEach(function (v) { v.hidden = v.getAttribute('data-view') !== id; });
    document.querySelectorAll('[data-nav]').forEach(function (a) {
      var on = a.getAttribute('data-nav') === id;
      a.classList.toggle('on', on);
      if (on) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
    });
    var t = tables[id];
    if (t) t.open();
    var view = document.querySelector('.view[data-view="' + id + '"]');
    if (id === 'search' && search) {
      var h = location.hash;
      if (h.indexOf('#search?') === 0) search.query(h.slice(8));
      else search.open(decodeURIComponent(h.split('/').slice(1).join('/')));
    }
    var to = null;
    if (id === 'systems') showSystem(view, decodeURIComponent(location.hash.split('/').slice(1).join('/')));
    else if (id === 'health' || id === 'logs') to = showHealth(view, decodeURIComponent(location.hash.split('/').slice(1).join('/')));
    else if (view.querySelector('[data-pick]')) {
      showPick(view, decodeURIComponent(location.hash.split('/').slice(1).join('/')));
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
    // "#health/@av" goes to the Antivirus table.
    if (key === '@av') { a1.hidden = false; a3.hidden = true; return document.getElementById('h-av'); }
    var scap = /\/scap$/.test(key);
    if (scap) key = key.replace(/\/scap$/, '');
    a1.hidden = !!key; a3.hidden = !key;
    if (key) showPick(a3, key);
    if (scap) return a3.querySelector('[data-pane="' + key.replace(/["\\]/g, '\\$&') + '"] [data-scapopen]');
    return null;
  }
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
  document.querySelectorAll('[data-detsev] span').forEach(function (chip) {
    chip.addEventListener('click', function () {
      var sev = chip.getAttribute('data-sev');
      chip.parentNode.querySelectorAll('span').forEach(function (c) { c.classList.toggle('on', c === chip); });
      var list = chip.closest('.dlist');
      list.querySelectorAll('[data-pick]').forEach(function (a) { a.hidden = !!sev && !a.classList.contains(sev); });
      tidyHeads(list, '.dayh');
    });
  });

  // ---- Event tables ----
  // Rows are kept as compact arrays: [index, time, host, sev, action, user,
  // target, source, summary, eventID, log, process, command, outcome, flags,
  // day, offset, kind, extra], strings already looked up.
  var ROW_H = 38;
  var tables = {}, pageByID = {};
  (meta.pages || []).forEach(function (p) { pageByID[p.ID] = p; });
  (meta.pages || []).forEach(function (p) {
    var el = document.querySelector('[data-events="' + p.ID + '"]');
    if (el) tables[p.ID] = new Table(p, el);
  });

  function Table(page, el) {
    this.page = page; this.el = el; this.rows = null; this.shown = [];
    this.body = el.querySelector('.vt-body'); this.box = el.querySelector('.vt');
    this.count = el.querySelector('[data-count]');
    var self = this;
    el.querySelectorAll('[data-f]').forEach(function (f) {
      f.addEventListener('input', function () { self.filter(); });
    });
    this.box.addEventListener('scroll', function () { self.draw(); });
    this.body.addEventListener('click', function (e) {
      var r = e.target.closest('[data-i]');
      if (r) openEvent(self, +r.getAttribute('data-i'));
    });
    el.querySelector('[data-csv]').addEventListener('click', function () { self.csv(); });
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
        var d = c.dict;
        c.rows.forEach(function (r) {
          // r[17] is how far this row's UTC offset is from the day's
          // (DST1: rows after a clock change on that day).
          var dz = r[17] || 0;
          rows.push([r[0], c.base + r[1] - dz, d[r[2]], d[r[3]], d[r[4]], d[r[5]], r[6], d[r[7]], r[8], r[9], d[r[10]], d[r[11]], r[12], d[r[13]], r[14], day, c.off + dz, d[r[15]] || '', d[r[16]] || '', p.ID]);
        });
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
  var TOO_OLD = 'This browser is too old to show the event list. Open events.zip in this report\'s folder instead, or use a current version of Edge, Chrome or Firefox.';

  Table.prototype.open = function () {
    if (this.loading) return;
    var self = this, p = this.page;
    if (!p.Days || !p.Days.length) { this.message('No events of this kind in this report.'); this.rows = []; this.count.textContent = ''; return; }
    if (tooOld) { this.message(TOO_OLD); return; }
    this.loading = true;
    this.message('Loading events…');
    loadRows(p, function (done, n) { self.message('Loading events… ' + done + ' of ' + n + ' days'); }).then(function (rows) {
      self.rows = rows;
      self.fitCols();
      self.options();
      if (self.want) self.setFilters(); else self.filter();
    }).catch(function (err) {
      self.loading = false;
      self.message('The events could not be read: ' + err.message + '. Open events.zip in this report\'s folder instead.');
    });
  };

  Table.prototype.message = function (text) {
    this.body.style.height = '';
    this.body.innerHTML = '<div class="vt-msg">' + esc(text) + '</div>';
  };

  Table.prototype.options = function () {
    var self = this;
    function fill(sel, col, label) {
      var seen = {};
      self.rows.forEach(function (r) { if (r[col]) seen[r[col]] = (seen[r[col]] || 0) + 1; });
      Object.keys(seen).sort(function (a, b) { return a.localeCompare(b); }).forEach(function (v) {
        var o = document.createElement('option'); o.value = v; o.textContent = (label ? label(v) : v) + ' (' + seen[v].toLocaleString() + ')';
        sel.appendChild(o);
      });
    }
    fill(this.el.querySelector('[data-f="host"]'), 2);
    fill(this.el.querySelector('[data-f="user"]'), 5);
    fill(this.el.querySelector('[data-f="day"]'), 15, dayLabel);
    var k = this.el.querySelector('[data-f="kind"]');
    if (k) fill(k, 17);
  };

  // apply sets the table's filters (from a stat card): kind, sev, host,
  // user, day, text, and flag ("New device", "First time", …). Unnamed
  // filters are cleared. It waits for the rows if they are still loading.
  Table.prototype.apply = function (f) {
    this.want = f;
    if (this.rows) this.setFilters();
  };
  Table.prototype.setFilters = function () {
    var f = this.want || {};
    this.want = null;
    this.el.querySelectorAll('[data-f]').forEach(function (x) {
      var v = f[x.getAttribute('data-f')] || '';
      if (x.tagName === 'SELECT' && v && !Array.prototype.some.call(x.options, function (o) { return o.value === v; })) {
        var o = document.createElement('option'); o.value = v; o.textContent = v.split('|').join(' or '); x.appendChild(o);
      }
      x.value = v;
    });
    this.flag = f.flag || '';
    var note = this.el.querySelector('[data-flagnote]');
    if (note) { note.hidden = !this.flag; note.querySelector('b').textContent = this.flag; }
    this.filter();
  };

  Table.prototype.filter = function () {
    if (!this.rows) return;
    var f = {}, flag = this.flag;
    this.el.querySelectorAll('[data-f]').forEach(function (x) { f[x.getAttribute('data-f')] = x.value; });
    var text = (f.text || '').toLowerCase(), kinds = f.kind ? f.kind.split('|') : null;
    this.shown = this.rows.filter(function (r) {
      if (f.sev && r[3] !== f.sev) return false;
      if (f.host && r[2] !== f.host) return false;
      if (f.user && r[5] !== f.user) return false;
      if (f.day && r[15] !== f.day) return false;
      if (kinds && kinds.indexOf(r[17]) < 0) return false;
      if (flag && (',' + r[14] + ',').indexOf(',' + flag + ',') < 0) return false;
      if (text) {
        var hay = (r[8] + ' ' + r[2] + ' ' + r[5] + ' ' + r[6] + ' ' + r[7] + ' ' + r[9] + ' ' + r[11] + ' ' + r[12] + ' ' + r[17] + ' ' + r[18]).toLowerCase();
        if (hay.indexOf(text) < 0) return false;
      }
      return true;
    });
    var all = this.rows.length, n = this.shown.length;
    this.count.textContent = n === all ? all.toLocaleString() + ' events' : n.toLocaleString() + ' of ' + all.toLocaleString() + ' events';
    this.body.style.height = (n * ROW_H) + 'px';
    this.box.scrollTop = 0;
    this.last = null;
    if (!n) { this.message(all ? 'No events match these filters.' : 'No events of this kind in this report.'); return; }
    this.draw();
  };

  // draw renders only the rows in view (plus a margin), so a page with
  // hundreds of thousands of events scrolls smoothly.
  Table.prototype.draw = function () {
    if (!this.shown.length) return;
    var top = this.box.scrollTop, h = this.box.clientHeight || 600;
    var first = Math.max(0, Math.floor(top / ROW_H) - 10), last = Math.min(this.shown.length, Math.ceil((top + h) / ROW_H) + 10);
    if (this.last && this.last[0] === first && this.last[1] === last) return;
    this.last = [first, last];
    var html = '';
    for (var i = first; i < last; i++) {
      var r = this.shown[i];
      html += '<div class="vt-row" data-i="' + i + '" style="top:' + (i * ROW_H) + 'px">' + this.cells(r) + '</div>';
    }
    this.body.innerHTML = html;
  };

  // A row's cells, in the page's columns.
  var FIELDS = {
    time: function (r) { return '<span class="mono">' + when(r[1], r[16]) + '</span>'; },
    host: function (r) { return '<span><b>' + esc(r[2]) + '</b></span>'; },
    user: function (r) { return '<span>' + esc(r[5]) + '</span>'; },
    account: function (r) { return '<span>' + esc(r[6] || r[5]) + '</span>'; },
    src: function (r) { return '<span class="mono">' + esc(r[7] || 'local') + '</span>'; },
    kind: function (r) { return '<span>' + esc(r[17]) + '</span>'; },
    x: function (r) { return '<span title="' + esc(r[18]) + '">' + esc(r[18]) + '</span>'; },
    cmd: function (r) { var c = (r[12] || r[8]).split('\n')[0]; return '<span class="mono" title="' + esc(c) + '">' + esc(c) + '</span>'; },
    sum: function (r, byPerson) {
      var s = r[8];
      if (byPerson && r[5] && s.indexOf(r[5] + ' ') === 0) {
        s = s.slice(r[5].length + 1);
        s = s.charAt(0).toUpperCase() + s.slice(1);
      }
      // Flags ("×7", "Late", "First time") first, so a long summary's
      // ellipsis never hides them (UX1).
      return '<span class="what" title="' + esc(r[8]) + '">' + (r[14] ? '<i class="flag">' + esc(r[14].split(',').join(' · ')) + '</i> ' : '') + esc(s) + '</span>';
    },
    sev: function (r) { return '<span>' + sevCell(r[3]) + '</span>'; },
    event: function (r) { var a = (r[4] || '').replace(/_/g, ' '); return '<span>' + esc(a.charAt(0).toUpperCase() + a.slice(1)) + '</span>'; }
  };
  var DEFAULT_COLS = [{ f: 'time' }, { f: 'host' }, { f: 'user' }, { f: 'sum' }, { f: 'sev' }];
  Table.prototype.cells = function (r) {
    var out = '', self = this;
    (this.cols || this.page.Cols || DEFAULT_COLS).forEach(function (c) {
      out += c.f === 'sum' && self.byPerson ? FIELDS.sum(r, true) : FIELDS[c.f](r);
    });
    return out;
  };

  // fitCols hides the columns that say nothing for this page's events
  // (UX7): Severity when no row is High or Medium, a Kind, Session or
  // From that is the same on every row. With a Person column, the
  // summary leaves out the person's name (the event panel keeps it).
  var FIT = {
    sev: function (r) { return r[3] === 'high' || r[3] === 'medium' ? r[3] : ''; },
    kind: function (r) { return r[17]; },
    x: function (r) { return r[18]; },
    src: function (r) { return r[7] || ''; }
  };
  var WIDTH = { time: '150px', sev: '90px', event: 'minmax(0,1.3fr)', sum: 'minmax(0,3fr)', cmd: 'minmax(0,3fr)' };
  Table.prototype.fitCols = function () {
    var cols = this.page.Cols || DEFAULT_COLS, rows = this.rows, head = this.el.querySelector('.vt-head');
    var keep = cols.filter(function (c, i) {
      var f = FIT[c.f], show = true;
      if (f && rows.length) {
        var first = f(rows[0]);
        show = !rows.every(function (r) { return f(r) === first; });
      }
      if (head && head.children[i]) head.children[i].hidden = !show;
      return show;
    });
    this.cols = keep;
    this.byPerson = keep.some(function (c) { return c.f === 'user'; });
    this.box.style.setProperty('--cols', keep.map(function (c) { return WIDTH[c.f] || 'minmax(0,1fr)'; }).join(' '));
  };

  // csvRows is the rows shown, header first, every time with its zone
  // (ASSESS1): the table's Export CSV and the Export menu's "This page".
  Table.prototype.csvRows = function () {
    var kind = (this.page.KindLabel || 'kind').toLowerCase();
    var rows = [['time', 'system', 'person', 'target', 'source', 'what happened', kind, 'severity', 'event id', 'log', 'process', 'command', 'outcome']];
    this.shown.forEach(function (r) {
      rows.push([when(r[1], r[16]) + ' ' + zoneOf(r[16]), r[2], r[5], r[6], r[7], r[8], r[17], r[3], r[9], r[10], r[11], r[12], r[13]].map(csvSafe));
    });
    return rows;
  };
  Table.prototype.csv = function () {
    if (!this.shown.length) return;
    save(this.page.ID + '-events' + (stamp ? '-' + stamp : '') + '.csv', toCSV(this.csvRows()));
  };

  // ---- Event panel ----
  var ov = document.querySelector('.ov'), drawer = document.querySelector('.drawer');
  function closeEvent() { ov.hidden = true; drawer.hidden = true; }
  ov.addEventListener('click', closeEvent);
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeEvent(); });

  function openEvent(table, i) {
    var r = table.shown[i], p = pageByID[r && r[19]] || table.page;
    if (!r) return;
    var det = meta.rowdet && meta.rowdet[r[0]];
    var cols = {};
    (p.Cols || []).forEach(function (c) { cols[c.f] = c.l; });
    var sys = r[2] + (meta.os && meta.os[r[2]] ? ' · ' + meta.os[r[2]] : '');
    var zip = meta.archives && meta.archives[r[2]];
    var rows = [['Time', when(r[1], r[16]) + ' ' + zoneOf(r[16])], ['System', sys], ['Person', r[5]], ['Account', r[6]], ['Source address', r[7]],
      [cols.x || '', r[18]], [cols.kind || p.KindLabel || 'Kind', r[17]], ['Program', r[11]], ['Command', r[12]], ['Outcome', r[13]],
      ['Original log', zip ? zip + ' › ' + (r[10] || '') : r[10]]];
    var kv = rows.filter(function (x) { return x[0] && x[1]; }).map(function (x) { return '<span>' + esc(x[0]) + '</span><b>' + esc(x[1]) + '</b>'; }).join('');
    var part = det !== undefined ? ' <a class="pm link" style="margin-left:10px" href="#detections/' + det + '">part of “' + esc(meta.dets[det]) + '”</a>' : '';
    var btn = function (href, ic, text) { return '<a class="btn" href="' + href + '">' + ((meta.icons || {})[ic] || '') + text + '</a>'; };
    var btns = '';
    if (r[7]) btns += btn('#search/' + encodeURIComponent(r[7]), 'search', 'Everything from ' + esc(r[7]));
    var who = r[5] || r[6];
    if (who) btns += btn('#people/' + encodeURIComponent(who), 'user-round', esc(who) + '’s page');
    btns += btn('#systems/' + encodeURIComponent(r[2]), 'server', esc(r[2]) + '’s page');
    if (det !== undefined) btns += btn('#detections/' + det, 'shield', 'Open detection');
    drawer.innerHTML = '<span class="x" tabindex="0">✕ Close</span><div class="pm" style="margin-bottom:4px">' + esc(p.Title) +
      (r[9] ? ' · event ' + esc(r[9]) : '') + (r[10] ? ' · ' + esc(r[10]) + ' log' : '') + '</div>' +
      '<h3>' + esc(r[8]) + '</h3>' + (SEV[r[3]] || part ? '<div style="margin-top:6px">' + (SEV[r[3]] ? sevCell(r[3]) : '') + part + '</div>' : '') + '<div class="kv3">' + kv + '</div>' +
      '<div class="raw">Loading the original event data…</div><div class="dbtns">' + btns + '</div>' +
      '<div class="sub2" style="margin-top:18px">2 minutes either side on ' + esc(r[2]) + '</div><div class="near">Loading…</div>';
    drawer.querySelector('.x').addEventListener('click', closeEvent);
    drawer.querySelectorAll('.dbtns a').forEach(function (a) { a.addEventListener('click', closeEvent); });
    ov.hidden = false; drawer.hidden = false;
    getData('raw/' + p.ID + '/' + r[15], p.ID + '-' + r[15] + '-raw.js').then(function (raw) {
      // The raw file lists the day's events in the same order as its data file.
      return getData(p.ID + '/' + r[15], p.ID + '-' + r[15] + '.js').then(function (c) {
        for (var k = 0; k < c.rows.length; k++) if (c.rows[k][0] === r[0]) return raw[k];
      });
    }).then(function (x) {
      var box = drawer.querySelector('.raw');
      if (!box) return;
      if (!x) { box.textContent = 'No original event data.'; return; }
      var tm = drawer.querySelector('.kv3 b');
      if (x[3] && tm) tm.textContent = x[3];
      var out = '';
      (x[0] || []).forEach(function (d) { out += '<span class="t">' + esc(d.label) + ':</span> <span class="v">' + esc(d.value) + '</span>\n'; });
      var f = x[1] || {};
      Object.keys(f).forEach(function (k) { out += '<span class="t">' + esc(k) + '</span> <span class="v">' + esc(f[k]) + '</span>\n'; });
      if (x[2]) out = '<span class="t">Recorded as:</span> <span class="v">' + esc(x[2]) + '</span>\n' + out;
      box.innerHTML = out || 'No original event data.';
    }).catch(function (err) {
      var box = drawer.querySelector('.raw');
      if (box) box.textContent = 'The original event data could not be read: ' + err.message;
    });
    nearby(r);
  }

  // nearby lists every event (on any page) on the same system within two
  // minutes of r.
  function nearby(r) {
    var t0 = r[1], host = r[2], found = [];
    var jobs = (meta.pages || []).filter(function (p) { return (p.Days || []).indexOf(r[15]) >= 0; }).map(function (p) {
      return getData(p.ID + '/' + r[15], p.ID + '-' + r[15] + '.js').then(function (c) {
        var d = c.dict, h = c.dict.indexOf(host);
        if (h < 0) return;
        c.rows.forEach(function (x) {
          var t = c.base + x[1] - (x[17] || 0);
          if (x[2] === h && Math.abs(t - t0) <= 120) found.push({ i: x[0], t: t, sum: x[8], user: d[x[5]], page: p.Title });
        });
      });
    });
    Promise.all(jobs).then(function () {
      var box = drawer.querySelector('.near');
      if (!box) return;
      found.sort(function (a, b) { return a.t - b.t || a.i - b.i; });
      // Keep the ones closest to this event.
      var at = 0;
      found.forEach(function (x, k) { if (x.i === r[0]) at = k; });
      var list = found.slice(Math.max(0, at - 6), at + 7);
      box.innerHTML = list.map(function (x) {
        var me = x.i === r[0];
        return '<div' + (me ? ' class="me"' : '') + '><span class="mono">' + when(x.t, r[16]).slice(7) + '</span><span>' +
          (me ? '<b>This event</b>' : esc(x.sum) + ' <small>' + esc(x.page) + '</small>') + '</span></div>';
      }).join('') + (found.length > list.length ? '<p class="pm">' + (found.length - list.length) + ' more in this time on ' + esc(host) + '.</p>' : '');
    }).catch(function () {
      var box = drawer.querySelector('.near');
      if (box) box.textContent = 'Could not read the nearby events.';
    });
  }

  // ---- Search: the sentence builder, over every page's data files ----
  var search = (function () {
    var panel = document.querySelector('[data-search]');
    if (!panel) return null;
    var q = {};
    document.querySelectorAll('[data-q]').forEach(function (el) { if (el.getAttribute('data-q')) q[el.getAttribute('data-q')] = el; });
    var st = Object.create(Table.prototype);
    st.page = { ID: 'search', Title: 'Search', Cols: [{ f: 'time' }, { f: 'host' }, { f: 'event' }, { f: 'user' }, { f: 'sum' }, { f: 'sev' }], KindLabel: 'kind' };
    st.el = panel; st.body = panel.querySelector('.vt-body'); st.box = panel.querySelector('.vt'); st.count = panel.querySelector('[data-count]');
    st.rows = []; st.shown = [];
    st.box.addEventListener('scroll', function () { st.draw(); });
    st.body.addEventListener('click', function (e) { var r = e.target.closest('[data-i]'); if (r) openEvent(st, +r.getAttribute('data-i')); });
    panel.querySelector('[data-csv]').addEventListener('click', function () { st.csv(); });
    var extra = null, sortBy = 'new', ran = false, seq = 0;

    function key(u) { u = (u || '').toLowerCase(); var i = u.lastIndexOf('\\'); if (i >= 0) u = u.slice(i + 1); i = u.indexOf('@'); return i > 0 ? u.slice(0, i) : u; }
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
    function run() {
      syncCats();
      if (tooOld) { st.message(TOO_OLD); return; }
      ran = true;
      var my = ++seq, pages = (meta.pages || []).filter(function (p) { return !q.page.value || p.ID === q.page.value; });
      st.message('Searching…');
      var all = [];
      Promise.all(pages.map(function (p) { return loadRows(p).then(function (rows) { all.push(rows); }); })).then(function () {
        if (my !== seq) return;
        var user = q.user.value, host = q.host.value, when = q.when.value, text = q.text.value.toLowerCase(), kinds = meta.hostKind || {};
        var out = [];
        all.forEach(function (rows) {
          rows.forEach(function (r) {
            if (user && key(r[5]) !== user) return;
            if (host && (host.charAt(0) === '@' ? kinds[r[2]] !== host.slice(1) : r[2] !== host)) return;
            if (when && (when === '@after' ? !afterHours(r) : when.indexOf('@slot:') === 0 ? !inSlot(r, when.slice(6)) : r[15] !== when)) return;
            if (extra && !extra(r)) return;
            if (text) {
              var hay = (r[8] + ' ' + r[2] + ' ' + r[5] + ' ' + r[6] + ' ' + r[7] + ' ' + r[9] + ' ' + r[11] + ' ' + r[12] + ' ' + r[17] + ' ' + r[18]).toLowerCase();
              if (hay.indexOf(text) < 0) return;
            }
            out.push(r);
          });
        });
        st.rows = out;
        order();
      }).catch(function (err) { st.message('The events could not be read: ' + err.message); });
    }
    function order() {
      var out = st.rows;
      if (sortBy === 'src') out.sort(function (a, b) { return (a[7] || 'local').localeCompare(b[7] || 'local', undefined, { numeric: true }) || b[1] - a[1]; });
      else if (sortBy === 'host') out.sort(function (a, b) { return a[2].localeCompare(b[2], undefined, { numeric: true }) || b[1] - a[1]; });
      else out.sort(function (a, b) { return b[1] - a[1] || b[0] - a[0]; });
      st.shown = out;
      var hosts = {};
      out.forEach(function (r) { hosts[r[2]] = 1; });
      var nh = Object.keys(hosts).length, who = q.user.value ? ' by ' + q.user.options[q.user.selectedIndex].text : '';
      panel.querySelector('[data-title] span').textContent = out.length.toLocaleString() + (out.length === 1 ? ' event' : ' events') + who +
        ' on ' + nh + (nh === 1 ? ' system' : ' systems');
      st.count.textContent = '';
      hist(out);
      st.body.style.height = (out.length * ROW_H) + 'px';
      st.box.scrollTop = 0; st.last = null;
      if (!out.length) { st.message('Nothing matches this search.'); return; }
      st.draw();
    }
    // A histogram of matches across the period, by hour.
    function hist(rows) {
      var box = panel.querySelector('[data-hist]'), days = [];
      (meta.pages || []).forEach(function (p) { (p.Days || []).forEach(function (d) { if (days.indexOf(d) < 0) days.push(d); }); });
      days.sort();
      if (!rows.length || !days.length) { box.innerHTML = ''; return; }
      var n = days.length * 24, b = new Array(n).fill(0), top = 1;
      rows.forEach(function (r) {
        var d = days.indexOf(r[15]);
        if (d < 0) return;
        var h = new Date((r[1] + r[16]) * 1000).getUTCHours(), i = d * 24 + h;
        b[i]++; if (b[i] > top) top = b[i];
      });
      var W = 1000, H = 60, bw = W / n, svg = '';
      b.forEach(function (v, i) { if (v) svg += '<rect x="' + (i * bw).toFixed(1) + '" y="' + (H - 16 - v / top * (H - 20)).toFixed(1) + '" width="' + Math.max(1, bw - 1).toFixed(1) + '" height="' + (v / top * (H - 20)).toFixed(1) + '" fill="#0B5FFF" opacity=".75"/>'; });
      // Day labels in HTML so they keep their shape; at most eight.
      var step = Math.ceil(days.length / 8), lab = '';
      days.forEach(function (d, k) {
        if (k % step !== 0) return;
        lab += '<span style="left:' + (k / days.length * 100).toFixed(2) + '%">' + dayLabel(d) + '</span>';
        // A short period also gets times of day (UX9).
        if (days.length <= 3) [6, 12, 18].forEach(function (h) {
          lab += '<span style="left:' + ((k * 24 + h) / n * 100).toFixed(2) + '%">' + (h < 10 ? '0' : '') + h + ':00</span>';
        });
      });
      box.innerHTML = '<svg viewBox="0 0 ' + W + ' ' + (H - 16) + '" width="100%" height="' + (H - 16) + '" preserveAspectRatio="none" role="img" aria-label="' +
        rows.length + ' matching events by hour over the period">' + svg + '</svg><div class="cbar-l">' + lab + '</div>';
    }
    Object.keys(q).forEach(function (k) {
      q[k].addEventListener(k === 'text' ? 'input' : 'change', function () { extra = null; run(); });
    });
    // Category chips (UX9): the same as choosing the kind of event.
    var cats = document.querySelectorAll('[data-cats] [data-cat]');
    function syncCats() { if (cats) cats.forEach(function (c) { c.classList.toggle('on', c.getAttribute('data-cat') === (q.page ? q.page.value : '')); }); }
    cats.forEach(function (c) {
      c.addEventListener('click', function () {
        if (!q.page) return;
        q.page.value = c.getAttribute('data-cat');
        q.page.dispatchEvent(new Event('change'));
      });
    });
    if (q.page) q.page.addEventListener('change', syncCats);
    // Sort: newest, by system, or (failed logons by source) by address.
    function setSort(by) {
      sortBy = by;
      panel.querySelectorAll('[data-sort]').forEach(function (x) { x.classList.toggle('on', x.getAttribute('data-sort') === by); });
    }
    panel.querySelectorAll('[data-sort]').forEach(function (c) {
      c.addEventListener('click', function () { setSort(c.getAttribute('data-sort')); if (ran) order(); });
    });
    var PS_DOWNLOAD = /downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|net\.webclient|start-bitstransfer|wget|curl/i;
    var presets = {
      person: { user: meta.firstPerson || '' },
      usbservers: { page: 'usb', host: '@server' },
      afterhours: { page: 'privileged', when: '@after' },
      failedsource: { page: 'failed', sort: 'src' },
      admingroups: { page: 'accounts', extra: function (r) { return /^group_member/.test(r[4]); } },
      audit: { page: 'integrity' },
      psdownload: { page: 'powershell', extra: function (r) { return PS_DOWNLOAD.test(r[12] + ' ' + r[8]); } },
      rdp: { page: 'logons', extra: function (r) { return r[17] === 'Remote Desktop'; } }
    };
    document.querySelectorAll('[data-preset]').forEach(function (a) {
      a.addEventListener('click', function () {
        var pr = presets[a.getAttribute('data-preset')];
        ['page', 'user', 'host', 'when'].forEach(function (k) { q[k].value = pr[k] || ''; });
        q.text.value = '';
        extra = pr.extra || null;
        setSort(pr.sort || 'new');
        run();
      });
    });
    return {
      table: st,
      // From a link: #search/<text>
      // From a link: #search?page=…&user=…&host=…&when=…&text=…
      query: function (qs) {
        var params = {};
        qs.split('&').forEach(function (kv) {
          var i = kv.indexOf('=');
          if (i > 0) params[decodeURIComponent(kv.slice(0, i))] = decodeURIComponent(kv.slice(i + 1).replace(/\+/g, ' '));
        });
        ['page', 'user', 'host', 'when', 'text'].forEach(function (k) {
          var el = q[k], v = params[k] || '';
          if (el.tagName === 'SELECT' && v && !Array.prototype.some.call(el.options, function (o) { return o.value === v; })) {
            var o = document.createElement('option'); o.value = v; o.textContent = v.indexOf('@slot:') === 0 ? slotLabel(v.slice(6)) : v; el.appendChild(o); // e.g. an account not on People
          }
          el.value = v;
        });
        extra = null; setSort(params.sort || 'new'); run();
      },
      open: function (text) {
        if (text) {
          ['page', 'user', 'host', 'when'].forEach(function (k) { q[k].value = ''; });
          extra = null; q.text.value = text; run();
        } else if (!ran) {
          run(); // nothing chosen yet: every event, newest first
        }
      }
    };
  })();

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
    if (tables[id]) return tables[id].shown.length ? { label: tables[id].page.Title + ' shown', file: id + '-events', rows: tables[id].csvRows() } : null;
    if (id === 'search') return search && search.table.shown.length ? { label: 'Search results', file: 'search', rows: search.table.csvRows() } : null;
    var f = meta.pagecsv && meta.pagecsv[id];
    return f ? { label: f.label, file: f.file, rows: f.rows } : null;
  }
  // Detections: the ones the severity filter shows.
  BB.exportPage('detections', function () {
    var f = meta.pagecsv && meta.pagecsv.detections;
    if (!f) return null;
    var on = document.querySelector('[data-detsev] .on'), sev = on ? on.getAttribute('data-sev') : '';
    var rows = f.rows.filter(function (r, i) { return i === 0 || !sev || r[0] === sev; });
    return { label: f.label, file: f.file + (sev ? '-' + sev : ''), rows: rows };
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
    loadRows(p).then(function (rows) {
      for (var k = 0; k < rows.length; k++) {
        if (rows[k][0] === idx) { openEvent({ shown: [rows[k]], page: p }, 0); return; }
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

  window.addEventListener('hashchange', show);
  show();
})();
