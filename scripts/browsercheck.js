// Opens a report in a headless browser and checks every page works: no
// script errors, Search and the event pages fill from the data files, a
// row opens the event panel, Search finds events, and each list page shows an item.
//
//   node scripts/browsercheck.js <report folder> [chrome path]
//
// Needs playwright-core (npm i --no-save playwright-core).
const path = require('path');
let pw;
try { pw = require('playwright-core'); } catch (e) { pw = require('playwright'); }

(async () => {
  const dir = path.resolve(process.argv[2] || '.');
  const exe = process.argv[3] || process.env.CHROME || undefined;
  const browser = await pw.chromium.launch({ executablePath: exe });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
  const fail = msg => { console.error('FAIL: ' + msg); process.exitCode = 1; };
  const url = 'file://' + path.join(dir, 'report.html');

  await page.goto(url);
  const views = await page.$$eval('.view', v => v.map(x => x.getAttribute('data-view')));
  for (const v of views) {
    await page.goto(url + '#' + v);
    await page.waitForTimeout(150);
    const shown = await page.$eval('.view[data-view="' + v + '"]', el => !el.hidden && el.innerText.trim().length > 40);
    if (!shown) fail('page ' + v + ' is empty');
    // Search and each event page (Search with its kind preset): the
    // results fill from the data files, and a row opens the event panel.
    if (await page.$('.view[data-view="' + v + '"] [data-sq]')) {
      try {
        await page.waitForSelector('.view[data-view="' + v + '"] tr[data-i]', { timeout: 20000 });
      } catch (e) { fail('results on ' + v + ' did not fill'); continue; }
      await page.click('.view[data-view="' + v + '"] tr[data-i]');
      await page.waitForSelector('.drawer:not([hidden]) .raw', { timeout: 5000 }).catch(() => fail('event panel on ' + v + ' did not open'));
      await page.waitForFunction(() => !/Loading/.test(document.querySelector('.drawer .raw').textContent), null, { timeout: 10000 })
        .catch(() => fail('the raw record on ' + v + ' did not load'));
      await page.keyboard.press('Escape');
    }
  }
  for (const v of ['systems', 'detections', 'people']) {
    await page.goto(url + '#' + v);
    await page.waitForTimeout(150);
    const n = await page.$$eval('.view[data-view="' + v + '"] [data-pane]:not([hidden])', x => x.length);
    if (await page.$('.view[data-view="' + v + '"] [data-pick]') && n !== 1) fail(v + ': no item shown');
  }
  await page.goto(url + '#search');
  await page.click('.view[data-view="search"] [data-common]');
  await page.click('[data-preset="person"]');
  await page.waitForFunction(() => /^\d[\d,]* events? · /.test(document.querySelector('.view[data-view="search"] [data-qhead]').textContent) &&
    /user=/.test(location.hash), null, { timeout: 30000 })
    .catch(() => fail('Search found nothing'));
  await page.goto(url + '#health');
  await page.click('aside [data-vline]');
  if (await page.$eval('[data-vhead]', h => h.classList.contains('bad'))) fail('Verified is red');
  // Audit health's tabs (UI-R1): a link opens its tab, a click another.
  if (await page.$('[data-htabs]')) {
    await page.goto(url + '#health/@systems');
    await page.waitForTimeout(150);
    if (!await page.$('[data-hpane="systems"]:not([hidden]) #h-matrix')) fail('#health/@systems did not open By system');
    await page.click('[data-htab="settings"]');
    if (!await page.$('[data-hpane="settings"]:not([hidden])')) fail('the Settings to fix tab did not open');
  }
  // Original logs: Gaps and missing hides the complete systems.
  if (await page.$('[data-lfilter="gaps"]')) {
    await page.goto(url + '#logs');
    await page.click('[data-lfilter="gaps"]');
    if (await page.$('[data-lrow][data-ok]:not([hidden])')) fail('Gaps and missing still shows complete systems');
  }

  // Every link inside the report leads to a page that exists, and a link
  // to one event opens its panel.
  await page.goto(url + '#overview');
  const bad = await page.$$eval('a[href^="#"]', (as, views) => as.map(a => a.getAttribute('href'))
    .filter(h => h.length > 1 && views.indexOf(h.slice(1).split(/[/?]/)[0]) < 0), views);
  if (bad.length) fail('links to pages that do not exist: ' + Array.from(new Set(bad)).slice(0, 10).join(', '));
  await page.goto(url + '#detections');
  const ev = await page.$('.view[data-view="detections"] [data-pane]:not([hidden]) [data-ev]');
  if (ev) {
    await ev.click();
    await page.waitForSelector('.drawer:not([hidden]) h3', { timeout: 10000 }).catch(() => fail('a link to an event did not open its panel'));
  }

  // Every page fits a narrow window (half a 1440p screen, a small laptop)
  // without scrolling sideways.
  await page.setViewportSize({ width: 960, height: 900 });
  for (const v of views) {
    await page.goto(url + '#' + v);
    await page.waitForTimeout(150);
    const over = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    if (over > 1) fail('page ' + v + ' scrolls sideways at 960px (' + over + 'px too wide)');
  }

  if (errors.length) fail('script errors:\n  ' + errors.join('\n  '));
  if (!process.exitCode) console.log('OK: ' + views.length + ' pages');
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
