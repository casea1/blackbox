// Opens a report in a headless browser and checks every page works: no
// script errors, the event tables fill from the data files, a row opens
// the event panel, Search finds events, and each list page shows an item.
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
    const events = await page.$('.view[data-view="' + v + '"] [data-events]');
    if (events) {
      const total = await page.$eval('.view[data-view="' + v + '"] [data-events] h2', h => h.textContent);
      if (/· 0$/.test(total.trim())) continue;
      try {
        await page.waitForSelector('.view[data-view="' + v + '"] .vt-row', { timeout: 20000 });
      } catch (e) { fail('event table on ' + v + ' did not fill'); continue; }
      await page.click('.view[data-view="' + v + '"] .vt-row');
      await page.waitForSelector('.drawer:not([hidden]) .raw', { timeout: 5000 }).catch(() => fail('event panel on ' + v + ' did not open'));
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
  await page.click('[data-preset="person"]');
  await page.waitForFunction(() => /\d.* events? /.test(document.querySelector('[data-title] span').textContent), null, { timeout: 30000 })
    .catch(() => fail('Search found nothing'));
  await page.goto(url + '#health');
  await page.click('aside [data-vline]');
  if (await page.$eval('[data-vhead]', h => h.classList.contains('bad'))) fail('Verified is red');

  // Trends: the range switch shows that range's page and breadcrumb.
  await page.goto(url + '#trends');
  if (await page.$('[data-trange="4"]')) {
    await page.click('[data-trange="4"]');
    const four = await page.evaluate(() => {
      const v = document.querySelector('.view[data-view="trends"]'), on = v.querySelector('[data-trview]:not([hidden])');
      return on && on.getAttribute('data-trview') === '4' && v.querySelector('.head .crumb').textContent.indexOf(on.getAttribute('data-crumb')) >= 0;
    });
    if (!four) fail('Trends: 4 weeks did not show its weeks');
    await page.click('[data-trange="8"]');
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
