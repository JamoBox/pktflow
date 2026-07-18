#!/usr/bin/env node
// 12.5 windowed-mode browser check (scheduled/manual tier, like the RSS
// ceilings): drives the real SPA in Chromium against a live
// `pktflow serve` whose capture is over the D17.4 gate, asserting the
// windowed tree pages/expands/queries, the timeline draws as canvas
// density, and the DOM stays viewport-bounded.
//
//   # serve something over the 20k-stream gate, e.g.:
//   pktflow serve -r scale-1m.pcap -c 100000 --no-condense --listen 127.0.0.1:18327 &
//   npm i playwright-core && node scripts/webui-scale-check.mjs http://127.0.0.1:18327/
//
// Chromium comes from PLAYWRIGHT_BROWSERS_PATH or the path below.
// Resolved from the invoking directory (where `npm i playwright-core`
// ran), so the repo itself needs no node_modules.
import { createRequire } from 'module';
const { chromium } = createRequire(process.cwd() + '/')('playwright-core');

(async () => {
  const url = process.argv[2] || 'http://127.0.0.1:18327/';
  const exe = process.env.PKTFLOW_CHROMIUM
    || '/opt/pw-browsers/chromium-1194/chrome-linux/chrome';
  const browser = await chromium.launch({ executablePath: exe, args: ['--no-sandbox'] });
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push('pageerror: ' + e.message));
  page.on('console', m => { if (m.type() === 'error') errors.push('console: ' + m.text()); });

  await page.goto(url, { waitUntil: 'domcontentloaded' });
  // Wait for windowed rows to arrive.
  try {
    await page.waitForSelector('#tree .row[data-id]', { timeout: 15000 });
  } catch (e) {
    console.log('FAIL no rows rendered');
    console.log('breadcrumbs:', await page.evaluate(() => (window.WDBG || []).join(' | ')));
    console.log('errors:', errors.join(' ; '));
    await browser.close();
    process.exit(1);
  }
  const rowCount = await page.locator('#tree .row[data-id]').count();
  console.log('PASS rows rendered:', rowCount);

  // Expand the first root → children fetched on demand.
  await page.locator('#tree .row[data-id] .caret.toggle').first().click();
  await page.waitForTimeout(600);
  const afterExpand = await page.locator('#tree .row[data-id]').count();
  console.log(afterExpand > rowCount ? 'PASS expand loads children:' : 'FAIL expand:', afterExpand);

  // Select a row → detail fetched.
  await page.locator('#tree .row[data-id]').nth(1).click();
  await page.waitForTimeout(400);
  const detail = await page.locator('#detail .dcard').count();
  console.log(detail > 0 ? 'PASS detail renders:' : 'FAIL detail:', detail, 'cards');

  // Query round-trip.
  await page.fill('#filter', 'proto == udp');
  await page.waitForTimeout(800);
  const status = await page.locator('#queryStatus').textContent();
  console.log(/match/.test(status) ? 'PASS query status:' : 'FAIL query status:', status.trim());
  await page.fill('#filter', '');
  await page.waitForTimeout(600);

  // Server-side sort round-trip.
  await page.selectOption('#sortSel', 'packets');
  await page.waitForTimeout(700);
  const afterSort = await page.locator('#tree .row[data-id]').count();
  console.log(afterSort > 0 ? 'PASS sort round-trip:' : 'FAIL sort round-trip:', afterSort, 'rows');

  // Timeline tab → canvas density.
  await page.click('#tabs button[data-tab="timeline"]');
  await page.waitForTimeout(1200);
  const canvas = await page.locator('#tlScroll canvas').count();
  console.log(canvas === 1 ? 'PASS timeline canvas' : 'FAIL timeline canvas: ' + canvas);

  // DOM stays viewport-bounded after scrolling the tree.
  await page.click('#tabs button[data-tab="streams"]');
  await page.waitForTimeout(300);
  await page.evaluate(() => { const t = document.querySelector('#tree'); t.scrollTop = t.scrollHeight; });
  await page.waitForTimeout(900);
  const afterScroll = await page.locator('#tree .row').count();
  console.log(afterScroll < 200 ? 'PASS DOM viewport-bounded:' : 'FAIL DOM rows:', afterScroll);

  console.log('js errors:', errors.length ? errors.join(' ; ') : 'none');
  await browser.close();
})().catch(e => { console.log('SCRIPT ERROR', e.message); process.exit(1); });
