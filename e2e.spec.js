const { test, expect } = require('@playwright/test');

async function openTrips(page){
  await page.goto('/#home');
  await page.locator('a[data-nav="trips"]').click();
  await expect(page).toHaveURL(/#trips/);
}

test('smoke: app loads and core views render', async ({ page }) => {
  await page.goto('/#home');
  await expect(page.getByText('Freight Logic', { exact: false })).toBeVisible();

  // Navigate between key tabs
  await page.locator('a[data-nav="trips"]').click();
  await expect(page).toHaveURL(/#trips/);
  await expect(page.locator('#tripList')).toBeVisible();

  await page.locator('a[data-nav="money"]').click();
  await expect(page).toHaveURL(/#money/);

  await page.locator('a[data-nav="more"]').click();
  await expect(page).toHaveURL(/#more/);
});

test('create a trip then verify it appears in list', async ({ page }) => {
  await openTrips(page);

  // Open Quick Add sheet from FAB
  await page.locator('#fab').click();
  await expect(page.locator('#qaTrip')).toBeVisible();

  // Open Trip wizard
  await page.locator('#qaTrip').click();
  await expect(page.locator('#saveTrip')).toBeVisible();

  // Fill required fields (minimal set)
  const orderNo = 'E2E-' + Date.now();
  await page.fill('#f_orderNo', orderNo);
  await page.fill('#f_pay', '650');
  await page.fill('#f_loaded', '320');
  await page.fill('#f_empty', '40');
  await page.fill('#f_customer', 'E2E Broker');
  await page.fill('#f_origin', 'Kansas City, MO');
  await page.fill('#f_dest', 'St. Louis, MO');
  // pickup date (ISO yyyy-mm-dd)
  await page.fill('#f_pickup', new Date().toISOString().slice(0,10));

  await page.locator('#saveTrip').click();

  // Trip should show up in list
  await expect(page.locator('#tripList')).toContainText(orderNo);
});

test('Nav button opens a maps URL', async ({ page }) => {
  await openTrips(page);

  // Create a trip quickly via wizard
  await page.locator('#fab').click();
  await page.locator('#qaTrip').click();

  const orderNo = 'NAV-' + Date.now();
  await page.fill('#f_orderNo', orderNo);
  await page.fill('#f_pay', '700');
  await page.fill('#f_loaded', '300');
  await page.fill('#f_empty', '20');
  await page.fill('#f_origin', 'Chicago, IL');
  await page.fill('#f_dest', 'Indianapolis, IN');
  await page.fill('#f_pickup', new Date().toISOString().slice(0,10));
  await page.locator('#saveTrip').click();

  const row = page.locator('#tripList .item', { hasText: orderNo }).first();
  await expect(row).toBeVisible();

  // Click Nav and capture popup
  const [popup] = await Promise.all([
    page.waitForEvent('popup'),
    row.locator('button[data-act="nav"]').click(),
  ]);

  await popup.waitForLoadState('domcontentloaded');

  const url = popup.url();
  expect(url).toMatch(/maps\.apple\.com|google\.com\/maps|google\.com\/maps\/dir|www\.google\.com\/maps/);
});

test('offline mode: app still renders home and trips list', async ({ page, context }) => {
  await page.goto('/#home');
  await expect(page.locator('#view-home')).toBeVisible();

  // Simulate offline
  await context.setOffline(true);

  // Navigate while offline
  await page.locator('a[data-nav="trips"]').click();
  await expect(page.locator('#tripList')).toBeVisible();

  // Back online for cleanup
  await context.setOffline(false);
});
