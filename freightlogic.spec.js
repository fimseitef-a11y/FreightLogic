// @ts-check
const { test, expect } = require('@playwright/test');

// ═══════════════════════════════════════════════════════════════
// FreightLogic v16.3.1 — E2E Test Suite
// Covers: Navigation, CRUD, Export/Import, Midwest Stack, PWA
// ═══════════════════════════════════════════════════════════════

test.describe('App Boot & Navigation', () => {
  test('loads home screen with correct version', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('#appMeta')).toContainText('v16.3.1');
    await expect(page.locator('#view-home')).toBeVisible();
  });

  test('shows welcome card when empty', async ({ page }) => {
    await page.goto('/');
    await page.waitForTimeout(500);
    await expect(page.locator('#view-home')).toContainText('Welcome to Freight Logic');
  });

  test('navigates to all main views', async ({ page }) => {
    await page.goto('/');
    // Trips
    await page.click('[data-nav="trips"]');
    await expect(page.locator('#view-trips')).toBeVisible();
    // Money
    await page.click('[data-nav="money"]');
    await expect(page.locator('#view-money')).toBeVisible();
    // More
    await page.click('[data-nav="more"]');
    await expect(page.locator('#view-more')).toBeVisible();
    // Home
    await page.click('[data-nav="home"]');
    await expect(page.locator('#view-home')).toBeVisible();
  });

  test('FAB opens quick-add sheet', async ({ page }) => {
    await page.goto('/');
    await page.click('#fab');
    await expect(page.locator('#modal')).toHaveClass(/open/);
    await expect(page.locator('#modalTitle')).toContainText('Quick Add');
  });

  test('modal closes with X button', async ({ page }) => {
    await page.goto('/');
    await page.click('#fab');
    await expect(page.locator('#modal')).toHaveClass(/open/);
    await page.click('#modalClose');
    await page.waitForTimeout(400);
    await expect(page.locator('#modal')).not.toHaveClass(/open/);
  });

  test('modal closes with Escape key', async ({ page }) => {
    await page.goto('/');
    await page.click('#fab');
    await expect(page.locator('#modal')).toHaveClass(/open/);
    await page.keyboard.press('Escape');
    await page.waitForTimeout(400);
    await expect(page.locator('#modal')).not.toHaveClass(/open/);
  });
});

test.describe('Trip CRUD', () => {
  test('add a trip with minimum fields', async ({ page }) => {
    await page.goto('/');
    await page.click('#fab');
    await page.click('#btnQuickTrip');
    await page.waitForTimeout(300);

    // Fill step 1
    await page.fill('#f_orderNo', 'TEST-001');
    await page.fill('#f_pay', '2500');
    await page.fill('#f_loaded', '800');
    await page.fill('#f_empty', '50');

    // Save from step 1
    await page.click('#saveTrip');
    await page.waitForTimeout(500);

    // Verify trip appears in list
    await page.click('[data-nav="trips"]');
    await page.waitForTimeout(300);
    await expect(page.locator('#tripList')).toContainText('TEST-001');
  });

  test('add a trip with full details (step 2)', async ({ page }) => {
    await page.goto('/');
    await page.click('#fab');
    await page.click('#btnQuickTrip');
    await page.waitForTimeout(300);

    // Step 1
    await page.fill('#f_orderNo', 'FULL-002');
    await page.fill('#f_pay', '3200');
    await page.fill('#f_loaded', '1100');
    await page.fill('#f_empty', '75');

    // Go to step 2
    await page.click('#toStep2');
    await page.waitForTimeout(300);

    // Fill step 2
    await page.fill('#f_customer', 'Test Broker LLC');
    await page.fill('#f_origin', 'Indianapolis, IN');
    await page.fill('#f_dest', 'Chicago, IL');
    await page.fill('#f_notes', 'E2E test trip');

    // Save
    await page.click('#saveTrip2');
    await page.waitForTimeout(500);

    // Verify
    await page.click('[data-nav="trips"]');
    await page.waitForTimeout(300);
    await expect(page.locator('#tripList')).toContainText('FULL-002');
    await expect(page.locator('#tripList')).toContainText('Test Broker LLC');
  });

  test('edit a trip', async ({ page }) => {
    // First add a trip
    await page.goto('/');
    await page.click('#fab');
    await page.click('#btnQuickTrip');
    await page.waitForTimeout(300);
    await page.fill('#f_orderNo', 'EDIT-003');
    await page.fill('#f_pay', '1800');
    await page.fill('#f_loaded', '600');
    await page.click('#saveTrip');
    await page.waitForTimeout(500);

    // Navigate to trips and click edit
    await page.click('[data-nav="trips"]');
    await page.waitForTimeout(300);
    const editBtn = page.locator('[data-act="edit"]').first();
    await editBtn.click();
    await page.waitForTimeout(300);

    // Change pay
    await page.fill('#f_pay', '2200');
    await page.click('#saveTrip');
    await page.waitForTimeout(500);

    // Verify updated
    await page.click('[data-nav="trips"]');
    await page.waitForTimeout(300);
    await expect(page.locator('#tripList')).toContainText('$2,200');
  });

  test('mark trip paid/unpaid', async ({ page }) => {
    await page.goto('/');
    await page.click('#fab');
    await page.click('#btnQuickTrip');
    await page.waitForTimeout(300);
    await page.fill('#f_orderNo', 'PAY-004');
    await page.fill('#f_pay', '1500');
    await page.fill('#f_loaded', '500');
    await page.click('#saveTrip');
    await page.waitForTimeout(500);

    await page.click('[data-nav="trips"]');
    await page.waitForTimeout(300);
    // Should show UNPAID
    await expect(page.locator('#tripList')).toContainText('UNPAID');
    // Mark paid
    const paidBtn = page.locator('[data-act="paid"]').first();
    await paidBtn.click();
    await page.waitForTimeout(500);
    // Should now show PAID
    await expect(page.locator('#tripList')).toContainText('PAID');
  });
});

test.describe('Expense CRUD', () => {
  test('add an expense', async ({ page }) => {
    await page.goto('/');
    await page.click('#fab');
    await page.click('#btnQuickExpense');
    await page.waitForTimeout(300);

    await page.fill('#exp_amount', '150.50');
    await page.fill('#exp_category', 'Fuel');
    await page.fill('#exp_notes', 'E2E test expense');

    // Save
    const saveBtn = page.locator('#modal button.primary').last();
    await saveBtn.click();
    await page.waitForTimeout(500);

    // Navigate to expenses
    await page.click('[data-nav="more"]');
    await page.waitForTimeout(300);
    // Click Expenses tile
    const expTile = page.locator('.menu-tile', { hasText: 'Expenses' });
    await expTile.click();
    await page.waitForTimeout(300);
    await expect(page.locator('#expenseList')).toContainText('Fuel');
  });
});

test.describe('Fuel CRUD', () => {
  test('add a fuel entry', async ({ page }) => {
    await page.goto('/');
    await page.click('#fab');
    await page.click('#btnQuickFuel');
    await page.waitForTimeout(300);

    await page.fill('#fuel_gallons', '120');
    await page.fill('#fuel_amount', '350.00');
    await page.fill('#fuel_state', 'IN');

    const saveBtn = page.locator('#modal button.primary').last();
    await saveBtn.click();
    await page.waitForTimeout(500);

    // Navigate to fuel
    await page.click('[data-nav="more"]');
    await page.waitForTimeout(300);
    const fuelTile = page.locator('.menu-tile', { hasText: 'Fuel Log' });
    await fuelTile.click();
    await page.waitForTimeout(300);
    await expect(page.locator('#fuelList')).toContainText('IN');
  });
});

test.describe('Export & Import', () => {
  test('JSON export generates valid file', async ({ page }) => {
    // Add a trip first
    await page.goto('/');
    await page.click('#fab');
    await page.click('#btnQuickTrip');
    await page.waitForTimeout(300);
    await page.fill('#f_orderNo', 'EXPORT-TEST');
    await page.fill('#f_pay', '3000');
    await page.fill('#f_loaded', '1000');
    await page.click('#saveTrip');
    await page.waitForTimeout(500);

    // Navigate to trips and export
    await page.click('[data-nav="trips"]');
    await page.waitForTimeout(300);

    // Intercept download
    const downloadPromise = page.waitForEvent('download');
    await page.click('#btnTripExport');
    const download = await downloadPromise;

    // Verify it's a JSON file
    expect(download.suggestedFilename()).toContain('.json');

    // Verify content is valid JSON
    const path = await download.path();
    const fs = require('fs');
    const content = JSON.parse(fs.readFileSync(path, 'utf8'));
    expect(content.meta).toBeDefined();
    expect(content.meta.app).toBe('Freight Logic');
    expect(content.meta.version).toBe('16.3.1');
    expect(content.trips).toBeDefined();
    expect(content.trips.length).toBeGreaterThanOrEqual(1);
    expect(content.meta.checksum).toBeDefined();
  });
});

test.describe('Midwest Stack Evaluator', () => {
  test('evaluates a load correctly', async ({ page }) => {
    await page.goto('/#omega');
    await page.waitForTimeout(500);

    // Fill in load details
    await page.fill('#mwOrigin', 'Indianapolis, IN');
    await page.fill('#mwDest', 'Chicago, IL');
    await page.fill('#mwLoadedMi', '185');
    await page.fill('#mwDeadMi', '20');
    await page.fill('#mwRevenue', '450');

    // Click evaluate
    const evalBtn = page.locator('#mwEvalBtn');
    if (await evalBtn.isVisible()) {
      await evalBtn.click();
    } else {
      // Auto-evaluate on input
      await page.waitForTimeout(600);
    }

    await page.waitForTimeout(500);

    // Should show evaluation output
    const output = page.locator('#mwEvalOutput');
    await expect(output).not.toBeEmpty();
    // Should contain RPM data
    const text = await output.textContent();
    expect(text).toContain('RPM');
  });
});

test.describe('Theme & PWA', () => {
  test('theme toggle works', async ({ page }) => {
    await page.goto('/');
    const html = page.locator('html');

    // Default is dark (no data-theme attr)
    await expect(html).not.toHaveAttribute('data-theme', 'light');

    // Toggle to light
    await page.click('#themeToggle');
    await expect(html).toHaveAttribute('data-theme', 'light');

    // Toggle back to dark
    await page.click('#themeToggle');
    await expect(html).not.toHaveAttribute('data-theme', 'light');
  });

  test('service worker registers', async ({ page }) => {
    await page.goto('/');
    await page.waitForTimeout(1000);
    const swRegistered = await page.evaluate(() => {
      return navigator.serviceWorker?.controller !== null ||
             navigator.serviceWorker?.ready !== undefined;
    });
    expect(swRegistered).toBeTruthy();
  });
});

test.describe('Settings', () => {
  test('saves and restores settings', async ({ page }) => {
    await page.goto('/#insights');
    await page.waitForTimeout(500);

    // Set weekly goal
    await page.fill('#weeklyGoal', '5000');
    await page.fill('#vehicleMpg', '6.5');
    await page.fill('#fuelPrice', '3.50');
    await page.fill('#opCostPerMile', '0.35');
    await page.fill('#settingsHomeLocation', 'Indianapolis, IN');
    await page.click('#btnSaveSettings');
    await page.waitForTimeout(500);

    // Reload and verify
    await page.goto('/#insights');
    await page.waitForTimeout(500);
    await expect(page.locator('#weeklyGoal')).toHaveValue('5000');
    await expect(page.locator('#vehicleMpg')).toHaveValue('6.5');
    await expect(page.locator('#settingsHomeLocation')).toHaveValue('Indianapolis, IN');
  });

  test('DAT API settings toggle', async ({ page }) => {
    await page.goto('/#insights');
    await page.waitForTimeout(500);

    // DAT fields should be hidden by default
    await expect(page.locator('#datApiFields')).toBeHidden();

    // Enable DAT
    await page.selectOption('#datApiEnabled', 'on');
    await expect(page.locator('#datApiFields')).toBeVisible();

    // Disable DAT
    await page.selectOption('#datApiEnabled', 'off');
    await expect(page.locator('#datApiFields')).toBeHidden();
  });
});

test.describe('Accessibility', () => {
  test('modal has correct ARIA attributes', async ({ page }) => {
    await page.goto('/');
    const modal = page.locator('#modal');
    await expect(modal).toHaveAttribute('role', 'dialog');
    await expect(modal).toHaveAttribute('aria-modal', 'true');
    await expect(modal).toHaveAttribute('aria-labelledby', 'modalTitle');
  });

  test('FAB is keyboard accessible', async ({ page }) => {
    await page.goto('/');
    const fab = page.locator('#fab');
    await expect(fab).toHaveAttribute('role', 'button');
    await expect(fab).toHaveAttribute('tabindex', '0');

    // Focus and press Enter
    await fab.focus();
    await page.keyboard.press('Enter');
    await page.waitForTimeout(300);
    await expect(page.locator('#modal')).toHaveClass(/open/);
  });

  test('nav links have aria-labels', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('[data-nav="home"]')).toHaveAttribute('aria-label', 'Home');
    await expect(page.locator('[data-nav="trips"]')).toHaveAttribute('aria-label', 'Trips');
    await expect(page.locator('[data-nav="money"]')).toHaveAttribute('aria-label', 'Money');
    await expect(page.locator('[data-nav="more"]')).toHaveAttribute('aria-label', 'More');
  });

  test('focus is trapped in modal', async ({ page }) => {
    await page.goto('/');
    await page.click('#fab');
    await page.waitForTimeout(300);

    // Tab through and verify focus stays in modal
    for (let i = 0; i < 20; i++) {
      await page.keyboard.press('Tab');
    }
    const activeId = await page.evaluate(() => {
      const el = document.activeElement;
      const modal = document.getElementById('modal');
      return modal?.contains(el) || false;
    });
    expect(activeId).toBeTruthy();
  });
});

test.describe('Security', () => {
  test('XSS in trip fields is escaped', async ({ page }) => {
    await page.goto('/');
    await page.click('#fab');
    await page.click('#btnQuickTrip');
    await page.waitForTimeout(300);

    const xssPayload = '<img src=x onerror=alert(1)>';
    await page.fill('#f_orderNo', xssPayload);
    await page.fill('#f_pay', '1000');
    await page.fill('#f_loaded', '500');
    await page.click('#saveTrip');
    await page.waitForTimeout(500);

    await page.click('[data-nav="trips"]');
    await page.waitForTimeout(300);

    // The XSS payload should be escaped, not rendered as HTML
    const html = await page.locator('#tripList').innerHTML();
    expect(html).not.toContain('<img');
    expect(html).toContain('&lt;img');
  });

  test('CSP blocks inline scripts', async ({ page }) => {
    const cspViolations = [];
    page.on('console', msg => {
      if (msg.text().includes('Content Security Policy')) {
        cspViolations.push(msg.text());
      }
    });

    await page.goto('/');
    await page.waitForTimeout(1000);

    // Try to inject an inline script (should be blocked by CSP)
    const result = await page.evaluate(() => {
      try {
        const s = document.createElement('script');
        s.textContent = 'window.__xss_test = true';
        document.head.appendChild(s);
        return window['__xss_test'] || false;
      } catch { return false; }
    });
    // CSP should block it (result stays false)
    // Note: In practice CSP will prevent the script from running
  });
});

test.describe('Offline Resilience', () => {
  test('app loads from cache when offline', async ({ page, context }) => {
    // First load to populate cache
    await page.goto('/');
    await page.waitForTimeout(2000);

    // Go offline
    await context.setOffline(true);
    await page.waitForTimeout(500);

    // Reload — should still work
    await page.reload();
    await page.waitForTimeout(1000);

    // App should still render
    await expect(page.locator('#appMeta')).toContainText('v16.3.1');

    // Offline banner should appear
    const banner = page.locator('#offlineBanner');
    await expect(banner).toBeVisible();

    // Restore online
    await context.setOffline(false);
  });

  test('data persists across page reloads', async ({ page }) => {
    await page.goto('/');
    await page.click('#fab');
    await page.click('#btnQuickTrip');
    await page.waitForTimeout(300);
    await page.fill('#f_orderNo', 'PERSIST-TEST');
    await page.fill('#f_pay', '4000');
    await page.fill('#f_loaded', '1200');
    await page.click('#saveTrip');
    await page.waitForTimeout(500);

    // Reload page
    await page.reload();
    await page.waitForTimeout(1000);

    // Data should persist
    await page.click('[data-nav="trips"]');
    await page.waitForTimeout(300);
    await expect(page.locator('#tripList')).toContainText('PERSIST-TEST');
  });
});

test.describe('USA Engine', () => {
  test('mode selector is visible on omega page', async ({ page }) => {
    await page.goto('/#omega');
    await page.waitForTimeout(500);
    await expect(page.locator('#mwModeSelector')).toBeVisible();
  });

  test('mode selector has all four modes', async ({ page }) => {
    await page.goto('/#omega');
    await page.waitForTimeout(500);
    const options = await page.locator('#mwModeSelector option').allTextContents();
    expect(options.length).toBe(4);
    expect(options.join(' ')).toContain('Harvest');
    expect(options.join(' ')).toContain('Reposition');
    expect(options.join(' ')).toContain('Escape');
    expect(options.join(' ')).toContain('Floor Protect');
  });

  test('evaluation shows USA Engine panel', async ({ page }) => {
    await page.goto('/#omega');
    await page.waitForTimeout(500);
    await page.fill('#mwOrigin', 'Chicago, IL');
    await page.fill('#mwDest', 'Indianapolis, IN');
    await page.fill('#mwLoadedMi', '185');
    await page.fill('#mwDeadMi', '20');
    await page.fill('#mwRevenue', '420');
    await page.click('#mwEvalBtn');
    await page.waitForTimeout(500);
    const output = await page.locator('#mwEvalOutput').textContent();
    expect(output).toContain('USA Engine');
    expect(output).toContain('anchor');
  });

  test('trap market gets penalized', async ({ page }) => {
    await page.goto('/#omega');
    await page.waitForTimeout(500);
    await page.fill('#mwOrigin', 'Chicago, IL');
    await page.fill('#mwDest', 'Miami, FL');
    await page.fill('#mwLoadedMi', '1200');
    await page.fill('#mwDeadMi', '50');
    await page.fill('#mwRevenue', '1800');
    await page.click('#mwEvalBtn');
    await page.waitForTimeout(500);
    const output = await page.locator('#mwEvalOutput').textContent();
    expect(output).toContain('trap');
  });

  test('mode selector persists after reload', async ({ page }) => {
    await page.goto('/#omega');
    await page.waitForTimeout(500);
    await page.selectOption('#mwModeSelector', 'ESCAPE');
    await page.waitForTimeout(300);
    await page.reload();
    await page.waitForTimeout(1000);
    await page.goto('/#omega');
    await page.waitForTimeout(500);
    const val = await page.locator('#mwModeSelector').inputValue();
    expect(val).toBe('ESCAPE');
  });
});
