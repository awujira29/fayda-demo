/**
 * Capture every UI state for design review — desktop + 380px, light + dark.
 * Uses installed Chrome via playwright-core (no browser download).
 *
 * Requires both processes:
 *   PUBLIC_URL=http://localhost:5173 APP_ENV=dev python backend/app.py
 *   npm run dev
 *
 * Usage: npm run shots   → writes ../screenshots/*.png
 */
import { chromium } from 'playwright-core'
import { mkdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'screenshots')
mkdirSync(OUT, { recursive: true })

const BASE = 'http://localhost:5173'
const browser = await chromium.launch({ channel: 'chrome', headless: true })

async function capture({ viewport, suffix, theme }) {
  const ctx = await browser.newContext({ viewport, deviceScaleFactor: 2 })
  const page = await ctx.newPage()
  const setTheme = () =>
    page.evaluate((t) => {
      localStorage.setItem('theme', t)
      document.documentElement.dataset.theme = t
    }, theme)
  const shot = async (name) => {
    await setTheme()
    await page.waitForTimeout(80)
    await page.screenshot({ path: join(OUT, `${name}${suffix}.png`), fullPage: true })
  }

  // Clean slate: reset needs auth, so log in first if needed, wipe, reload.
  await page.goto(BASE)
  await page.waitForSelector('h1')
  if (!(await page.locator('text=Sign out').count())) {
    await page.click('text=Begin verification with Fayda')
    await page.waitForSelector('.persona')
    await page.click('.persona >> nth=0')
    await page.waitForSelector('text=Verified identity record')
  }
  await page.evaluate(() => fetch('/api/dev/reset', { method: 'POST' }))
  await page.goto(BASE)
  await page.waitForSelector('h1')
  await shot('01-signed-out')

  // The mock IdP's simulated biometric prompt (its own dark identity).
  await page.click('text=Begin verification with Fayda')
  await page.waitForSelector('.persona')
  await page.screenshot({ path: join(OUT, `02-biometric-prompt${suffix}.png`), fullPage: true })

  await page.click('.persona >> nth=0')
  await page.waitForSelector('text=Verified identity record')
  await shot('03-identity-record')

  // Attestation dialog via the dev test key — full message, review state.
  await page.click('button:has-text("Throwaway test key (dev)") >> nth=0')
  await page.waitForSelector('text=Review, then sign')
  await shot('04-attestation')

  // Bind → one chain active.
  await page.click('text=Bind with test-key signature')
  await page.waitForSelector('text=Wallet bound')
  await shot('05-one-bound')

  // Replacement → cooling state.
  await page.click('button:has-text("Throwaway test key (dev)") >> nth=0')
  await page.waitForSelector('text=Review, then sign')
  await page.click('text=Bind with test-key signature')
  await page.waitForSelector('text=Replacement under cooling')
  await shot('06-cooling')

  // Error state: force the bind to fail server-side; banner appears in dialog.
  await page.route('**/api/wallet/bind', (route) =>
    route.fulfill({
      status: 400,
      contentType: 'application/json',
      body: JSON.stringify({ detail: 'proof of control failed: signature does not match address' }),
    }),
  )
  await page.click('button:has-text("Throwaway test key (dev)")')
  await page.waitForSelector('text=Review, then sign')
  await page.click('text=Bind with test-key signature')
  await page.waitForSelector('text=The signature was not accepted.')
  await shot('07-error')
  await page.unroute('**/api/wallet/bind')

  await ctx.close()
}

const DESKTOP = { width: 1280, height: 900 }
const MOBILE = { width: 380, height: 800 }

await capture({ viewport: DESKTOP, suffix: '', theme: 'light' })
await capture({ viewport: MOBILE, suffix: '-380px', theme: 'light' })
await capture({ viewport: DESKTOP, suffix: '-dark', theme: 'dark' })
await capture({ viewport: MOBILE, suffix: '-380px-dark', theme: 'dark' })
await browser.close()
console.log(`screenshots written to ${OUT}`)
