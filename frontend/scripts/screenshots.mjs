/**
 * Screenshot every UI state for design review, desktop and 380px.
 *
 * Uses the locally installed Chrome via playwright-core (no browser download).
 * Requires both processes running:
 *   PUBLIC_URL=http://localhost:5173 APP_ENV=dev python backend/app.py
 *   npm run dev
 *
 * Usage: npm run shots   (writes ../screenshots/*.png)
 */
import { chromium } from 'playwright-core'
import { mkdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'screenshots')
mkdirSync(OUT, { recursive: true })

const BASE = 'http://localhost:5173'
const DESKTOP = { width: 1200, height: 900 }
const MOBILE = { width: 380, height: 800 }

const browser = await chromium.launch({ channel: 'chrome', headless: true })

async function capture(viewport, suffix) {
  const ctx = await browser.newContext({ viewport, deviceScaleFactor: 2 })
  const page = await ctx.newPage()
  const shot = (name) => page.screenshot({ path: join(OUT, `${name}${suffix}.png`), fullPage: true })

  // Clean slate every run: the reset endpoint needs an authenticated session,
  // so log in first if needed, wipe, and land signed out with an empty DB.
  await page.goto(BASE)
  await page.waitForSelector('h1')
  if (!(await page.locator('text=Sign out').count())) {
    await page.click('text=Verify with Fayda')
    await page.waitForSelector('.persona')
    await page.click('.persona >> nth=0')
    await page.waitForSelector('text=Verified identity')
  }
  await page.evaluate(() => fetch('/api/dev/reset', { method: 'POST' }))
  await page.goto(BASE)
  await page.waitForSelector('h1')
  await shot('01-signed-out')

  // Mock IdP — the simulated biometric prompt.
  await page.click('text=Verify with Fayda')
  await page.waitForSelector('.persona')
  await shot('02-biometric-prompt')

  // Authenticate as the first persona.
  await page.click('.persona >> nth=0')
  await page.waitForSelector('text=Verified identity')
  await shot('03-signed-in-no-wallets')

  // Signing panel via the dev test key (message fully visible, nothing sent yet).
  await page.click('.card:has-text("Ethereum") >> text=Throwaway test key (dev)')
  await page.waitForSelector('text=Sign to prove control')
  await shot('04-signing-panel')

  // Bind it — one chain bound, one empty.
  await page.click('text=Bind with test-key signature')
  await page.waitForSelector('.card:has-text("Ethereum") .p-active')
  await shot('05-one-bound')

  // Replacement: second test key on the same chain goes pending (cooling).
  await page.click('.card:has-text("Ethereum") >> text=Throwaway test key (dev)')
  await page.waitForSelector('text=Sign to prove control')
  await page.click('text=Bind with test-key signature')
  await page.waitForSelector('.pill.p-pending')
  await shot('06-pending-cooling')

  // Error state: make the next bind fail server-side and show the banner.
  await page.route('**/api/wallet/bind', (route) =>
    route.fulfill({
      status: 400,
      contentType: 'application/json',
      body: JSON.stringify({ detail: 'proof of control failed: signature does not match address' }),
    }),
  )
  await page.click('.card:has-text("Solana") >> text=Throwaway test key (dev)')
  await page.waitForSelector('text=Sign to prove control')
  await page.click('text=Bind with test-key signature')
  await page.waitForSelector('.err')
  await shot('07-error')
  await page.unroute('**/api/wallet/bind')

  await ctx.close()
}

await capture(DESKTOP, '')
await capture(MOBILE, '-380px')
await browser.close()
console.log(`screenshots written to ${OUT}`)
