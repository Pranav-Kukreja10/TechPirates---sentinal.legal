import asyncio
from playwright.async_api import async_playwright

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        page.on('console', lambda msg: print('CONSOLE:', msg.text))
        page.on('pageerror', lambda exc: print('PAGE ERROR:', exc))
        await page.goto('http://localhost:5500')
        await page.click('#tab-img')
        file_input = page.locator('#imgfi')
        await file_input.set_input_files('test.png')
        await asyncio.sleep(2)
        await page.click('#abtn')
        await asyncio.sleep(1)
        await browser.close()

asyncio.run(run())
