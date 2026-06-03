const { chromium } = require('playwright');

(async () => {
  let browser;
  try {
    browser = await chromium.launch();
    const page = await browser.newPage();
    
    // Capture console errors
    page.on('console', msg => {
        if (msg.type() === 'error') console.log('BROWSER ERROR LOG:', msg.text());
    });
    page.on('pageerror', err => console.log('BROWSER UNCAUGHT ERR:', err.message));

    console.log('Navigating to http://localhost:5175/?demo=wallet ...');
    await page.goto('http://localhost:5175/?demo=wallet', { waitUntil: 'networkidle' });

    // Wait for the app to initialize
    await page.waitForTimeout(2000);

    console.log('--- UI Verification ---');
    
    // 1. Check if the Wallet is unlocked and rendering
    const headerText = await page.textContent('.wallet-header').catch(() => null);
    if (!headerText) {
        console.log('Header text: NOT FOUND');
        console.log('--- Page HTML ---');
        console.log(await page.content());
        return;
    }
    console.log('Header text:', headerText ? headerText.replace(/\s+/g, ' ').trim() : 'NOT FOUND');

    // 2. Count Credential Cards
    const cards = await page.$$('.credential-card');
    console.log(`Found ${cards.length} credential cards.`);
    for (let i = 0; i < cards.length; i++) {
        const title = await cards[i].$eval('.credential-card-name', el => el.textContent).catch(() => 'Unknown');
        console.log(` - Card ${i+1}: ${title}`);
    }

    // 3. Count Action Buttons
    const buttons = await page.$$('.action-btn');
    console.log(`Found ${buttons.length} quick action buttons.`);

    if (cards.length > 0 && buttons.length > 0) {
        console.log('\n--- Interaction Test ---');
        console.log('Clicking "Age Check" (Liquor Store) button...');
        
        // Find the age check button and click it
        const ageCheckBtn = await page.$('text="Age Check"');
        if (ageCheckBtn) {
            await ageCheckBtn.click();
            await page.waitForTimeout(1000); // wait for evaluation
            
            // Check logs
            const logs = await page.$$eval('.log-entry', els => els.map(e => e.textContent));
            console.log('Recent Audit Logs:');
            logs.slice(-5).forEach(l => console.log(' >', l));
            
            // Check if consent modal opened or proof sent
            const consentModal = await page.$('.secure-prompt');
            if (consentModal) {
                console.log('Result: Consent Modal / Alert opened successfully.');
            } else {
                console.log('Result: No modal opened (might be auto-allowed or failed).');
            }
        } else {
            console.log('Age Check button not found.');
        }
    } else {
        console.log('\n❌ CRITICAL: Wallet did not render cards or buttons. Initialization failed.');
    }

  } catch (err) {
    console.log('Test Script Error:', err.message);
  } finally {
    if (browser) await browser.close();
  }
})();
