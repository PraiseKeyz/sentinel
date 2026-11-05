// Renders the built UI with demo data and saves README screenshots to docs/.
// Usage: pnpm screenshot   (runs `pnpm build` first)
const { app, BrowserWindow } = require('electron');
const { mkdirSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');

const root = join(__dirname, '..');
const out = join(root, 'docs');
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

async function shot(win, name) {
  await wait(700);
  const image = await win.webContents.capturePage();
  writeFileSync(join(out, name), image.toPNG());
  console.log('saved docs/' + name);
}

app.whenReady().then(async () => {
  mkdirSync(out, { recursive: true });
  // No preload script, so the renderer falls back to its built-in demo data.
  const win = new BrowserWindow({ width: 1440, height: 900, show: false, backgroundColor: '#0a0d12' });
  await win.loadFile(join(root, 'dist', 'index.html'), { query: { screenshot: '1' } });
  await shot(win, 'screenshot-overview.png');

  await win.webContents.executeJavaScript(`
    [...document.querySelectorAll('.server-item')].find((b) => b.textContent.includes('web-edge')).click();
  `);
  await wait(200);
  await win.webContents.executeJavaScript(`
    [...document.querySelectorAll('.tabs button')].find((b) => b.textContent.startsWith('Network')).click();
  `);
  await shot(win, 'screenshot-server.png');
  app.quit();
});
