const { BrowserWindow, ipcMain } = require('electron');

ipcMain.handle('settings:read', (_event, key) => String(key));

function createWindow() {
  const win = new BrowserWindow({
    webPreferences: {
      preload: './preload.js',
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  win.loadFile('index.html');
  return win;
}

module.exports = { createWindow };
