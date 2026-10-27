const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('settings', {
  read: (key) => ipcRenderer.invoke('settings:read', key),
});
