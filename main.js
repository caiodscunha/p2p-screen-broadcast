const { app, BrowserWindow, session, ipcMain, clipboard, desktopCapturer } = require('electron');
const path = require('path');
const { registerDisplayMediaHandler, supportsSystemAudioLoopback } = require('./capture');
const processAudio = require('./native/audio-loopback');

// Handles de captura por processo ativos, por WebContents (pra poder parar
// tudo se a janela fechar/recarregar sem que o usuário clique "Parar").
const activeProcessAudioCaptures = new Map();

// É comum abrir duas instâncias deste app na mesma máquina para testar
// transmissor e espectador ao mesmo tempo. Por padrão o Electron usa a mesma
// pasta de perfil/cache (userData) para todas as instâncias do mesmo app, e
// no Windows isso causa "Acesso negado" quando duas instâncias tentam
// escrever no cache de GPU/disco ao mesmo tempo (cache_util_win.cc) — o que
// pode derrubar o processo de GPU de uma delas e travar o vídeo. O app não
// guarda nenhum estado entre execuções, então isolar o userData por processo
// não perde nada e elimina esse conflito.
app.setPath('userData', path.join(app.getPath('temp'), `p2p-screen-broadcast-${process.pid}`));

ipcMain.handle('clipboard:write', (event, text) => clipboard.writeText(text));
ipcMain.handle('clipboard:read', () => clipboard.readText());
ipcMain.handle('capture:supportsSystemAudio', () => supportsSystemAudioLoopback);

// Captura de áudio por processo (Windows apenas, via módulo nativo em
// native/audio-loopback). Deixa incluir só um app específico, ou excluir um
// app específico do resto — útil pra tirar uma chamada de voz (Discord, etc)
// do que é compartilhado, sem depender de rotear áudio manualmente pro SO.
ipcMain.handle('audio-process:supported', () => processAudio.supported);
ipcMain.handle('audio-process:list', () => processAudio.listProcesses());

ipcMain.handle('audio-process:start', (event, { pid, exclude }) => {
  const webContents = event.sender;
  const handle = processAudio.startCapture(pid, exclude, (error, samples, sampleRate, channels) => {
    if (webContents.isDestroyed()) return;
    if (error) {
      webContents.send('audio-process:error', error);
      return;
    }
    webContents.send('audio-process:chunk', samples, sampleRate, channels);
  });

  if (!activeProcessAudioCaptures.has(webContents.id)) activeProcessAudioCaptures.set(webContents.id, new Set());
  activeProcessAudioCaptures.get(webContents.id).add(handle);
  return handle;
});

ipcMain.handle('audio-process:stop', (event, handle) => {
  processAudio.stopCapture(handle);
  activeProcessAudioCaptures.get(event.sender.id)?.delete(handle);
});

// Lista as telas disponíveis (com miniatura) pra deixar o usuário escolher
// qual monitor compartilhar — inclusive pra trocar de monitor com a
// transmissão já rolando, sem depender do seletor nativo do SO (que só
// aparece no início, e nem existe no Linux).
ipcMain.handle('capture:listScreens', async () => {
  const sources = await desktopCapturer.getSources({
    types: ['screen'],
    thumbnailSize: { width: 320, height: 180 },
  });
  return sources.map((s) => ({
    id: s.id,
    name: s.name,
    thumbnail: s.thumbnail.isEmpty() ? null : s.thumbnail.toDataURL(),
  }));
});

function createWindow() {
  const win = new BrowserWindow({
    width: 1100,
    height: 720,
    autoHideMenuBar: true,
    title: 'Sinal P2P',
    icon: path.join(__dirname, 'assets', 'icon.png'),
    backgroundColor: '#15161a',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      // Desliga o DevTools (Ctrl+Shift+I/F12 e qualquer chamada a
      // openDevTools()) nos executáveis empacotados, para o usuário final não
      // conseguir abrir o console. Continua disponível rodando via
      // "npm start"/"electron .", já que app.isPackaged só é true num build.
      devTools: !app.isPackaged,
    },
  });
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  // Evita vazar uma thread de captura nativa rodando pra sempre se a janela
  // fechar/recarregar sem que o usuário clique em "Parar".
  win.webContents.on('destroyed', () => {
    const handles = activeProcessAudioCaptures.get(win.webContents.id);
    if (handles) {
      handles.forEach((handle) => processAudio.stopCapture(handle));
      activeProcessAudioCaptures.delete(win.webContents.id);
    }
  });
}

app.whenReady().then(() => {
  // Sem verificador ortográfico: os campos de texto do app são só
  // código/senha/nome, não precisam disso, e o serviço de spellcheck do
  // Chromium carrega dicionários inteiros na memória à toa.
  session.defaultSession.setSpellCheckerEnabled(false);

  registerDisplayMediaHandler(session.defaultSession);

  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
