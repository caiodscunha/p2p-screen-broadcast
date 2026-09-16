const { app, BrowserWindow, session, ipcMain, clipboard } = require('electron');
const path = require('path');
const { execFile } = require('child_process');
const { registerDisplayMediaHandler, supportsSystemAudioLoopback } = require('./capture');

// O Windows reduz a prioridade de CPU/GPU de processos sem foco/minimizados
// para economizar energia (Efficiency Mode/EcoQoS), num nível que fica abaixo
// de qualquer flag do Chromium — é por isso que as flags de occlusion não
// resolvem o congelamento ao minimizar. A saída (mesma usada por apps como
// OBS/Discord) é forçar prioridade "Acima do normal" para os processos do
// Electron (janela principal, renderer e GPU), contornando esse throttling.
function boostProcessPriority() {
  if (process.platform !== 'win32') return;
  app.getAppMetrics().forEach(({ pid }) => {
    execFile(
      'powershell.exe',
      [
        '-NoProfile',
        '-WindowStyle', 'Hidden',
        '-Command',
        `try { (Get-Process -Id ${pid}).PriorityClass = 'AboveNormal' } catch {}`,
      ],
      () => {}
    );
  });
}

// É comum abrir duas instâncias deste app na mesma máquina para testar
// transmissor e espectador ao mesmo tempo. Por padrão o Electron usa a mesma
// pasta de perfil/cache (userData) para todas as instâncias do mesmo app, e
// no Windows isso causa "Acesso negado" quando duas instâncias tentam
// escrever no cache de GPU/disco ao mesmo tempo (cache_util_win.cc) — o que
// pode derrubar o processo de GPU de uma delas e travar o vídeo. O app não
// guarda nenhum estado entre execuções, então isolar o userData por processo
// não perde nada e elimina esse conflito.
app.setPath('userData', path.join(app.getPath('temp'), `p2p-screen-broadcast-${process.pid}`));

// Sem isso, o Windows detecta a janela minimizada ou totalmente coberta por
// outro app ("occlusion") e o Chromium trata a página como se estivesse em
// segundo plano: reduz a prioridade do processo e pausa/limita timers e
// renderização, o que congela a transmissão para os espectadores mesmo com a
// captura de tela ainda ativa. Precisa ser definido antes do app ficar
// pronto (app.whenReady).
// IntensiveWakeUpThrottling é um mecanismo separado de throttling de timers
// para páginas em segundo plano (distinto do que backgroundThrottling:false
// desliga) que também pode segurar o loop de captura/envio de vídeo.
app.commandLine.appendSwitch('disable-features', 'CalculateNativeWinOcclusion,IntensiveWakeUpThrottling');
app.commandLine.appendSwitch('disable-backgrounding-occluded-windows');
app.commandLine.appendSwitch('disable-renderer-backgrounding');
app.commandLine.appendSwitch('disable-background-timer-throttling');

ipcMain.handle('clipboard:write', (event, text) => clipboard.writeText(text));
ipcMain.handle('clipboard:read', () => clipboard.readText());
ipcMain.handle('capture:supportsSystemAudio', () => supportsSystemAudioLoopback);
// Reforça a prioridade assim que a captura de tela começa, porque nesse
// momento o Chromium sobe processos novos (serviço de captura de vídeo) que
// ainda não tinham sido priorizados pela chamada inicial.
ipcMain.handle('capture:started', () => boostProcessPriority());

function createWindow() {
  const win = new BrowserWindow({
    width: 1100,
    height: 720,
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      backgroundThrottling: false,
    },
  });
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  // Reaplica a prioridade ao minimizar: o Windows pode resetar a classe de
  // prioridade do processo quando ele perde o estado "restaurado".
  win.on('minimize', boostProcessPriority);
}

app.whenReady().then(() => {
  registerDisplayMediaHandler(session.defaultSession);

  createWindow();
  setTimeout(boostProcessPriority, 3000);

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
