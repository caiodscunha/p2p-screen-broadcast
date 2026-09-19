const { app, BrowserWindow, session, ipcMain, clipboard, desktopCapturer, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { exec } = require('child_process');
const { registerDisplayMediaHandler, supportsSystemAudioLoopback } = require('./capture');
const processAudio = require('./native/audio-loopback');
const signalPunch = require('./signal-punch');

// A conexão automática (ver signal-punch.js) manda um pacote UDP não
// solicitado pro outro PC. Entre duas instâncias na MESMA máquina isso
// funciona porque o tráfego local não passa pelo mesmo filtro; entre dois
// PCs de verdade, o Firewall do Windows bloqueia por padrão qualquer pacote
// de entrada não solicitado de um app sem regra explícita — daí "funciona
// só no mesmo PC". Não tem como evitar isso com código: qualquer coisa que
// aceite uma conexão de rede não solicitada precisa de alguma liberação no
// firewall, é assim que firewall funciona. A correção real é uma regra
// bem específica (só este programa, só UDP, só em rede privada — nunca em
// Wi-Fi público) liberando entrada; como isso exige admin, perguntamos por
// executável (ver getFirewallRuleId) se o usuário quer liberar, e só paramos
// de perguntar de novo depois de confirmar que a regra realmente ficou lá.
//
// Importante: a regra é específica pro caminho exato do .exe (netsh
// program="..."). Rodar "npm start" (electron.exe dentro de node_modules) e
// depois testar o .exe empacotado (dist/Sinal-P2P-*.exe) são dois programas
// diferentes pro Windows — cada um precisa da sua própria liberação.
function getFirewallRuleId(exePath) {
  const hash = crypto.createHash('sha1').update(exePath).digest('hex').slice(0, 10);
  return { name: `Sinal P2P (auto-connect ${hash})`, exePath };
}

function getFirewallMarkerPath() {
  return path.join(app.getPath('appData'), 'sinal-p2p', 'firewall-marker.json');
}

function readFirewallMarker() {
  try {
    return JSON.parse(fs.readFileSync(getFirewallMarkerPath(), 'utf8'));
  } catch {
    return {};
  }
}

// Guardado por exe (chave = caminho do executável), não um flag único
// global — assim cada binário (dev vs. empacotado, ou um portátil movido de
// pasta) pergunta e é verificado de forma independente.
function writeFirewallMarkerEntry(exePath, entry) {
  const markerPath = getFirewallMarkerPath();
  const marker = readFirewallMarker();
  marker[exePath] = entry;
  try {
    fs.mkdirSync(path.dirname(markerPath), { recursive: true });
    fs.writeFileSync(markerPath, JSON.stringify(marker));
  } catch {
    // não crítico — na pior das hipóteses pergunta de novo no próximo início
  }
}

// "netsh ... show rule" sai com código 0 quando acha a regra e código 1
// quando não acha ("Nenhuma regra correspondente..."/"No rules match...",
// dependendo do idioma do Windows) — checa pelo código de saída em vez de
// tentar casar o texto, que muda de idioma pra idioma.
function firewallRuleExists(ruleName) {
  return new Promise((resolve) => {
    exec(`netsh advfirewall firewall show rule name="${ruleName}"`, (err) => {
      resolve(!err);
    });
  });
}

// Roda o netsh elevado (precisa de admin pra mexer em regra de firewall).
// Escreve um .ps1 temporário em vez de aninhar aspas direto no comando —
// evita o inferno de escaping de rodar PowerShell dentro de PowerShell.
//
// A regra é a mais restrita possível pro que precisa funcionar:
// - program="<exe>": só esse executável pode receber a conexão, nenhum outro
//   app do PC ganha nada com isso.
// - protocol=UDP: nada de TCP (não abre "porta" pra serviços tipo compartilhamento
//   de arquivo/RDP, só o pacotinho de sinalização).
// - profile=private,domain: NÃO libera em rede Wi-Fi pública (aeroporto, café
//   etc.) — só em redes marcadas como "privada" no Windows (casa/trabalho
//   confiável), que é o único cenário em que isso precisa funcionar mesmo.
function addFirewallRuleElevated(ruleName, exePath) {
  return new Promise((resolve) => {
    const scriptPath = path.join(app.getPath('temp'), `sinal-p2p-add-firewall-rule-${process.pid}.ps1`);
    const scriptContent =
      `netsh advfirewall firewall add rule name="${ruleName}" dir=in action=allow protocol=UDP program="${exePath}" enable=yes profile=private,domain\r\n`;

    try {
      fs.writeFileSync(scriptPath, scriptContent, 'utf8');
    } catch {
      resolve(false);
      return;
    }

    const elevate = `Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File "${scriptPath}"' -Verb RunAs -WindowStyle Hidden -Wait`;
    exec(`powershell -NoProfile -Command "${elevate}"`, (err) => {
      try {
        fs.unlinkSync(scriptPath);
      } catch {
        // arquivo temporário; se sobrar, não afeta nada
      }
      resolve(!err);
    });
  });
}

async function ensureFirewallAccess() {
  if (process.platform !== 'win32') return;

  const { name: ruleName, exePath } = getFirewallRuleId(process.execPath);
  const marker = readFirewallMarker();
  const previous = marker[exePath];

  // Só para de perguntar quando já sabemos que a regra existe de verdade ou
  // quando o usuário recusou explicitamente — uma tentativa que falhou (ex:
  // cancelou o UAC sem querer) volta a perguntar na próxima abertura, em vez
  // de ficar quebrado pra sempre em silêncio.
  if (previous?.rule === 'added' || previous?.rule === 'declined') return;

  if (await firewallRuleExists(ruleName)) {
    writeFirewallMarkerEntry(exePath, { rule: 'added' });
    return;
  }

  const { response } = await dialog.showMessageBox({
    type: 'question',
    buttons: ['Liberar agora', 'Agora não'],
    defaultId: 0,
    cancelId: 1,
    title: 'Conexão automática entre PCs diferentes',
    message:
      'Pra conexão automática funcionar entre PCs diferentes (não só entre duas janelas no mesmo PC), o Windows precisa liberar este app no Firewall. Isso pede permissão de administrador, só essa vez.',
    detail:
      'A regra é restrita: só vale pra este programa, só UDP, e só em redes marcadas como privada (nunca em Wi-Fi público). ' +
      'Se preferir não liberar agora, o app continua funcionando normalmente — só sempre cai no código de resposta manual.',
  });

  if (response !== 0) {
    writeFirewallMarkerEntry(exePath, { rule: 'declined' });
    return;
  }

  await addFirewallRuleElevated(ruleName, exePath);
  // Confirma de verdade em vez de assumir que o netsh elevado funcionou —
  // se o usuário cancelar o UAC, o "Start-Process -Verb RunAs" não retorna
  // erro pro processo que o chamou, então só dá pra saber checando de novo.
  const confirmed = await firewallRuleExists(ruleName);
  writeFirewallMarkerEntry(exePath, { rule: confirmed ? 'added' : 'failed' });

  await dialog.showMessageBox({
    type: confirmed ? 'info' : 'warning',
    title: 'Conexão automática entre PCs diferentes',
    message: confirmed
      ? 'Regra adicionada com sucesso.'
      : 'Não consegui confirmar que a regra foi adicionada (talvez o UAC tenha sido cancelado).',
    detail: confirmed
      ? 'Se ainda assim a conexão automática não funcionar entre PCs, confira se a rede de ambos está marcada como "privada" ' +
        '(Configurações > Rede e Internet), não "pública" — a regra só vale pra redes privadas.'
      : 'O app continua funcionando normalmente pelo fluxo manual. Pra tentar de novo, feche e abra o app.',
  });
}

// Handles de captura por processo ativos, por WebContents (pra poder parar
// tudo se a janela fechar/recarregar sem que o usuário clique "Parar").
const activeProcessAudioCaptures = new Map();

// Handshakes automáticos (UDP+STUN) ativos, por WebContents, indexados pelo
// sessionId — ver signal-punch.js. Mesmo motivo do Map acima: limpar se a
// janela fechar sem o usuário completar a conexão.
const activeSignalListeners = new Map();

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

// Handshake automático de resposta (ver signal-punch.js): o transmissor abre
// um "ponto de encontro" UDP (IP local + IP público via STUN) e embute esses
// candidatos no próprio código de oferta (dentro do payload criptografado
// pela senha, se houver uma); o espectador manda a resposta direto pra lá,
// sem precisar colar nada de volta na mão.
ipcMain.handle('signal:startHost', async (event) => {
  const webContents = event.sender;
  let handle;
  handle = await signalPunch.startHostListener({
    onAnswer: (code) => {
      if (webContents.isDestroyed()) return;
      webContents.send('signal:answer', { sessionId: handle.sessionId, code });
    },
  });
  if (!handle) return null; // nem IP local nem STUN disponíveis — sem atalho automático

  if (!activeSignalListeners.has(webContents.id)) activeSignalListeners.set(webContents.id, new Map());
  activeSignalListeners.get(webContents.id).set(handle.sessionId, handle.stop);

  return { sessionId: handle.sessionId, candidates: handle.candidates };
});

ipcMain.handle('signal:stopHost', (event, sessionId) => {
  const listeners = activeSignalListeners.get(event.sender.id);
  const stop = listeners && listeners.get(sessionId);
  if (stop) {
    stop();
    listeners.delete(sessionId);
  }
});

ipcMain.handle('signal:sendAnswer', (event, { candidates, sessionId, code }) => {
  return signalPunch.sendAnswer({ candidates, sessionId, code });
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
    const signalListeners = activeSignalListeners.get(win.webContents.id);
    if (signalListeners) {
      signalListeners.forEach((stop) => stop());
      activeSignalListeners.delete(win.webContents.id);
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
  ensureFirewallAccess(); // não bloqueia a abertura da janela — a caixa de diálogo aparece por cima

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
