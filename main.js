const { app, BrowserWindow, session, ipcMain, clipboard, desktopCapturer, dialog, screen } = require('electron');
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
// O netsh é chamado direto pelo Start-Process elevado — nada de script
// intermediário. Antes isso escrevia um .ps1 com nome previsível na pasta
// temporária e o executava como admin: qualquer programa rodando como o
// usuário podia trocar o arquivo nesse meio tempo e ganhar admin de carona
// no UAC que a pessoa aprovou. O comando do PowerShell vai em
// -EncodedCommand (base64 de UTF-16LE), então não tem aspas pra escapar
// no caminho até ele.
//
// A regra é a mais restrita possível pro que precisa funcionar:
// - program="<exe>": só esse executável pode receber a conexão, nenhum outro
//   app do PC ganha nada com isso.
// - protocol=UDP: nada de TCP (não abre "porta" pra serviços tipo compartilhamento
//   de arquivo/RDP, só o pacotinho de sinalização).
// - profile=private,domain: NÃO libera em rede Wi-Fi pública (aeroporto, café
//   etc.) — só em redes marcadas como "privada" no Windows (casa/trabalho
//   confiável), que é o único cenário em que isso precisa funcionar mesmo.
function powershellQuote(text) {
  return `'${text.replace(/'/g, "''")}'`;
}

function encodePowershellCommand(command) {
  return Buffer.from(command, 'utf16le').toString('base64');
}

function addFirewallRuleElevated(ruleName, exePath) {
  return new Promise((resolve) => {
    const netshArgs = `advfirewall firewall add rule name="${ruleName}" dir=in action=allow protocol=UDP program="${exePath}" enable=yes profile=private,domain`;
    const elevate = `Start-Process -FilePath netsh -ArgumentList ${powershellQuote(netshArgs)} -Verb RunAs -WindowStyle Hidden -Wait`;
    exec(`powershell -NoProfile -EncodedCommand ${encodePowershellCommand(elevate)}`, (err) => resolve(!err));
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

// Minimizar a janela enquanto está compartilhando a tela travava o PC inteiro
// nalgumas máquinas (não só o app) — reproduzido em mais de uma máquina.
//
// A primeira explicação (bug de driver de GPU híbrida, Intel+dedicada) estava
// ERRADA pra este caso: o PC onde mais acontecia tem uma GPU só (RTX 5070). A
// causa medida depois foi a política de segundo plano do Windows 11 (ver
// optOutOfBackgroundThrottling acima): ao minimizar, as threads do app iam
// pros núcleos de eficiência da CPU híbrida e o resto do Windows ficava preso
// atrás delas. Isso agora é desligado no próprio app, e o codec de vídeo
// passou a usar a placa de vídeo com muito mais gente (ver chooseSendCodec no
// renderer), então minimizar não deveria mais travar.
//
// O botão de minimizar continua desabilitado enquanto uma transmissão está
// ativa (ver 'sharing:active' abaixo) só como cinto de segurança, até
// confirmarmos em uso real que não é mais necessário: é a única parte da
// correção antiga que ainda pesa na experiência de quem usa. Não cobre todos
// os jeitos de minimizar no Windows (Win+D "Mostrar área de trabalho" ainda
// minimiza todas as janelas) — é por isso que o opt-out acima é a correção de
// verdade, e este bloqueio é só complemento.
function getMinimizeWarningMarkerPath() {
  return path.join(app.getPath('appData'), 'sinal-p2p', 'minimize-warning-shown.json');
}

async function maybeExplainMinimizeDisabled() {
  const markerPath = getMinimizeWarningMarkerPath();
  if (fs.existsSync(markerPath)) return;

  try {
    fs.mkdirSync(path.dirname(markerPath), { recursive: true });
    fs.writeFileSync(markerPath, JSON.stringify({ shown: true }));
  } catch {
    // não crítico — na pior das hipóteses mostra de novo na próxima vez
  }

  await dialog.showMessageBox({
    type: 'info',
    title: 'Minimizar desabilitado durante a transmissão',
    message: 'Enquanto você está compartilhando a tela, o botão de minimizar desta janela fica desativado.',
    detail:
      'Minimizar durante a transmissão pode deixar o computador lento ou travado em algumas máquinas. ' +
      'Pra tirar a janela do caminho sem minimizar, é só trocar de janela normalmente (Alt+Tab ou clicando em ' +
      'outro app) — o Sinal P2P continua transmitindo por trás.',
  });
}

// Registro de diagnóstico em arquivo: o app empacotado não tem console nem
// DevTools, então é a única forma de ver depois o que aconteceu num
// travamento (política de energia aplicada, janela minimizada, codec usado
// com cada pessoa, etc). Poucas linhas por sessão; passa de 512 KB vira .1.
// Fica em %APPDATA%\sinal-p2p\diagnostico.log.
const DIAG_MAX_BYTES = 512 * 1024;
let diagPath = null;
function diag(message) {
  try {
    if (!diagPath) {
      diagPath = path.join(app.getPath('appData'), 'sinal-p2p', 'diagnostico.log');
      fs.mkdirSync(path.dirname(diagPath), { recursive: true });
    }
    try {
      if (fs.statSync(diagPath).size > DIAG_MAX_BYTES) fs.renameSync(diagPath, diagPath + '.1');
    } catch {
      // ainda não existe — tudo bem
    }
    // Hora local (não UTC) pra bater com o relógio de quem vai ler o arquivo.
    const now = new Date();
    const pad = (n, size = 2) => String(n).padStart(size, '0');
    const stamp =
      `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ` +
      `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}.${pad(now.getMilliseconds(), 3)}`;
    fs.appendFileSync(diagPath, `${stamp} [${process.pid}] ${message}\n`);
  } catch {
    // diagnóstico nunca pode derrubar o app
  }
}

// No Windows 11, minimizar a janela faz o SO tratar o app como "de segundo
// plano": EcoQoS, threads empurradas pros núcleos de eficiência das CPUs
// híbridas Intel e timer mais grosso. O Sinal P2P continua trabalhando
// pesado em segundo plano (é pra isso que ele serve), e medido aqui, num
// i5-12600K, com VP8 por software em 3 conexões: minimizado, os 4 E-cores iam
// a 100%, o codificador ficava 14x mais lento e o Windows inteiro engasgava
// (abrir um app levava de 6 a 14 s: o "PC estático"). Pedir ao SO pra não
// aplicar essa política (ver DisableProcessThrottling no addon nativo)
// deixou minimizado idêntico a visível: mesmo custo de CPU, mesmos fps.
//
// A configuração vale POR PROCESSO e não passa pros filhos, então vale pro
// principal e pra cada processo do Chromium (renderer, GPU, utilitários) —
// inclusive os que nascem depois (ex: o serviço de captura de vídeo ao começar
// a compartilhar). Por isso roda no começo, a cada evento que cria processo
// e num intervalo curto.
const throttlingOptOutDone = new Set();
const throttlingOptOutFailures = new Map();
function optOutOfBackgroundThrottling(reason) {
  if (process.platform !== 'win32') return;
  let metrics;
  try {
    metrics = app.getAppMetrics();
  } catch {
    return;
  }
  const alive = new Set(metrics.map((metric) => metric.pid));
  throttlingOptOutDone.forEach((pid) => {
    if (!alive.has(pid)) throttlingOptOutDone.delete(pid);
  });
  throttlingOptOutFailures.forEach((count, pid) => {
    if (!alive.has(pid)) throttlingOptOutFailures.delete(pid);
  });

  const applied = [];
  const failed = [];
  for (const metric of metrics) {
    if (throttlingOptOutDone.has(metric.pid)) continue;
    if ((throttlingOptOutFailures.get(metric.pid) || 0) >= 3) continue; // desiste (ex: sem permissão)
    if (processAudio.disableProcessThrottling(metric.pid)) {
      throttlingOptOutDone.add(metric.pid);
      applied.push(`${metric.type}:${metric.pid}`);
    } else {
      throttlingOptOutFailures.set(metric.pid, (throttlingOptOutFailures.get(metric.pid) || 0) + 1);
      failed.push(`${metric.type}:${metric.pid}`);
    }
  }
  if (applied.length || failed.length) {
    diag(`segundo plano: política do Windows desligada (${reason}) em [${applied.join(', ')}]` + (failed.length ? `, falhou em [${failed.join(', ')}]` : ''));
  }
}

// Chama agora e de novo logo depois: o processo novo (ex: o serviço de captura
// de vídeo) só aparece alguns instantes após o evento que o cria.
function optOutOfBackgroundThrottlingSoon(reason) {
  optOutOfBackgroundThrottling(reason);
  setTimeout(() => optOutOfBackgroundThrottling(reason + '+1s'), 1000).unref();
  setTimeout(() => optOutOfBackgroundThrottling(reason + '+3s'), 3000).unref();
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
//
// Onde fica essa pasta importa no Linux: lá /tmp costuma ser tmpfs (montado
// NA RAM — padrão em Arch, Fedora, Debian 13+ e várias outras), então todo
// cache que o Chromium escreve nela (GPU/shader, código, blobs...) ocupa
// memória de verdade, não disco. E como era uma pasta nova por PID que
// ninguém apagava, cada abertura do app deixava mais uma pra trás — RAM que
// só voltava reiniciando o PC, e que não aparece como memória do processo
// (fica em "shared"/"buff/cache" no `free`). No Linux vai pra ~/.cache
// (disco), e em qualquer SO a pasta é apagada ao sair, com as órfãs de
// execuções anteriores (crash/kill) limpas ao abrir.
const INSTANCE_DIR_PREFIX = 'p2p-screen-broadcast-';
const instanceDirsBase = process.platform === 'linux'
  ? path.join(app.getPath('cache'), 'sinal-p2p', 'instances')
  : app.getPath('temp');
const instanceUserData = path.join(instanceDirsBase, `${INSTANCE_DIR_PREFIX}${process.pid}`);
app.setPath('userData', instanceUserData);

function processIsAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code === 'EPERM'; // existe, só não é nosso
  }
}

function removeStaleInstanceDirs() {
  const bases = new Set([instanceDirsBase, app.getPath('temp')]); // temp: sobras de versões anteriores no Linux
  bases.forEach((base) => {
    let entries;
    try {
      entries = fs.readdirSync(base);
    } catch {
      return;
    }
    entries.forEach((entry) => {
      if (!entry.startsWith(INSTANCE_DIR_PREFIX)) return;
      const pid = Number(entry.slice(INSTANCE_DIR_PREFIX.length));
      if (!Number.isInteger(pid) || pid === process.pid || processIsAlive(pid)) return;
      fs.rm(path.join(base, entry), { recursive: true, force: true }, () => {});
    });
  });
}

// No Windows o Chromium ainda pode estar segurando arquivos aqui e isso
// falha em parte — tudo bem, o removeStaleInstanceDirs da próxima abertura pega.
app.on('quit', () => {
  try {
    fs.rmSync(instanceUserData, { recursive: true, force: true });
  } catch {
    // não crítico
  }
});

ipcMain.handle('clipboard:write', (event, text) => clipboard.writeText(text));
ipcMain.handle('clipboard:read', () => clipboard.readText());
ipcMain.handle('capture:supportsSystemAudio', () => supportsSystemAudioLoopback);

// Captura de áudio por processo (Windows via módulo nativo, Linux via
// PipeWire — ver native/audio-loopback). Deixa incluir só um app específico,
// ou excluir um app específico do resto — útil pra tirar uma chamada de voz
// (Discord, etc) do que é compartilhado, sem depender de rotear áudio
// manualmente pro SO.
ipcMain.handle('audio-process:supported', () => processAudio.supported);
ipcMain.handle('audio-process:list', () => processAudio.listProcesses());

ipcMain.handle('audio-process:start', async (event, { pid, exclude }) => {
  const webContents = event.sender;
  const handle = await processAudio.startCapture(pid, exclude, (error, samples, sampleRate, channels) => {
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

// Ver comentário grande acima (maybeExplainMinimizeDisabled) sobre o porquê.
ipcMain.on('sharing:active', (event, active) => {
  const win = BrowserWindow.fromWebContents(event.sender);
  if (!win || win.isDestroyed()) return;
  win.setMinimizable(!active);
  diag(`compartilhando a tela: ${active ? 'começou' : 'parou'} (janela ${win.isMinimized() ? 'minimizada' : 'aberta'})`);
  // Começar a compartilhar cria processos novos (captura de vídeo/áudio).
  if (active) optOutOfBackgroundThrottlingSoon('compartilhar');
  if (active) maybeExplainMinimizeDisabled();
});

// Linhas de diagnóstico vindas da página (ex: qual codec cada conexão usa).
ipcMain.on('diag:log', (event, line) => {
  if (typeof line === 'string') diag('página: ' + line.slice(0, 500));
});

// Canal de sinalização sem servidor (ver signal-punch.js): cada participante
// de uma sala abre o próprio "ponto de encontro" (UDP local/STUN/UPnP +
// retransmissor ntfy.sh) e mantém aberto pela sessão inteira — usado tanto
// pra entrar na sala (o código da sala carrega o ponto de encontro de quem
// criou) quanto pra formar a malha de conexões WebRTC entre todo mundo
// depois (oferta/resposta trocadas direto entre cada par, sem passar pelo
// host de novo).
ipcMain.handle('signal:startListener', async (event) => {
  const webContents = event.sender;
  let handle;
  handle = await signalPunch.startListener({
    onMessage: (message, meta) => {
      if (webContents.isDestroyed()) return;
      webContents.send('signal:message', { sessionId: handle.sessionId, message, from: meta.from });
    },
  });
  if (!handle) return null; // nem IP local nem STUN disponíveis — sem atalho automático

  if (!activeSignalListeners.has(webContents.id)) activeSignalListeners.set(webContents.id, new Map());
  activeSignalListeners.get(webContents.id).set(handle.sessionId, handle);

  return { sessionId: handle.sessionId, candidates: handle.candidates };
});

ipcMain.handle('signal:stopListener', (event, sessionId) => {
  const listeners = activeSignalListeners.get(event.sender.id);
  const handle = listeners && listeners.get(sessionId);
  if (handle) {
    handle.stop();
    listeners.delete(sessionId);
  }
});

ipcMain.handle('signal:kick', (event, sessionId) => {
  const listeners = activeSignalListeners.get(event.sender.id);
  const handle = listeners && listeners.get(sessionId);
  if (handle) handle.kick();
});

ipcMain.handle('signal:send', (event, { mySessionId, candidates, targetSessionId, message, opts }) => {
  const listeners = activeSignalListeners.get(event.sender.id);
  const handle = listeners && listeners.get(mySessionId);
  if (!handle) return Promise.resolve({ ok: false, via: null });
  return handle.send(candidates, targetSessionId, message, opts);
});

// Lista as telas disponíveis (com miniatura) pra deixar o usuário escolher
// qual monitor compartilhar — inclusive pra trocar de monitor com a
// transmissão já rolando, sem depender do seletor nativo do SO (que só
// aparece no início, e nem existe no Linux).
//
// No Linux (testado num Wayland/Mutter), pedir a miniatura em si — o
// thumbnailSize abaixo — parece ser o que causa aquela piscada rápida na
// tela ao entrar numa sala (o compositor grava um frame de verdade da tela
// pra gerar a imagem). Testando sem miniatura nenhuma lá (só o nome/id de
// cada tela) pra ver se é isso mesmo; se for, o preview visual do seletor de
// monitor fica sem imagem no Linux, só com o nome.
ipcMain.handle('capture:listScreens', async () => {
  const sources = await desktopCapturer.getSources({
    types: ['screen'],
    thumbnailSize: process.platform === 'linux' ? { width: 0, height: 0 } : { width: 320, height: 180 },
  });
  const displays = screen.getAllDisplays();
  return sources.map((s) => {
    const size = physicalDisplaySize(s, displays);
    return {
      id: s.id,
      name: s.name,
      thumbnail: s.thumbnail.isEmpty() ? null : s.thumbnail.toDataURL(),
      width: size ? size.width : null,
      height: size ? size.height : null,
    };
  });
});

// Resolução real (em pixels físicos, não em DIP — um monitor 1440p com
// escala de 150% aparece como 1707x960 em display.size) do monitor por trás
// de uma fonte do desktopCapturer — usada pra só oferecer "1440p" na
// configuração de qualidade quando o monitor tem pelo menos isso. No Linux
// (Wayland/portal) o display_id às vezes vem vazio; com um monitor só ainda
// dá pra saber qual é, com mais de um fica desconhecido (null).
function physicalDisplaySize(source, displays) {
  const display =
    displays.find((d) => String(d.id) === source.display_id) ||
    (displays.length === 1 ? displays[0] : null);
  if (!display) return null;
  return {
    width: Math.round(display.size.width * display.scaleFactor),
    height: Math.round(display.size.height * display.scaleFactor),
  };
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1100,
    height: 720,
    autoHideMenuBar: true,
    title: 'Sinal P2P',
    icon: path.join(__dirname, 'assets', 'icon.png'),
    backgroundColor: '#15161a',
    // Sem isso, a janela aparece assim que criada e só ganha conteúdo
    // depois que renderer/index.html termina de carregar/pintar — nesse
    // intervalo dá pra ver uma piscada (janela em branco/cor de fundo do SO
    // por um instante antes do primeiro frame real). Escondida até
    // 'ready-to-show' (que só dispara depois do primeiro frame já pintado)
    // evita esse intervalo visível inteiro.
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      // Desliga o DevTools (Ctrl+Shift+I/F12 e qualquer chamada a
      // openDevTools()) nos executáveis empacotados, para o usuário final não
      // conseguir abrir o console. Continua disponível rodando via
      // "npm start"/"electron .", já que app.isPackaged só é true num build.
      devTools: !app.isPackaged,
      // Sem isso, o vídeo (com som) de quem entrou na sala e só começou a
      // compartilhar bem depois de qualquer clique na janela ficava com o
      // autoplay bloqueado pela política padrão do Chromium (que existe pra
      // sites não tocarem som sem permissão do usuário) — a conexão e o
      // vídeo chegavam certinho, só nunca eram exibidos, sem erro nenhum.
      // Este é um app desktop nosso, não um site de terceiros; a
      // transmissão de tela SEMPRE deve tocar automaticamente.
      autoplayPolicy: 'no-user-gesture-required',
      // Por padrão o Electron desacelera a renderização de janelas sem foco
      // (pra economizar recursos) — o processamento de rede/decodificação
      // do WebRTC continua rodando (confirmado: os frames continuam sendo
      // decodificados nas estatísticas), mas a pintura do <video> na tela
      // trava, ficando preso em "nada carregado ainda" até a janela voltar
      // a ficar em foco. Isso é fatal pra um app que mostra vídeo de várias
      // pessoas ao mesmo tempo — a pessoa não fica o tempo todo com a
      // janela em foco, e cada participante da sala roda numa janela
      // separada.
      backgroundThrottling: false,
    },
  });
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  win.once('ready-to-show', () => win.show());

  // O app é uma página local só: nunca navega pra outro endereço nem abre
  // janela nova. Bloquear isso garante que nada vindo da rede (um nome de
  // participante, um link arrastado pra janela) consiga levar a janela —
  // que tem acesso às APIs do preload — pra um conteúdo de fora.
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', (event) => event.preventDefault());

  // Toda vez que a página carrega/recarrega, o estado de "compartilhando"
  // do renderer começa do zero — sem isso, um reload em pleno
  // compartilhamento (ex: DevTools) deixaria minimizar desabilitado pra
  // sempre, já que só o renderer avisa quando volta a compartilhar de novo.
  win.webContents.on('did-finish-load', () => {
    win.setMinimizable(true);
    optOutOfBackgroundThrottlingSoon('página carregada'); // o renderer só existe a partir daqui
  });

  // Histórico das mudanças de estado da janela no diagnóstico: se o PC
  // travar de novo, dá pra ver se foi logo depois de minimizar/restaurar.
  ['minimize', 'restore', 'hide', 'show'].forEach((eventName) => {
    win.on(eventName, () => diag(`janela: ${eventName}`));
  });

  // Avisa o renderer quando a janela some/volta (minimizar, esconder). Com
  // backgroundThrottling desligado (necessário, ver acima), a página fica
  // "visible" pra sempre pela Page Visibility API — o renderer não teria
  // como saber sozinho que ninguém está olhando, e continuaria pedindo
  // vídeo em qualidade cheia de todo mundo (ver updateViewRequests).
  const sendWindowVisible = (visible) => {
    if (!win.webContents.isDestroyed()) win.webContents.send('window:visible', visible);
  };
  win.on('minimize', () => sendWindowVisible(false));
  win.on('hide', () => sendWindowVisible(false));
  win.on('restore', () => sendWindowVisible(true));
  win.on('show', () => sendWindowVisible(!win.isMinimized()));

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
      signalListeners.forEach((handle) => handle.stop());
      activeSignalListeners.delete(win.webContents.id);
    }
  });
}

app.whenReady().then(() => {
  // Sem verificador ortográfico: os campos de texto do app são só
  // código/senha/nome, não precisam disso, e o serviço de spellcheck do
  // Chromium carrega dicionários inteiros na memória à toa.
  session.defaultSession.setSpellCheckerEnabled(false);

  // Por padrão o Electron concede QUALQUER permissão que a página pedir
  // (localização, notificações, USB, ...). O app só precisa de captura de
  // mídia (microfone/tela) — o resto é negado.
  const ALLOWED_PERMISSIONS = new Set(['media', 'display-capture']);
  session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => {
    callback(ALLOWED_PERMISSIONS.has(permission));
  });
  session.defaultSession.setPermissionCheckHandler((webContents, permission) => ALLOWED_PERMISSIONS.has(permission));

  removeStaleInstanceDirs();
  processAudio.cleanupOrphans();

  registerDisplayMediaHandler(session.defaultSession);

  diag(`app iniciado (v${app.getVersion()}, Electron ${process.versions.electron}, ${process.platform})`);
  optOutOfBackgroundThrottling('início');
  // Rede de segurança pra processos que o Chromium cria sem avisar (ou recria
  // depois de uma queda do processo de GPU, por exemplo).
  setInterval(() => optOutOfBackgroundThrottling('periódico'), 5000).unref();

  createWindow();
  ensureFirewallAccess(); // não bloqueia a abertura da janela — a caixa de diálogo aparece por cima

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
