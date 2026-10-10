// Dois hosts do mesmo serviço público de STUN (Google): se um não responder,
// o endereço público ainda é descoberto pelo outro.
const ICE_SERVERS = [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] }];

const SHARE_ICON_SVG =
  '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
  '<rect x="2" y="4" width="20" height="13" rx="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>';
const STOP_ICON_SVG =
  '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><rect x="5" y="5" width="14" height="14" rx="2"></rect></svg>';
const ENTER_FULLSCREEN_ICON_SVG =
  '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
  '<path d="M8 3H5a2 2 0 0 0-2 2v3"></path><path d="M21 8V5a2 2 0 0 0-2-2h-3"></path><path d="M3 16v3a2 2 0 0 0 2 2h3"></path><path d="M16 21h3a2 2 0 0 0 2-2v-3"></path></svg>';
const EXIT_FULLSCREEN_ICON_SVG =
  '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
  '<path d="M8 3v3a2 2 0 0 1-2 2H3"></path><path d="M21 8h-3a2 2 0 0 1-2-2V3"></path><path d="M3 16h3a2 2 0 0 1 2 2v3"></path><path d="M16 21v-3a2 2 0 0 1 2-2h3"></path></svg>';
// Ícone composto (seta + pessoas, lado a lado, não empilhado) do botão que
// oculta/mostra a tira de miniaturas dos outros participantes na view de
// foco: seta pra cima quando a tira já está escondida (modo exclusivo),
// seta pra baixo quando ainda está visível (clicar entra no modo
// exclusivo).
const PEOPLE_CHEVRON_UP_SVG =
  '<svg viewBox="0 0 36 20" width="28" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
  '<polyline points="2 12 6 4 10 12"></polyline>' +
  '<g transform="translate(14,2) scale(0.667)" stroke-width="3">' +
  '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle>' +
  '<path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path>' +
  '</g></svg>';
const PEOPLE_CHEVRON_DOWN_SVG =
  '<svg viewBox="0 0 36 20" width="28" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
  '<polyline points="2 4 6 12 10 4"></polyline>' +
  '<g transform="translate(14,2) scale(0.667)" stroke-width="3">' +
  '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle>' +
  '<path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path>' +
  '</g></svg>';

// ---------- utilidades de código (criptografia/codificação) ----------

// O código de sala carrega o ponto de encontro (id de sessão + candidatos
// IP:porta) de quem o gerou — nenhum SDP. Com uma senha combinada por outro
// canal (voz, presencial), o payload vira AES-GCM de verdade; sem senha, cai
// no formato antigo (prefixo "P1."), só codificado. "E1." identifica um
// código criptografado para que o lado que decodifica saiba se precisa pedir
// a senha.
const PBKDF2_ITERATIONS = 100000;

function bufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function deriveKey(passphrase, salt, usage) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    [usage]
  );
}

async function encode(obj, passphrase) {
  const json = JSON.stringify(obj);
  if (!passphrase) {
    return 'P1.' + btoa(unescape(encodeURIComponent(json)));
  }

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt, 'encrypt');
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(json));

  const combined = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(ciphertext), salt.length + iv.length);
  return 'E1.' + bufToBase64(combined.buffer);
}

async function decode(str, passphrase) {
  const trimmed = str.trim();
  const prefix = trimmed.slice(0, 3);
  const payload = trimmed.slice(3);

  if (prefix === 'P1.') {
    return JSON.parse(decodeURIComponent(escape(atob(payload))));
  }

  if (prefix === 'E1.') {
    if (!passphrase) {
      throw new Error('Este código é protegido por senha. Informe a senha combinada.');
    }
    const combined = base64ToBytes(payload);
    const salt = combined.slice(0, 16);
    const iv = combined.slice(16, 28);
    const ciphertext = combined.slice(28);
    const key = await deriveKey(passphrase, salt, 'decrypt');
    try {
      const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
      return JSON.parse(new TextDecoder().decode(plainBuf));
    } catch (err) {
      throw new Error('Senha incorreta ou código inválido.');
    }
  }

  throw new Error('Código não reconhecido.');
}

function randomPeerId() {
  const bytes = crypto.getRandomValues(new Uint8Array(9));
  return bufToBase64(bytes.buffer).replace(/[+/=]/g, '');
}

// ---------- criptografia da sinalização ----------
//
// Toda mensagem trocada entre participantes — oferta/resposta (com os IPs
// de cada um e a impressão digital DTLS que protege o vídeo/áudio), lista
// da sala, nomes — vai cifrada e autenticada com a CHAVE DA SALA (AES-GCM,
// 256 bits), que viaja dentro do código da sala. Antes isso ia em texto
// puro pelo UDP e pelo ntfy.sh: dava pra ler (o ntfy guardava 12h, e o id
// do tópico aparece aberto nos pacotes UDP) e, pior, pra INJETAR uma
// resposta com outra impressão digital DTLS e ficar no meio do vídeo. Agora
// quem não tem o código não lê nem forja nada; a senha opcional continua
// protegendo o código em si (ver encode/decode).
//
// - A mensagem é compactada antes de cifrar (SDP compacta ~3x): menos
//   pedaços, menos cota do ntfy gasta.
// - O id de sessão de quem manda entra como dado autenticado (AAD): uma
//   mensagem cifrada não vale se reaproveitada como vinda de outra pessoa.
// - IVs já vistos são recusados: reenviar uma mensagem capturada (replay)
//   não tem efeito.
const SIGNAL_AAD_PREFIX = 'sinal-p2p/v2|';
const MAX_SIGNAL_PLAINTEXT_BYTES = 256 * 1024;
const MAX_SEEN_SIGNAL_IVS = 10000;
let roomKey = null; // CryptoKey da sala atual
let roomKeyB64 = null; // a mesma chave, pra embutir nos códigos de convite
const seenSignalIvs = new Set();

function newRoomKeyB64() {
  return bufToBase64(crypto.getRandomValues(new Uint8Array(32)).buffer);
}

async function setRoomKey(b64) {
  const bytes = base64ToBytes(b64);
  if (bytes.length !== 32) throw new Error('chave da sala inválida');
  roomKey = await crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
  roomKeyB64 = b64;
}

function clearRoomKey() {
  roomKey = null;
  roomKeyB64 = null;
  seenSignalIvs.clear();
}

async function deflateBytes(bytes) {
  const stream = new Blob([bytes]).stream().pipeThrough(new CompressionStream('deflate-raw'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

// Com teto de tamanho: um "zip bomb" (poucos bytes que descompactam pra
// gigabytes) de um participante mal-intencionado não esgota a memória.
async function inflateBytes(bytes) {
  const reader = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw')).getReader();
  const parts = [];
  let total = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_SIGNAL_PLAINTEXT_BYTES) {
      reader.cancel().catch(() => {});
      throw new Error('mensagem grande demais');
    }
    parts.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

async function sealSignal(message, mySessionId) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const compressed = await deflateBytes(new TextEncoder().encode(JSON.stringify(message)));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(SIGNAL_AAD_PREFIX + mySessionId) },
    roomKey,
    compressed
  );
  const out = new Uint8Array(iv.length + ciphertext.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ciphertext), iv.length);
  return { e: bufToBase64(out.buffer) };
}

// Devolve a mensagem original, ou null se não deu pra abrir (sem a chave da
// sala, adulterada, de outra versão do app, repetida...).
async function openSignal(sealed, fromSessionId) {
  if (!roomKey || !sealed || typeof sealed.e !== 'string' || typeof fromSessionId !== 'string') return null;
  const ivKey = sealed.e.slice(0, 16); // 16 caracteres de base64 = exatamente os 12 bytes do IV
  if (seenSignalIvs.has(ivKey)) return null;
  try {
    const bytes = base64ToBytes(sealed.e);
    if (bytes.length < 12 + 16) return null;
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: bytes.slice(0, 12), additionalData: new TextEncoder().encode(SIGNAL_AAD_PREFIX + fromSessionId) },
      roomKey,
      bytes.slice(12)
    );
    const message = JSON.parse(new TextDecoder().decode(await inflateBytes(new Uint8Array(plain))));
    seenSignalIvs.add(ivKey);
    if (seenSignalIvs.size > MAX_SEEN_SIGNAL_IVS) seenSignalIvs.delete(seenSignalIvs.values().next().value);
    return message;
  } catch {
    return null;
  }
}

// ---------- telas ----------

const viewHome = document.getElementById('view-home');
const viewRoom = document.getElementById('view-room');

// O aviso de "deixe a rede como Privada" só faz sentido no Windows (é lá
// que o Firewall do SO bloqueia conexão direta em rede Pública), sem IPC
// dedicado pra isso, `navigator.platform` já resolve dentro do Electron.
if (/^Win/.test(navigator.platform)) {
  document.getElementById('home-windows-note').hidden = false;
}

function showHomeScreen() {
  viewRoom.classList.remove('active');
  viewHome.classList.add('active');
  stopDockAutoHide();
}

function showRoomScreen() {
  viewHome.classList.remove('active');
  viewRoom.classList.add('active');
  startDockAutoHide();
}

// ===================================================================
// HOME — criar/entrar em sala
// ===================================================================

const createNameInput = document.getElementById('create-name-input');
const createPassphraseInput = document.getElementById('create-passphrase-input');
const btnCreateRoom = document.getElementById('btn-create-room');

const joinNameInput = document.getElementById('join-name-input');
const joinCodeInput = document.getElementById('join-code-input');
const pasteJoinCodeBtn = document.getElementById('paste-join-code');
const joinPassphraseInput = document.getElementById('join-passphrase-input');
const btnJoinRoom = document.getElementById('btn-join-room');
const createAlertEl = document.getElementById('create-alert');
const joinAlertEl = document.getElementById('join-alert');

// Erro mostrado dentro do painel (criar/entrar) que causou ele, logo acima
// do botão; texto vazio esconde.
function setHomeAlert(alertEl, text) {
  alertEl.querySelector('.pane-alert-text').textContent = text;
  alertEl.hidden = !text;
}

function clearHomeAlerts() {
  setHomeAlert(createAlertEl, '');
  setHomeAlert(joinAlertEl, '');
}

// Enquanto cria/entra, o botão clicado vira "spinner + Criando sala..." e
// os dois botões ficam travados (sem isso dava pra disparar criar e entrar
// ao mesmo tempo). busyText null restaura.
function setHomeBusy(button, busyText) {
  [btnCreateRoom, btnJoinRoom].forEach((btn) => { btn.disabled = !!busyText; });
  if (busyText) {
    button.dataset.label = button.textContent;
    button.classList.add('is-busy');
    button.innerHTML = '<span class="btn-spinner" aria-hidden="true"></span>';
    button.append(busyText);
  } else if (button.dataset.label) {
    button.classList.remove('is-busy');
    button.textContent = button.dataset.label;
    delete button.dataset.label;
  }
}

// Mexer no código/senha depois de um "Código inválido" tira o aviso — ele
// já não se refere mais ao que está escrito.
[joinCodeInput, joinPassphraseInput].forEach((input) => {
  input.addEventListener('input', () => setHomeAlert(joinAlertEl, ''));
});

pasteJoinCodeBtn.addEventListener('click', async () => {
  joinCodeInput.value = await window.api.readClipboard();
});

btnCreateRoom.addEventListener('click', async () => {
  const name = createNameInput.value.trim() || 'Anônimo';
  const passphrase = createPassphraseInput.value.trim();
  clearHomeAlerts();
  setHomeBusy(btnCreateRoom, 'Criando sala...');
  try {
    await enterRoom({ name, passphrase });
  } finally {
    setHomeBusy(btnCreateRoom, null);
  }
});

btnJoinRoom.addEventListener('click', async () => {
  const name = joinNameInput.value.trim() || 'Anônimo';
  const passphrase = joinPassphraseInput.value.trim();
  clearHomeAlerts();
  let decoded;
  try {
    decoded = await decode(joinCodeInput.value, passphrase);
  } catch (err) {
    setHomeAlert(joinAlertEl, 'Código inválido: ' + err.message);
    return;
  }
  if (!decoded || typeof decoded.sid !== 'string' || !Array.isArray(decoded.cands)) {
    setHomeAlert(joinAlertEl, 'Código inválido: não parece ser um código de sala.');
    return;
  }
  if (typeof decoded.k !== 'string') {
    setHomeAlert(
      joinAlertEl,
      'Esse código é de uma versão antiga do Sinal P2P. Peça um código novo pra quem está na sala — todo mundo precisa estar na versão nova.'
    );
    return;
  }

  setHomeBusy(btnJoinRoom, 'Entrando na sala...');
  try {
    await enterRoom({ name, passphrase, hostSid: decoded.sid, hostCands: decoded.cands, roomKeyCode: decoded.k });
  } finally {
    setHomeBusy(btnJoinRoom, null);
  }
});

// ===================================================================
// SALA — estado, sinalização e malha de conexões
// ===================================================================

let myPeerId = null;
let myName = '';
let myPassphrase = '';
let myListener = null; // { sessionId, candidates }
let unsubscribeSignal = null;
let roomPeers = new Map(); // peerId -> estado de cada participante (ver connectToPeer)
let myInviteCodePromise = null;
// true depois que já estou de fato na sala (criei, ou recebi o "welcome") —
// quem aparecer a partir daí "entrou na sala" (ver announceJoin).
let roomReady = false;
// Quem saiu de propósito ("peer-left"): mensagens atrasadas deles não podem
// trazê-los de volta (ver handleSignalMessage).
const departedPeerIds = new Set();
// Quem caiu por falta de conexão (não saiu): peerId -> {peerId, name, sid,
// cands}. Se eu ficar sozinho, é pra eles que mando "join" pra tentar voltar
// (ver maybeStartRejoin).
const lostPeers = new Map();
let focusedPeerId = null; // null | 'self' | peerId
let focusStripCollapsed = false; // esconde a tira de miniaturas na view de foco (ver btnToggleFocusStrip)
let mySharing = false;
// Cresce a cada vez que começo/paro de compartilhar. Vai junto com o estado
// (mensagem "sharing" e toda oferta/resposta) pra quem recebe descartar um
// estado mais velho que chegue atrasado depois de um mais novo.
let mySharingVersion = 0;
let localStream = null;
// Agenda a saída automática dessa "sala fantasma" (só você, ninguém
// conectado) alguns segundos depois de um "Entrar" que falhou — ver o `if
// (!result.ok)` abaixo. Guardado à parte pra poder cancelar se a pessoa
// clicar em "Sair da sala" antes do tempo, e pra `leaveRoom()` não tentar
// disparar de novo depois.
let joinFailureAutoLeaveTimer = null;

const roomNameLabel = document.getElementById('room-name-label');
const btnCopyRoomCode = document.getElementById('btn-copy-room-code');
const btnLeaveRoom = document.getElementById('btn-leave-room');
const btnToggleParticipants = document.getElementById('btn-toggle-participants');
const btnToggleFullscreen = document.getElementById('btn-toggle-fullscreen');
const participantsPanel = document.getElementById('participants-panel');
const participantsListEl = document.getElementById('participants-list');
const roomStatusEl = document.getElementById('room-status');

const gridEmptyEl = document.getElementById('grid-empty');
const streamGridEl = document.getElementById('stream-grid');
const focusViewEl = document.getElementById('focus-view');
const focusMainEl = document.getElementById('focus-main');
const focusStripEl = document.getElementById('focus-strip');
const btnToggleFocusStrip = document.getElementById('btn-toggle-focus-strip');
btnToggleFocusStrip.innerHTML = PEOPLE_CHEVRON_DOWN_SVG;

function setRoomStatus(text) {
  roomStatusEl.textContent = text;
  roomStatusEl.hidden = !text;
}

// Traduz o diagnóstico vindo de signal-punch.js (`result.ntfy`, ver
// `summarizeNtfyOutcome` lá) numa mensagem específica — em vez de um erro
// genérico só, dá pra saber pelo front se o problema foi o relé ntfy.sh
// (inalcançável ou limitando taxa) ou o código/sessão de destino em si.
function joinFailureMessage(result) {
  if (result.ntfy === 'rate-limited' && result.mqtt === 'ok') {
    return 'Não consegui entrar — o ntfy.sh atingiu o limite e a mensagem foi pelo servidor reserva (MQTT), mas ninguém respondeu: código expirado ou a pessoa não está mais na sala.';
  }
  if (result.ntfy === 'rate-limited' && (result.mqtt === 'failed' || result.mqtt === 'unavailable')) {
    return 'Não consegui entrar — o ntfy.sh atingiu o limite e o servidor reserva (MQTT) também não respondeu. Tente de novo mais tarde.';
  }
  switch (result.ntfy) {
    case 'unreachable':
      return 'Não consegui entrar — o servidor de retransmissão (ntfy.sh) está inacessível agora, provavelmente bloqueado temporariamente por excesso de uso. Tente de novo mais tarde.';
    case 'rate-limited':
      return 'Não consegui entrar — o servidor de retransmissão (ntfy.sh) está limitando conexões por excesso de uso. Tente de novo em alguns minutos.';
    case 'error':
      return 'Não consegui entrar — o servidor de retransmissão (ntfy.sh) recusou a mensagem. Tente de novo em alguns minutos.';
    case 'ok':
      return 'Não consegui entrar — código expirado ou a pessoa não está mais na sala. Confira o código e tente de novo.';
    default:
      return 'Não consegui entrar — código expirado, offline, ou problema de rede.';
  }
}

async function enterRoom({ name, passphrase, hostSid, hostCands, roomKeyCode }) {
  try {
    await setRoomKey(hostSid ? roomKeyCode : newRoomKeyB64());
  } catch {
    setHomeAlert(joinAlertEl, 'Código inválido: a chave da sala está corrompida.');
    return;
  }
  myPeerId = randomPeerId();
  myName = name;
  myPassphrase = passphrase;
  mySharing = false;
  focusedPeerId = null;
  roomPeers = new Map();
  roomReady = !hostSid;
  departedPeerIds.clear();
  lostPeers.clear();
  rejoinGaveUp = false;
  localStream = null;
  // Limpa qualquer mensagem deixada por uma tentativa anterior (ex: "não
  // consegui entrar na sala" de um código antigo que falhou) — sem isso, ela
  // ficava perdida em #room-status e reaparecia na sala nova, mesmo
  // funcionando normalmente, porque só o fluxo de "Entrar" (hostSid) mexe
  // nesse texto: criar uma sala nova nunca escrevia nada nele pra sobrescrever.
  setRoomStatus('');

  myListener = await window.api.startSignalListener();
  if (!myListener) {
    setHomeAlert(hostSid ? joinAlertEl : createAlertEl, 'Conexão automática indisponível nessa rede — não é possível criar ou entrar em salas.');
    return;
  }

  unsubscribeSignal = window.api.onSignalMessage(({ message, from }) => receiveSignal(message, from));

  myFarewellSealed = await sealSignal({ t: 'peer-left', peerId: myPeerId }, myListener.sessionId);

  roomNameLabel.textContent = hostSid ? 'Sala' : `Sala de ${myName}`;
  myInviteCodePromise = encode({ v: 2, sid: myListener.sessionId, cands: myListener.candidates, k: roomKeyB64 }, myPassphrase);

  showRoomScreen();
  clearToasts();
  updateConnectionBanner();
  resetMediaTileRegistries();
  renderParticipants();
  renderGrid();
  updateShareButtonUI();
  refreshMonitors();
  window.api.supportsSystemAudio().then((supported) => {
    supportsLoopback = supported;
    document.getElementById('audio-hint').hidden = supported;
    refreshAudioSources();
  });
  window.api.supportsProcessAudio().then((supported) => {
    supportsProcessAudio = supported;
    refreshAudioSources();
  });

  if (hostSid) {
    setRoomStatus('Entrando na sala...');
    const joinMessage = { t: 'join', peerId: myPeerId, name: myName, sid: myListener.sessionId, cands: myListener.candidates };
    const listener = myListener;
    // Quem decide se deu certo é o "welcome" (ou alguém da sala conectar),
    // não a confirmação de entrega do "join". Antes, se a confirmação se
    // perdesse — mesmo com o "join" tendo chegado e a sala funcionando —,
    // o app agendava a volta pra tela inicial; o "welcome" apagava a
    // mensagem de erro mas não cancelava isso, e a pessoa era tirada da sala
    // sem aviso nenhum ~10s depois de entrar.
    let result = { ok: false, via: null };
    for (let attempt = 0; attempt < JOIN_ATTEMPTS && !roomReady && myListener === listener; attempt++) {
      result = await sendToPeer({ sid: hostSid, cands: hostCands }, joinMessage);
      if (result.ok) break;
    }
    // Sem confirmação, o "join" ainda pode ter chegado: espera o "welcome"
    // mais um pouco antes de desistir.
    const deadline = Date.now() + JOIN_WELCOME_GRACE_MS;
    while (!roomReady && myListener === listener && Date.now() < deadline && !result.ok) {
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    if (myListener !== listener) return; // saiu no meio
    if (roomReady) {
      setRoomStatus(''); // já entrou (welcome ou alguém conectou)
      return;
    }
    if (!result.ok) {
      setRoomStatus(joinFailureMessage(result) + ' Voltando ao início...');
      // Sem isso a pessoa ficava presa numa "sala" sozinha, sem ninguém
      // conectado, até clicar em "Sair da sala" por conta própria — agora
      // volta pra tela inicial sozinha depois de um tempo pra dar chance de
      // ler a mensagem. Cancelado se o "welcome" ainda chegar (markJoinedRoom)
      // ou se a pessoa sair antes (leaveRoom).
      joinFailureAutoLeaveTimer = setTimeout(() => {
        joinFailureAutoLeaveTimer = null;
        leaveRoom();
      }, 10000);
    } else {
      setRoomStatus('');
    }
  }
}

const JOIN_ATTEMPTS = 2;
const JOIN_WELCOME_GRACE_MS = 8000;

// Prova de que estou na sala: chegou o "welcome" ou alguém conectou. Cancela
// uma volta automática pra tela inicial agendada por uma confirmação perdida.
function markJoinedRoom() {
  if (joinFailureAutoLeaveTimer) {
    clearTimeout(joinFailureAutoLeaveTimer);
    joinFailureAutoLeaveTimer = null;
    setRoomStatus('');
  }
  roomReady = true;
}

btnCopyRoomCode.addEventListener('click', async () => {
  if (!myInviteCodePromise) return;
  const code = await myInviteCodePromise;
  window.api.copyToClipboard(code);
  setRoomStatus('Código copiado! Qualquer pessoa com esse código pode entrar enquanto você estiver na sala.');
  setTimeout(() => setRoomStatus(''), 4000);
});

btnToggleParticipants.addEventListener('click', () => {
  participantsPanel.hidden = !participantsPanel.hidden;
});

// Modo "tela cheia": o palco passa a ocupar também a linha reservada pra
// dock (que vira overlay flutuando por cima do vídeo, encostando nele por
// baixo) e a moldura ao redor do vídeo fica só com uma borda mínima de
// 10px, sem cantos arredondados (ver .stage-zoomed no CSS). A dock e o
// botão de participantes continuam funcionando normalmente por cima, só
// somem junto com o resto da dock quando o mouse fica parado (ver
// startDockAutoHide abaixo).
let stageZoomed = false;
btnToggleFullscreen.addEventListener('click', () => {
  stageZoomed = !stageZoomed;
  viewRoom.classList.toggle('stage-zoomed', stageZoomed);
  btnToggleFullscreen.classList.toggle('active-toggle', stageZoomed);
  btnToggleFullscreen.innerHTML = stageZoomed ? EXIT_FULLSCREEN_ICON_SVG : ENTER_FULLSCREEN_ICON_SVG;
  btnToggleFullscreen.title = stageZoomed ? 'Sair da tela cheia' : 'Tela cheia';
});

// Dock some sozinha (estilo player de vídeo/PiP): mouse parado por 2s
// dentro da sala esconde a dock e o botão de participantes; mexer o mouse
// (ou o mouse sair da janela) mostra/esconde na hora. Com o popover de
// compartilhar aberto a dock fica sempre visível — ele sai dela, e dá pra
// ficar um tempo lendo/escolhendo sem mexer o mouse. Isso vale também pro
// mouseleave: a lista aberta de um <select> é uma janela nativa fora da
// página, então passar o mouse por ela conta como sair da sala.
let dockIdleTimer = null;
function showDockControls() {
  viewRoom.classList.remove('controls-hidden');
  clearTimeout(dockIdleTimer);
  if (!sharePopover.hidden) return;
  dockIdleTimer = setTimeout(() => viewRoom.classList.add('controls-hidden'), 2000);
}
function stopDockAutoHide() {
  clearTimeout(dockIdleTimer);
  viewRoom.classList.remove('controls-hidden');
}
function startDockAutoHide() {
  showDockControls();
}
viewRoom.addEventListener('mousemove', showDockControls);
viewRoom.addEventListener('mouseenter', showDockControls);
viewRoom.addEventListener('mouseleave', () => {
  clearTimeout(dockIdleTimer);
  if (!sharePopover.hidden) return;
  viewRoom.classList.add('controls-hidden');
});

btnLeaveRoom.addEventListener('click', () => leaveRoom());

// Fechar o app (ou a janela) sem clicar em "Sair da sala" também avisa os
// outros. Sem isso, pra eles parecia uma queda: "reconectando" por um
// minuto até desistir. Melhor esforço: a primeira leva de UDP sai na hora,
// antes do app terminar de fechar.
window.addEventListener('beforeunload', () => sendFarewell());

// O aviso de saída ("peer-left") já fica cifrado desde a entrada na sala
// (ver enterRoom): cifrar é assíncrono, e na hora de sair/fechar o app não
// dá pra esperar — o canal de sinalização fecha logo em seguida. A mesma
// mensagem cifrada serve pra todo mundo (cada um só a vê uma vez). `urgent`
// manda pelo ntfy na hora, sem esperar o UDP tentar primeiro.
let myFarewellSealed = null;

function sendFarewell() {
  if (!myListener || !myFarewellSealed) return;
  const mySessionId = myListener.sessionId;
  roomPeers.forEach((peer) => {
    // Direto primeiro (chega na hora); o externo vai junto porque a conexão
    // fecha logo em seguida e pode não dar tempo de o canal entregar.
    sendDirect(peer, { t: 'peer-left', peerId: myPeerId });
    window.api
      .sendSignalMessage({
        mySessionId,
        candidates: peer.cands,
        targetSessionId: peer.sid,
        message: myFarewellSealed,
        opts: { urgent: true },
      })
      .catch(() => {});
  });
}

function leaveRoom() {
  if (joinFailureAutoLeaveTimer) {
    clearTimeout(joinFailureAutoLeaveTimer);
    joinFailureAutoLeaveTimer = null;
  }

  sendFarewell();
  myFarewellSealed = null;
  roomPeers.forEach((peer) => {
    clearTimeout(peer.recoveryTimer);
    clearTimeout(peer.localCandidateFlushTimer);
    if (peer.pc) peer.pc.close();
  });
  roomPeers.clear();
  clearTimeout(rejoinTimer);
  rejoinTimer = null;
  rejoinGaveUp = false;
  lostPeers.clear();
  departedPeerIds.clear();
  roomReady = false;

  stopSharing();
  clearRoomKey();

  if (myListener) {
    // Fecha o canal só daqui a pouco: dá tempo do aviso de saída ser
    // reenviado por UDP e confirmado (a página já voltou pro início; nada
    // mais é processado daqui, ver unsubscribeSignal logo abaixo).
    const sessionId = myListener.sessionId;
    setTimeout(() => window.api.stopSignalListener(sessionId), 2000);
    myListener = null;
  }
  if (unsubscribeSignal) {
    unsubscribeSignal();
    unsubscribeSignal = null;
  }

  focusedPeerId = null;
  resetMediaTileRegistries();
  participantsPanel.hidden = true;
  hideSharePopover();
  if (focusStripCollapsed) {
    focusStripCollapsed = false;
    btnToggleFocusStrip.innerHTML = PEOPLE_CHEVRON_DOWN_SVG;
    btnToggleFocusStrip.title = 'Ocultar as outras transmissões';
    viewRoom.classList.remove('focus-strip-collapsed');
  }
  if (stageZoomed) {
    stageZoomed = false;
    viewRoom.classList.remove('stage-zoomed');
    btnToggleFullscreen.classList.remove('active-toggle');
    btnToggleFullscreen.innerHTML = ENTER_FULLSCREEN_ICON_SVG;
    btnToggleFullscreen.title = 'Tela cheia';
  }
  // Sem isso, um aviso de erro de uma tentativa anterior à sala (que abriu
  // com sucesso depois) reaparecia do nada ao sair dela.
  clearHomeAlerts();
  clearToasts();
  updateConnectionBanner();
  showHomeScreen();
}

// ---------- protocolo de sinalização (join/welcome/oferta/resposta/sharing) ----------

// "welcome"/"peer-joined" (a apresentação formal de um participante) e as
// mensagens diretas entre um par (offer/answer/sharing) viajam por
// transmissões de rede INDEPENDENTES, sem nenhuma garantia de ordem entre
// elas — então uma oferta pode muito bem chegar antes da apresentação que
// ensinaria quem é o remetente. Por isso toda mensagem direta carrega os
// próprios dados de quem mandou (`sender`), e quem recebe se "apresenta"
// sozinho via connectToPeer (idempotente — não faz nada se já conhecido)
// antes de processar o conteúdo, em vez de depender só de já ter recebido
// "welcome"/"peer-joined" antes. Sem isso, uma mensagem que chegasse cedo
// demais era descartada em silêncio e NUNCA mais reprocessada — foi
// exatamente esse bug que fazia par específicos nunca conectarem (o
// transporte confirma "entregue" assim que a mensagem é remontada, mesmo
// que a aplicação não soubesse o que fazer com ela).
// Mensagens que não abrem (sem a chave da sala, adulteradas, de uma versão
// antiga do app) são descartadas antes de qualquer processamento. Avisa no
// console uma vez por remetente, pra não inundar o log.
const unreadableSignalSenders = new Set();

async function receiveSignal(sealed, from) {
  const message = await openSignal(sealed, from);
  if (!message) {
    if (!unreadableSignalSenders.has(from)) {
      unreadableSignalSenders.add(from);
      console.warn('[room] mensagem que não abre com a chave da sala descartada (versão antiga do app, código de outra sala ou adulterada), de', from);
    }
    return;
  }
  handleSignalMessage(message, from);
}

function handleSignalMessage(message, from) {
  if (!message || typeof message.t !== 'string') return;
  // Quem manda não pode se passar por outro participante: o remetente
  // declarado tem que bater com a sessão de onde a mensagem veio de fato
  // (que, com a chave da sala, também é autenticada — ver openSignal).
  if (message.sender && message.sender.sid !== from) return;
  if (message.t === 'join' && message.sid !== from) return;
  if (message.t === 'peer-left') {
    const leaving = roomPeers.get(message.peerId);
    if (leaving && leaving.sid !== from) return;
  }
  // Quem saiu de propósito ("peer-left") não volta à vida por causa de uma
  // mensagem dele que ainda estava a caminho (as retentativas de UDP/ntfy
  // chegam atrasadas) — sem isso, reaparecia na lista "conectando" pra sempre.
  const senderId = message.sender && message.sender.peerId;
  if (senderId && departedPeerIds.has(senderId)) return;
  switch (message.t) {
    case 'join':
      handleJoin(message);
      break;
    case 'welcome':
      handleWelcome(message);
      break;
    case 'peer-joined':
      if (message.peer) connectToPeer(message.peer);
      break;
    case 'peer-left':
      if (message.peerId) handlePeerLeft(message.peerId);
      break;
    case 'offer':
    case 'answer':
    case 'ice-candidate':
    case 'ice-candidates':
    case 'restart-request': {
      if (message.sender) connectToPeer(message.sender);
      const peer = (senderId && roomPeers.get(senderId)) || findPeerBySid(from);
      if (!peer) {
        console.warn(`[room] "${message.t}" recebido de peer desconhecido (sem sender embutido?)`, from);
        break;
      }
      runSignalingTask(peer, () => handlePeerSignal(peer, message));
      break;
    }
    case 'view': {
      const peer = (senderId && roomPeers.get(senderId)) || findPeerBySid(from);
      if (peer) applyRemoteView(peer, message);
      break;
    }
    case 'sharing': {
      if (message.sender) connectToPeer(message.sender);
      const peer = (senderId && roomPeers.get(senderId)) || findPeerBySid(from);
      if (peer) {
        applyRemoteSharing(peer, !!message.on, message.v);
      } else {
        console.warn('[room] "sharing" recebido de peer desconhecido (sem sender embutido?)', from);
      }
      break;
    }
  }
}

function sharingMessage() {
  return { t: 'sharing', sender: myPeerInfo(), on: mySharing, v: mySharingVersion };
}

function applyRemoteSharing(peer, on, version) {
  if (typeof on !== 'boolean') return;
  if (typeof version === 'number') {
    if (peer.sharingVersion !== null && version < peer.sharingVersion) return; // mais velho que o que já sei
    peer.sharingVersion = version;
  }
  if (peer.sharing === on) return;
  peer.sharing = on;
  // Quem começa a compartilhar parte de "todo mundo me vê em tela cheia"
  // (ver confirmStartSharing); se não é o meu caso, renderGrid/renderFocus
  // abaixo mandam o pedido certo (updateViewRequests).
  if (on) peer.sentView = 'full';
  console.log('[room] status de compartilhamento de', peer.name, '->', on);
  renderGrid();
  renderParticipants();
  renderFocusIfShowing();
}

function handlePeerSignal(peer, message) {
  switch (message.t) {
    case 'offer':
      return handleOffer(peer, message);
    case 'answer':
      return handleAnswer(peer, message);
    case 'ice-candidate': // formato antigo (um por mensagem), pra versões anteriores do app
      return handleRemoteCandidates(peer, message, [message.candidate]);
    case 'ice-candidates':
      return handleRemoteCandidates(peer, message, message.candidates);
    case 'restart-request':
      return handleRestartRequest(peer, message);
  }
}

// Tudo que mexe na negociação de UM par (aplicar oferta/resposta/
// candidatos, criar oferta) roda numa fila, um de cada vez. Com UDP
// reenviando e o ntfy correndo junto, a mesma mensagem (ou uma mais antiga)
// pode chegar duas vezes quase juntas — processadas em paralelo, as duas
// intercalavam setRemoteDescription/createAnswer e uma estragava a outra.
// Nada aqui dentro espera o envio pela rede (isso leva segundos); só as
// operações na RTCPeerConnection, que são rápidas.
function runSignalingTask(peer, task) {
  const run = () => (roomPeers.get(peer.peerId) === peer ? task() : undefined);
  peer.signalingQueue = peer.signalingQueue
    .then(run)
    .catch((err) => console.error('[room] erro na negociação com', peer.name, err));
  return peer.signalingQueue;
}

function findPeerBySid(sid) {
  for (const peer of roomPeers.values()) {
    if (peer.sid === sid) return peer;
  }
  return null;
}

function toPeerInfo(peer) {
  return { peerId: peer.peerId, name: peer.name, sid: peer.sid, cands: peer.cands };
}

function myPeerInfo() {
  // Mesma proteção de sendToPeer: `myListener` pode ter virado null (saiu da
  // sala) entre um await e outro de uma função que ainda está no meio de
  // montar uma mensagem pra mandar — melhor devolver algo inofensivo do que
  // derrubar com uma exceção não relacionada ao que realmente aconteceu.
  if (!myListener) return { peerId: myPeerId, name: myName, sid: null, cands: [] };
  return { peerId: myPeerId, name: myName, sid: myListener.sessionId, cands: myListener.candidates };
}

// Chega em QUALQUER participante que receba um "join" (normalmente só quem
// tem seu próprio ponto de encontro embutido no código de sala usado, mas o
// protocolo não distingue "host" de qualquer outro membro — qualquer um
// pode apresentar um recém-chegado ao resto da sala, inclusive depois que
// quem criou a sala originalmente já saiu).
function handleJoin(message) {
  const peerInfo = { peerId: message.peerId, name: message.name || 'Participante', sid: message.sid, cands: message.cands };
  if (!peerInfo.peerId || !peerInfo.sid || !Array.isArray(peerInfo.cands)) return;
  if (peerInfo.peerId === myPeerId || departedPeerIds.has(peerInfo.peerId) || !myListener) return;

  // Já conhecido: é alguém que perdeu a conexão com a sala inteira e está
  // tentando voltar sozinho (ver attemptRejoin) — do lado dele, todo mundo
  // foi removido, então a apresentação vai de novo, e a conexão antiga com
  // ele (se ainda existir deste lado) não serve mais.
  const known = roomPeers.get(peerInfo.peerId);
  console.log('[room] recebi "join" de', peerInfo.name, known ? '(já conhecido — voltando pra sala)' : '— apresentando pro resto da sala');

  const roster = [...roomPeers.values()].filter((peer) => peer.peerId !== peerInfo.peerId).map(toPeerInfo);
  roster.push(myPeerInfo());

  if (!known) connectToPeer(peerInfo);
  const joiningPeer = roomPeers.get(peerInfo.peerId);
  if (joiningPeer) sendToPeer(joiningPeer, { t: 'welcome', roster }).catch(() => {});

  roomPeers.forEach((peer) => {
    if (peer.peerId === peerInfo.peerId) return;
    sendToPeer(peer, { t: 'peer-joined', peer: peerInfo }).catch(() => {});
  });

  if (known) {
    if (known.connectionState !== 'connected') requestReconnect(known, { full: true });
    sendToPeerReliable(known, sharingMessage()).catch(() => {});
  }
}

function handleWelcome(message) {
  if (!Array.isArray(message.roster)) return;
  console.log('[room] recebi "welcome" com', message.roster.length, 'participante(s) já na sala');
  const wasRejoining = rejoinTimer !== null;
  message.roster.forEach((peerInfo) => connectToPeer(peerInfo));
  markJoinedRoom();
  setRoomStatus('');
  if (wasRejoining) {
    stopRejoin();
    notify('Você voltou pra sala.', 'success');
  }
}

function handlePeerLeft(peerId) {
  departedPeerIds.add(peerId);
  lostPeers.delete(peerId);
  const peer = roomPeers.get(peerId);
  if (!peer) return;
  removePeer(peerId);
  notify(`${peer.name} saiu da sala.`, 'info');
}

// Conta por onde a sinalização está indo — só diagnóstico (console:
// `signalStats`): direto pela conexão WebRTC ou pelo caminho externo
// (UDP/ntfy/MQTT).
const signalStats = { sentDirect: 0, sentExternal: 0, receivedDirect: 0 };

// Depois que dois participantes conectam, tudo entre eles (quem está
// compartilhando, como cada um vê a tela do outro, renegociações,
// apresentações de quem chega, aviso de saída) vai pelo canal de dados da
// própria conexão: direto, mais rápido e sem gastar a cota do ntfy.sh — o
// caminho externo fica só pra entrar na sala e pra reconectar depois de uma
// queda. Só usa o canal com a conexão de pé de verdade: durante uma queda
// ele ainda pode dizer "aberto" sem entregar nada (é justamente quando as
// mensagens de reconexão precisam do caminho externo).
function sendDirect(peer, message) {
  const channel = peer.signalChannel;
  if (!channel || channel.readyState !== 'open') return false;
  if (!peer.pc || peer.pc.connectionState !== 'connected' || peer.downSince !== null) return false;
  try {
    channel.send(JSON.stringify(message));
  } catch {
    return false;
  }
  signalStats.sentDirect++;
  return true;
}

async function sendToPeer(peer, message, opts) {
  if (sendDirect(peer, message)) return { ok: true, via: { source: 'datachannel' } };
  // `myListener` pode virar null no meio de um envio ainda em andamento (ex:
  // saiu da sala/fechou o app enquanto uma retentativa de sendToPeerReliable
  // ainda estava pendente) — sem essa checagem, isso derrubava a função com
  // "Cannot read properties of null (reading 'sessionId')" em vez de só
  // desistir silenciosamente.
  if (!myListener || !roomKey) return { ok: false, via: null };
  const mySessionId = myListener.sessionId;
  const sealed = await sealSignal(message, mySessionId);
  if (!myListener) return { ok: false, via: null }; // saiu enquanto cifrava
  signalStats.sentExternal++;
  return window.api.sendSignalMessage({
    mySessionId,
    candidates: peer.cands,
    targetSessionId: peer.sid,
    message: sealed,
    opts,
  });
}

// Uma tentativa de sendToPeer já é bem persistente por si só (reenvia por
// UDP por ~6s e cai pro retransmissor ntfy — ver signal-punch.js), mas se as
// DUAS vias falharem nessa janela (rede congestionada, o stream ntfy do
// outro lado reconectando bem nesse instante etc.), a tentativa acaba e
// NINGUÉM tenta de novo — a oferta ou resposta simplesmente se perde pra
// sempre e aquele par fica travado. Pra mensagens que realmente precisam
// chegar pra a conexão funcionar (oferta/resposta), tenta de novo algumas
// vezes antes de desistir de verdade.
async function sendToPeerReliable(peer, message, { attempts = 3, opts } = {}) {
  let result = { ok: false, via: null };
  for (let i = 0; i < attempts; i++) {
    if (!roomPeers.has(peer.peerId)) break; // saiu/foi removido no meio
    result = await sendToPeer(peer, message, opts);
    if (result.ok) return result;
    console.warn(
      `[room] envio de "${message.t}" pra`, peer.name,
      `falhou (tentativa ${i + 1}/${attempts}) — ntfy:`, result.ntfy || 'n/d', '| mqtt:', result.mqtt || 'n/d'
    );
  }
  return result;
}

// ---------- malha de conexões WebRTC (uma RTCPeerConnection por par) ----------

// Quem oferece em cada par é SEMPRE o mesmo lado: o de peerId
// lexicograficamente menor. Ele é o único que cria os transceivers e o
// único que manda ofertas (inclusive as de reconexão); o outro lado só
// responde, usando os transceivers que a própria oferta criou.
//
// Isso não é preferência de estilo — era a causa da tela preta pra quem
// entrava depois de alguém já estar compartilhando (e de toda a saga de
// "tela preta" anterior). Antes, os DOIS lados chamavam addTransceiver.
// Pela especificação (JSEP 5.10), ao aplicar a oferta remota o navegador só
// reaproveita transceivers criados por addTrack — os de addTransceiver
// ficam de fora, e ele cria transceivers NOVOS (recvonly) pra oferta.
// Resultado, medido aqui: quem respondia ficava com 4 transceivers, e os 2
// dele (onde a tela era colocada via replaceTrack) com mid=null, fora do
// SDP — nunca transmitiam nada. Quem ofereceu ficava "sendonly", sem evento
// "track", e o vídeo daquela pessoa ficava preto pra sempre (0 frames,
// readyState=0). Quando alguém já transmitindo era quem respondia (o
// recém-chegado tinha o peerId menor), a tela dele nunca chegava pro
// recém-chegado. A "renegociação ao começar a compartilhar" de antes só
// mascarava isso nos outros casos, criando m-lines extras pra esses
// transceivers órfãos.
function isOfferer(peer) {
  return myPeerId < peer.peerId;
}

// Tempos do acompanhamento de cada conexão (ver beginRecovery/recoveryTick).
// "disconnected" costuma voltar sozinho em 1-2s (perda curta de pacotes);
// passou disso, reinicia o ICE (procura caminho de rede novo, mesma
// conexão). Se nem assim voltar, recria a conexão do zero; e depois de um
// minuto sem nada, desiste e avisa.
const INITIAL_CONNECT_GRACE_MS = 15000;
const RECOVERY_FIRST_CHECK_MS = 3000;
const RECOVERY_RETRY_DELAYS_MS = [10000, 15000, 20000];
const RECOVERY_FULL_RESTART_FROM_ATTEMPT = 3;
const RECOVERY_GIVE_UP_MS = 60000;
// Espera a descoberta de candidatos ICE (ou esse tempo) antes de mandar a
// oferta/resposta, pra eles irem dentro do próprio SDP: uma mensagem só, em
// vez do SDP mais 2-3 lotes de candidatos — cada mensagem gasta cota do ntfy
// (ver signal-punch.js). Candidato que aparecer depois disso vai em lote.
const ICE_GATHER_WAIT_MS = 1500;

function connectToPeer(peerInfo) {
  if (!peerInfo || !peerInfo.peerId || peerInfo.peerId === myPeerId || roomPeers.has(peerInfo.peerId)) return;
  if (departedPeerIds.has(peerInfo.peerId) || !peerInfo.sid || !Array.isArray(peerInfo.cands)) return;
  console.log('[room] conhecendo novo participante:', peerInfo.name, peerInfo.peerId);
  const peer = {
    peerId: peerInfo.peerId,
    name: peerInfo.name || 'Participante',
    sid: peerInfo.sid,
    cands: peerInfo.cands,
    pc: null,
    pcId: null, // identidade da MINHA RTCPeerConnection atual com esse par
    remotePcId: null, // identidade da conexão do OUTRO lado com quem a minha está pareada
    videoSender: null,
    audioSender: null,
    outgoingStream: null,
    remoteStream: null,
    remoteStreamFromEvent: false,
    pendingIceCandidates: [],
    unsentLocalCandidates: [],
    gatheredLocalCandidates: [],
    holdingLocalCandidates: false,
    localCandidateFlushTimer: null,
    remoteCandidatesReceived: 0,
    offerSeq: 0,
    pendingOfferSeq: 0,
    lastRemoteOfferSeq: 0,
    lastRestartAt: 0,
    lastScratchAt: 0,
    signalingQueue: Promise.resolve(),
    encodingQueue: Promise.resolve(),
    remoteView: 'full', // como ESSA pessoa está vendo a minha tela (ver applyRemoteView)
    remoteViewVersion: 0,
    sentView: 'full', // como eu disse pra ela que estou vendo a tela DELA
    pcEpoch: 0, // cresce a cada conexão nova minha com esse par (ver createPeerConnection)
    remotePcEpoch: 0, // a mais nova do outro lado que já vi — ofertas de conexões mais velhas são atrasadas
    sharing: false,
    sharingVersion: null,
    volume: 1,
    volumeBeforeMute: 1,
    connectionState: 'new',
    everConnected: false,
    // "Fulano entrou na sala" só pra quem chega DEPOIS de mim — quem já
    // estava lá quando entrei (o roster do welcome) não "entrou" agora, e
    // quem está voltando de uma queda não é novidade.
    announceJoin: roomReady && rejoinTimer === null && !lostPeers.has(peerInfo.peerId),
    downSince: Date.now(), // desde quando está sem conexão (null = conectado)
    reconnecting: false,
    recoveryAttempts: 0,
    recoveryTimer: null,
    timeoutReason: null, // 'signaling' | 'ice' — só pra quem nunca chegou a conectar
  };
  roomPeers.set(peer.peerId, peer);
  lostPeers.delete(peer.peerId);
  createPeerConnection(peer);
  scheduleRecoveryTick(peer, INITIAL_CONNECT_GRACE_MS);
  if (isOfferer(peer)) negotiate(peer);
  if (mySharing) sendToPeerReliable(peer, sharingMessage()).catch(() => {});
  renderParticipants();
}

function createPeerConnection(peer) {
  const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
  peer.pc = pc;
  peer.pcId = randomPeerId();
  peer.pcEpoch = Math.max(Date.now(), peer.pcEpoch + 1);
  peer.remotePcId = null;
  peer.offerSeq = 0;
  peer.pendingOfferSeq = 0;
  peer.lastRemoteOfferSeq = 0;
  peer.videoSender = null;
  peer.audioSender = null;
  // Associa os transceivers a UM MediaStream próprio (mesmo sem track
  // nenhuma ainda) — sem isso, o m-line negociado não carrega um "msid" de
  // verdade, e o `event.streams` do lado de quem recebe chega vazio.
  peer.outgoingStream = new MediaStream();
  peer.remoteStream = null;
  peer.remoteStreamFromEvent = false;
  peer.pendingIceCandidates = [];
  peer.unsentLocalCandidates = [];
  peer.gatheredLocalCandidates = [];
  peer.holdingLocalCandidates = false;
  clearTimeout(peer.localCandidateFlushTimer);
  peer.localCandidateFlushTimer = null;
  peer.connectionState = 'new';

  if (isOfferer(peer)) {
    const videoTransceiver = pc.addTransceiver('video', { direction: 'sendrecv', streams: [peer.outgoingStream] });
    const audioTransceiver = pc.addTransceiver('audio', { direction: 'sendrecv', streams: [peer.outgoingStream] });
    attachLocalTransceivers(peer, videoTransceiver, audioTransceiver);
  }

  // Canal de dados pra sinalização DIRETA com esse par, depois de conectado
  // (ver sendDirect). "negotiated" + id fixo: os dois lados criam o mesmo
  // canal sozinhos, sem precisar combinar quem cria. Vai cifrado e
  // autenticado pelo próprio DTLS da conexão (o mesmo que protege o
  // vídeo), então não passa por sealSignal.
  const signalChannel = pc.createDataChannel('sinal', { negotiated: true, id: 0 });
  peer.signalChannel = signalChannel;
  signalChannel.addEventListener('message', (event) => {
    if (peer.pc !== pc || typeof event.data !== 'string') return;
    let message;
    try {
      message = JSON.parse(event.data);
    } catch {
      return;
    }
    signalStats.receivedDirect++;
    handleSignalMessage(message, peer.sid);
  });

  // Prefere o MediaStream que o próprio evento "track" já entrega
  // (`event.streams[0]`) — é o caminho "oficial"/testado do navegador, ao
  // contrário de montar um MediaStream na mão a partir de
  // `pc.getReceivers()` (ver `syncRemoteStreamFromReceivers`, mantida só
  // como reforço pro caso de `event.streams` vir vazio, ex: versão antiga do
  // app do outro lado).
  pc.addEventListener('track', (event) => {
    if (peer.pc !== pc) return;
    console.log(
      '[room] evento "track" (' + event.track.kind + ') de', peer.name,
      '— streams no evento:', event.streams.length
    );
    if (event.streams[0]) {
      peer.remoteStreamFromEvent = true; // nunca mais deixa o reforço (getReceivers) sobrescrever
      if (peer.remoteStream !== event.streams[0]) {
        peer.remoteStream = event.streams[0];
        renderGrid();
        renderFocusIfShowing();
      }
    } else {
      syncRemoteStreamFromReceivers(peer);
    }
  });

  pc.addEventListener('connectionstatechange', () => {
    if (peer.pc !== pc) return; // conexão antiga, já substituída (ver recreatePeerConnection)
    peer.connectionState = pc.connectionState;
    console.log('[room] conexão com', peer.name, '->', pc.connectionState);
    if (pc.connectionState === 'connected') {
      markPeerConnected(peer);
      syncRemoteStreamFromReceivers(peer);
    } else if (pc.connectionState === 'failed') {
      // Antes isto removia a pessoa da sala na hora, em silêncio e pra
      // sempre — uma queda de alguns segundos tirava alguém da chamada sem
      // aviso nenhum e sem jeito de voltar. Agora tenta reconectar.
      beginRecovery(peer, 0);
    } else if (pc.connectionState === 'disconnected') {
      beginRecovery(peer, RECOVERY_FIRST_CHECK_MS);
    }
    renderParticipants();
    updateConnectionBanner();
  });

  // Descoberta de candidatos ICE. Os que aparecem enquanto a oferta/resposta
  // ainda está esperando pra sair (holdingLocalCandidates, ver
  // ICE_GATHER_WAIT_MS) já vão dentro do próprio SDP; os que aparecem
  // depois vão em lote (~300ms), com retentativa.
  pc.addEventListener('icegatheringstatechange', () => {
    if (peer.pc !== pc) return;
    if (pc.iceGatheringState === 'gathering') {
      // nova rodada de descoberta (ex: ICE restart) — candidatos antigos não servem mais
      peer.gatheredLocalCandidates = [];
      peer.unsentLocalCandidates = [];
    }
  });
  pc.addEventListener('icecandidate', (event) => {
    if (peer.pc !== pc || !event.candidate) return;
    const candidate = event.candidate.toJSON();
    peer.gatheredLocalCandidates.push(candidate);
    if (peer.holdingLocalCandidates) return;
    peer.unsentLocalCandidates.push(candidate);
    if (!peer.localCandidateFlushTimer) {
      peer.localCandidateFlushTimer = setTimeout(() => flushLocalCandidates(peer), 300);
    }
  });
}

// Liga os transceivers (criados pela minha oferta, ou adotados da oferta do
// outro lado) às minhas tracks locais.
function attachLocalTransceivers(peer, videoTransceiver, audioTransceiver) {
  preferHardwareVideoCodec(videoTransceiver);
  peer.videoSender = videoTransceiver.sender;
  peer.audioSender = audioTransceiver.sender;
  applyLocalTracksToPeer(peer);
}

// Lado que responde: usa os transceivers que a oferta acabou de criar
// (recvonly por padrão) como os SEUS — passa pra sendrecv, associa o msid e
// coloca as tracks locais neles. Precisa acontecer entre
// setRemoteDescription e createAnswer pra resposta já sair com tudo isso.
function adoptRemoteTransceivers(peer) {
  if (peer.videoSender) return;
  const transceivers = peer.pc.getTransceivers();
  const video = transceivers.find((t) => t.mid !== null && t.receiver.track.kind === 'video');
  const audio = transceivers.find((t) => t.mid !== null && t.receiver.track.kind === 'audio');
  if (!video || !audio) throw new Error('oferta sem m-line de vídeo e áudio');
  for (const transceiver of [video, audio]) {
    transceiver.direction = 'sendrecv';
    transceiver.sender.setStreams(peer.outgoingStream);
  }
  attachLocalTransceivers(peer, video, audio);
}

// Áudio em estéreo e com mais bitrate. Por padrão o Chromium negocia o Opus
// em MONO a 32 kbps: ótimo pra voz, mas música e som de jogo viravam mono e
// perdiam bastante qualidade. O parâmetro "stereo=1" no SDP quer dizer
// "prefiro RECEBER estéreo" (e "maxaveragebitrate", até quanto quero
// receber), então cada lado põe isso na PRÓPRIA descrição (oferta ou
// resposta) antes de aplicá-la: o decodificador daqui passa a sair em
// estéreo, e o codificador do outro lado, ao ler isso, passa a mandar
// estéreo a 128 kbps. Medido (440 Hz só no canal esquerdo, 660 Hz só no
// direito): sem isso os dois tons chegavam iguais nos dois canais; com
// isso, ~70 dB de separação. E fica compatível com versões antigas: quem
// ainda não atualizou continua recebendo mono a 32 kbps como antes, e quem
// atualizou recebe estéreo mesmo de quem não atualizou.
const OPUS_RECEIVE_PARAMS = ['stereo=1', 'sprop-stereo=1', 'maxaveragebitrate=128000'];

function withStereoOpus(description) {
  const payloadTypes = [...description.sdp.matchAll(/a=rtpmap:(\d+) opus\/48000\/2/gi)].map((match) => match[1]);
  const sdp = payloadTypes.reduce(
    (current, payloadType) =>
      current.replace(new RegExp(`(a=fmtp:${payloadType} [^\\r\\n]*)`), (line) => {
        const missing = OPUS_RECEIVE_PARAMS.filter((param) => !new RegExp(`[ ;]${param.split('=')[0]}=`).test(line));
        return missing.length ? line + ';' + missing.join(';') : line;
      }),
    description.sdp
  );
  return { type: description.type, sdp };
}

function waitForIceGathering(pc, timeoutMs) {
  if (pc.iceGatheringState === 'complete') return Promise.resolve();
  return new Promise((resolve) => {
    const done = () => {
      clearTimeout(timer);
      pc.removeEventListener('icegatheringstatechange', onChange);
      resolve();
    };
    const onChange = () => {
      if (pc.iceGatheringState === 'complete') done();
    };
    const timer = setTimeout(done, timeoutMs);
    pc.addEventListener('icegatheringstatechange', onChange);
  });
}

// Ordem de preferência do codec de vídeo: H.264 High primeiro, VP8 logo
// depois, o resto na ordem padrão do navegador. Sem isso o Chromium
// negocia VP8, que no Windows é SEMPRE codificado e decodificado na CPU
// (libvpx) — e na malha da sala cada pessoa assistindo tem o SEU próprio
// encoder, codificando a mesma tela de novo. Medido num i5-12600K + RTX
// 5070, tela em movimento a 1080p30, 3 pessoas assistindo: com VP8 a CPU do
// PC inteiro chegou a 100% e o vídeo caiu pra ~10 fps (é o que travava o
// PC e as abas do Chrome); com H.264 na placa de vídeo (NVENC) ficou em ~3%
// de CPU, 30 fps cravados. A 1440p o VP8 não passava de 2 fps nem com uma
// pessoa só. Quem recebe também ganha: H.264 decodifica na placa de vídeo,
// VP8 não.
//
// Por que "High" (profile-level-id=64...) e não qualquer H.264: no Windows o
// Chromium só manda pra placa de vídeo os perfis Baseline/Main/High; o
// Constrained Baseline (42e01f, o H.264 "padrão" do WebRTC) vai pro
// OpenH264 por software, que foi ainda pior que o VP8 (2 fps a 1080p).
//
// A lista sai das capacidades de RECEBIMENTO, não de envio: o High só
// aparece nas de envio quando existe encoder de hardware, mas decodificar
// todo mundo decodifica. Agora que quem responde também aplica a
// preferência (nos transceivers adotados da oferta), montar pelas de envio
// tiraria o High da resposta de quem não tem encoder de hardware — e aí
// nem o outro lado, que tem, poderia mandar H.264 pra ele. Cada lado
// codifica com o primeiro codec da lista que ele consegue: com hardware,
// H.264 High; sem, pula pro VP8 (o 2º), nunca o OpenH264 — testado com
// --disable-accelerated-video-encode.
function preferHardwareVideoCodec(transceiver) {
  const capabilities = RTCRtpReceiver.getCapabilities && RTCRtpReceiver.getCapabilities('video');
  if (!capabilities || typeof transceiver.setCodecPreferences !== 'function') return;
  const fmtp = (codec) => codec.sdpFmtpLine || '';
  const isH264High = (codec) =>
    codec.mimeType.toLowerCase() === 'video/h264' &&
    /profile-level-id=64/i.test(fmtp(codec)) &&
    /packetization-mode=1/.test(fmtp(codec));
  const isVp8 = (codec) => codec.mimeType.toLowerCase() === 'video/vp8';
  const ordered = [...capabilities.codecs.filter(isH264High), ...capabilities.codecs.filter(isVp8)];
  ordered.push(...capabilities.codecs.filter((codec) => !ordered.includes(codec)));
  try {
    transceiver.setCodecPreferences(ordered);
  } catch (err) {
    console.warn('[room] não deu pra definir a preferência de codec de vídeo — fica o padrão do navegador', err);
  }
}

// Reforço pro caso de o evento "track" vir sem `event.streams` (ex: versão
// antiga do app do outro lado, sem msid): monta o MediaStream a partir do
// que a RTCPeerConnection já está recebendo. Só age UMA VEZ por conexão —
// reatribuir um MediaStream novo a `srcObject` interrompe o carregamento
// do anterior, e uma versão antiga que refazia isso a cada 3s nunca deixava
// o vídeo carregar.
function syncRemoteStreamFromReceivers(peer) {
  if (!peer.pc || peer.remoteStreamFromEvent || peer.remoteStream) return;
  const videoReceiver = peer.pc.getReceivers().find((r) => r.track && r.track.kind === 'video');
  if (!videoReceiver || !videoReceiver.track) return;

  console.log('[room] montando stream de vídeo recebido de', peer.name, '(via getReceivers, uma única vez)');
  const audioReceiver = peer.pc.getReceivers().find((r) => r.track && r.track.kind === 'audio');
  const tracks = [videoReceiver.track];
  if (audioReceiver && audioReceiver.track) tracks.push(audioReceiver.track);
  peer.remoteStream = new MediaStream(tracks);
  renderGrid();
  renderFocusIfShowing();
}

// Cada oferta/resposta/lote de candidatos leva:
// - pcId: a identidade da conexão de quem mandou;
// - toPcId: a identidade da conexão do destinatário com quem ela está
//   pareada (null = ainda nenhuma — oferta inicial de uma conexão nova);
// - seq (oferta/resposta): número da oferta, crescente por conexão;
// - pcEpoch (oferta): crescente a cada conexão nova de quem oferece — uma
//   oferta de uma conexão já substituída que chegue atrasada (comum depois
//   de uma queda: as retentativas ficam represadas e chegam todas juntas
//   quando a rede volta) é ignorada, em vez de derrubar a conexão nova;
// - sharing/sharingV: se quem mandou está compartilhando (ver
//   applyRemoteSharing) — quem recriou a conexão do zero pode ter perdido
//   isso, e uma reconexão sempre passa por oferta/resposta.
// Com isso dá pra jogar fora o que chegar atrasado ou repetido (as
// retentativas de UDP/ntfy entregam a mesma oferta 2x, às vezes depois de
// uma mais nova — aplicar uma oferta velha depois de uma reconexão
// derrubava a conexão de novo) e perceber quando um dos lados recriou a
// conexão do zero e o outro ainda está na antiga (aí os dois recomeçam
// juntos, em vez de ficarem conversando com conexões que não existem mais).
function negotiate(peer, { iceRestart = false } = {}) {
  if (!isOfferer(peer)) return Promise.resolve();
  return runSignalingTask(peer, async () => {
    const pc = peer.pc;
    if (!pc || pc.signalingState === 'closed') return;
    const seq = ++peer.offerSeq;
    let message;
    peer.holdingLocalCandidates = true;
    try {
      await pc.setLocalDescription(withStereoOpus(await pc.createOffer(iceRestart ? { iceRestart: true } : undefined)));
      peer.pendingOfferSeq = seq;
      await waitForIceGathering(pc, ICE_GATHER_WAIT_MS);
      if (peer.pc !== pc) return;
      message = {
        t: 'offer',
        sender: myPeerInfo(),
        sdp: pc.localDescription.toJSON(),
        pcId: peer.pcId,
        toPcId: peer.remotePcId,
        seq,
        pcEpoch: peer.pcEpoch,
        sharing: mySharing,
        sharingV: mySharingVersion,
      };
    } finally {
      if (peer.pc === pc) peer.holdingLocalCandidates = false;
    }
    console.log(`[room] mandando oferta${iceRestart ? ' (reinício de ICE)' : ''} pra`, peer.name, `#${seq}`);
    // Reconectando, o próprio ciclo de recoveryTick já repete — 3
    // tentativas por oferta aqui só multiplicavam mensagens pro ntfy
    // enquanto o outro lado nem está alcançável (estourou o limite num teste).
    sendToPeerReliable(peer, message, { attempts: peer.reconnecting ? 1 : 3 }).then((result) => {
      if (!result.ok) console.warn('[room] oferta pra', peer.name, 'não foi confirmada em nenhuma tentativa');
    });
  });
}

async function handleOffer(peer, message) {
  const fromPcId = message.pcId || null; // null = versão antiga do app, sem esses campos
  const toPcId = message.toPcId || null;
  const seq = Number(message.seq) || 0;
  const epoch = Number(message.pcEpoch) || 0;

  if (fromPcId) {
    if (epoch && epoch < peer.remotePcEpoch) return; // de uma conexão dele já substituída, chegando atrasada
    if (toPcId && toPcId !== peer.pcId) {
      // O outro lado está renegociando com uma conexão minha que não existe
      // mais (eu recriei a minha). Pede pra ele recomeçar do zero também.
      console.log('[room] oferta de', peer.name, 'era pra uma conexão minha antiga — pedindo pra recomeçar do zero');
      sendToPeerReliable(peer, { t: 'restart-request', sender: myPeerInfo(), pcId: peer.pcId, toPcId: fromPcId, full: true }, { attempts: 1 }).catch(() => {});
      return;
    }
    if (peer.remotePcId && peer.remotePcId !== fromPcId) {
      if (toPcId) return; // de uma conexão dele mais antiga, que já foi substituída
      // Oferta inicial de uma conexão NOVA do outro lado (ele recomeçou do
      // zero): a minha, pareada com a antiga dele, não serve mais.
      console.log('[room]', peer.name, 'recomeçou a conexão do zero — recriando a minha também');
      recreatePeerConnection(peer);
    } else if (peer.remotePcId === fromPcId && seq <= peer.lastRemoteOfferSeq) {
      return; // oferta repetida ou atrasada — já respondi essa (ou uma mais nova)
    }
  }

  const pc = peer.pc;
  if (pc.signalingState === 'have-local-offer') {
    // Só acontece com uma versão antiga do app do outro lado, que ainda
    // renegocia dos dois lados: quem oferece aqui (eu) ignora a dele.
    console.log('[room] ignorando oferta de', peer.name, '— colisão com a minha');
    return;
  }

  await pc.setRemoteDescription(message.sdp);
  if (fromPcId) {
    peer.remotePcId = fromPcId;
    peer.lastRemoteOfferSeq = seq;
    peer.remotePcEpoch = Math.max(peer.remotePcEpoch, epoch);
  }
  applyRemoteSharing(peer, message.sharing, message.sharingV);
  adoptRemoteTransceivers(peer);
  await flushPendingIceCandidates(peer);
  let answer;
  peer.holdingLocalCandidates = true;
  try {
    await pc.setLocalDescription(withStereoOpus(await pc.createAnswer()));
    await waitForIceGathering(pc, ICE_GATHER_WAIT_MS);
    if (peer.pc !== pc) return;
    answer = {
      t: 'answer',
      sender: myPeerInfo(),
      sdp: pc.localDescription.toJSON(),
      pcId: peer.pcId,
      toPcId: fromPcId,
      seq,
      sharing: mySharing,
      sharingV: mySharingVersion,
    };
  } finally {
    if (peer.pc === pc) peer.holdingLocalCandidates = false;
  }
  console.log('[room] mandando resposta pra', peer.name, `#${seq}`);
  sendToPeerReliable(peer, answer, { attempts: peer.reconnecting ? 1 : 3 }).then((result) => {
    if (!result.ok) console.warn('[room] resposta pra', peer.name, 'não foi confirmada em nenhuma tentativa');
  });
}

async function handleAnswer(peer, message) {
  const pc = peer.pc;
  const fromPcId = message.pcId || null;
  const toPcId = message.toPcId || null;
  const seq = Number(message.seq) || 0;

  if (toPcId && toPcId !== peer.pcId) return; // resposta pra uma conexão minha que já foi substituída
  if (pc.signalingState !== 'have-local-offer') return; // repetida/atrasada — já aplicada
  if (seq && seq !== peer.pendingOfferSeq) return; // responde uma oferta minha mais antiga
  if (fromPcId && peer.remotePcId && fromPcId !== peer.remotePcId) {
    // O outro lado respondeu com uma conexão NOVA (outra identidade DTLS) —
    // não dá pra aplicar na minha, pareada com a antiga. Recomeça do zero.
    console.log('[room] resposta de', peer.name, 'veio de uma conexão nova dele — recomeçando do zero');
    restartFromScratch(peer);
    return;
  }

  console.log('[room] recebi resposta de', peer.name, `#${seq} — aplicando`);
  await pc.setRemoteDescription(message.sdp);
  if (fromPcId) peer.remotePcId = fromPcId;
  applyRemoteSharing(peer, message.sharing, message.sharingV);
  await flushPendingIceCandidates(peer);
}

// Candidatos ICE do outro lado podem chegar (via nosso canal de
// sinalização, independente da SDP) ANTES da gente ter aplicado a
// oferta/resposta dele — `addIceCandidate` exige que `remoteDescription` já
// exista, então guarda numa fila e aplica assim que ela for setada (ver
// `flushPendingIceCandidates`, chamada logo depois de cada
// `setRemoteDescription`). O mesmo vale pros de um reinício de ICE que
// chegam antes da oferta de reinício (outra "ufrag", que a descrição atual
// ainda não conhece).
async function handleRemoteCandidates(peer, message, candidates) {
  if (!Array.isArray(candidates)) return;
  const fromPcId = message.pcId || null;
  const toPcId = message.toPcId || null;
  if (toPcId && toPcId !== peer.pcId) return; // pra uma conexão minha que já foi substituída
  if (fromPcId && peer.remotePcId && fromPcId !== peer.remotePcId) return; // de uma conexão antiga dele

  for (const candidate of candidates) {
    if (!candidate) continue;
    peer.remoteCandidatesReceived++;
    if (!peer.pc.remoteDescription || (fromPcId && !peer.remotePcId)) {
      peer.pendingIceCandidates.push({ candidate, pcId: fromPcId });
      continue;
    }
    try {
      await peer.pc.addIceCandidate(candidate);
    } catch (err) {
      const ufrag = candidate.usernameFragment;
      if (ufrag && !peer.pc.remoteDescription.sdp.includes('a=ice-ufrag:' + ufrag)) {
        peer.pendingIceCandidates.push({ candidate, pcId: fromPcId });
      } else {
        console.warn('[room] falha ao aplicar candidato ICE de', peer.name, err);
      }
    }
  }
}

function flushLocalCandidates(peer) {
  peer.localCandidateFlushTimer = null;
  if (!peer.unsentLocalCandidates.length) return;
  const candidates = peer.unsentLocalCandidates;
  peer.unsentLocalCandidates = [];
  sendToPeerReliable(
    peer,
    { t: 'ice-candidates', sender: myPeerInfo(), candidates, pcId: peer.pcId, toPcId: peer.remotePcId },
    { attempts: peer.reconnecting ? 1 : 3 }
  ).catch(() => {});
}

async function flushPendingIceCandidates(peer) {
  if (!peer.pendingIceCandidates.length) return;
  const pending = peer.pendingIceCandidates;
  peer.pendingIceCandidates = [];
  for (const { candidate, pcId } of pending) {
    if (pcId && peer.remotePcId && pcId !== peer.remotePcId) continue; // de uma conexão antiga dele
    try {
      await peer.pc.addIceCandidate(candidate);
    } catch (err) {
      console.warn('[room] falha ao aplicar candidato ICE (fila) de', peer.name, err);
    }
  }
}

// ---------- queda e reconexão ----------

// Quem oferece recebe isto de quem responde quando o lado que responde
// percebeu a queda (ou a falta de conexão) — só quem oferece reinicia.
function handleRestartRequest(peer, message) {
  if (!isOfferer(peer)) return;
  const toPcId = message.toPcId || null;
  if (toPcId && toPcId !== peer.pcId) return; // fala de uma conexão minha antiga; a atual já é um recomeço
  if (message.full) {
    restartFromScratch(peer);
  } else if (Date.now() - peer.lastRestartAt >= 5000) {
    peer.lastRestartAt = Date.now();
    // Sem resposta ainda nessa conexão: a oferta se perdeu — manda de novo.
    negotiate(peer, { iceRestart: !!peer.pc.remoteDescription });
  }
}

// Pede uma reconexão: quem oferece faz direto; quem responde pede pra quem
// oferece (uma mensagem só, sem retentativa — o próximo ciclo de
// recoveryTick manda de novo se precisar).
function requestReconnect(peer, { full }) {
  if (isOfferer(peer)) {
    if (full) {
      restartFromScratch(peer);
    } else if (Date.now() - peer.lastRestartAt >= 5000) {
      peer.lastRestartAt = Date.now();
      negotiate(peer, { iceRestart: !!peer.pc.remoteDescription });
    }
    return;
  }
  sendToPeerReliable(
    peer,
    { t: 'restart-request', sender: myPeerInfo(), pcId: peer.pcId, toPcId: peer.remotePcId, full },
    { attempts: 1 }
  ).catch(() => {});
}

function restartFromScratch(peer) {
  if (!isOfferer(peer)) {
    requestReconnect(peer, { full: true });
    return;
  }
  // Acabou de recomeçar: espera essa tentativa em vez de matar a conexão
  // nova no meio do caminho (o pedido do outro lado e o meu próprio ciclo
  // de reconexão costumam pedir isso com poucos segundos de diferença).
  if (Date.now() - peer.lastScratchAt < 8000) return;
  peer.lastScratchAt = Date.now();
  peer.lastRestartAt = Date.now();
  runSignalingTask(peer, () => {
    console.log('[room] recriando a conexão com', peer.name, 'do zero');
    recreatePeerConnection(peer);
  });
  negotiate(peer);
}

function recreatePeerConnection(peer) {
  const oldPc = peer.pc;
  createPeerConnection(peer);
  if (oldPc) oldPc.close();
  // O MediaStream recebido era da conexão antiga; o novo chega pelo evento
  // "track" da nova. Enquanto isso o card mostra "Reconectando...".
  renderGrid();
  renderFocusIfShowing();
}

function scheduleRecoveryTick(peer, delayMs) {
  clearTimeout(peer.recoveryTimer);
  peer.recoveryTimer = setTimeout(() => recoveryTick(peer), delayMs);
}

// A conexão com `peer` caiu ('disconnected'/'failed'). `firstCheckMs` = 0
// age na hora; senão espera um pouco pra ver se volta sozinha.
function beginRecovery(peer, firstCheckMs) {
  if (peer.downSince === null) {
    peer.downSince = Date.now();
    peer.recoveryAttempts = 0;
    scheduleRecoveryTick(peer, firstCheckMs);
  } else if (firstCheckMs === 0 && !peer.reconnecting) {
    scheduleRecoveryTick(peer, 0); // 'disconnected' virou 'failed' antes do primeiro check
  }
}

function recoveryTick(peer) {
  peer.recoveryTimer = null;
  if (roomPeers.get(peer.peerId) !== peer || peer.downSince === null) return;
  if (peer.pc.connectionState === 'connected') {
    markPeerConnected(peer);
    return;
  }

  const downFor = Date.now() - peer.downSince;
  if (downFor >= RECOVERY_GIVE_UP_MS) {
    giveUpOnPeer(peer);
    return;
  }

  if (!peer.everConnected) {
    // Nunca conectou: diz no painel ONDE está travado. 'signaling' = a
    // oferta/resposta nem chegou (problema da sinalização UDP/ntfy, não de
    // NAT); 'ice' = os dois lados trocaram tudo mas nenhum caminho de rede
    // passa (NAT estrito sem TURN nessa combinação de redes).
    peer.timeoutReason = peer.pc.remoteDescription ? 'ice' : 'signaling';
    console.warn('[room] conexão com', peer.name, 'não fechou ainda —', peer.timeoutReason, {
      connectionState: peer.pc.connectionState,
      iceConnectionState: peer.pc.iceConnectionState,
      signalingState: peer.pc.signalingState,
      candidatosRemotosRecebidos: peer.remoteCandidatesReceived,
      candidatosLocaisColetados: peer.gatheredLocalCandidates.length,
    });
  } else if (!peer.reconnecting) {
    notify(`Conexão com ${peer.name} caiu — tentando reconectar...`, 'warning');
  }
  peer.reconnecting = true;

  peer.recoveryAttempts++;
  const full = peer.recoveryAttempts >= RECOVERY_FULL_RESTART_FROM_ATTEMPT;
  console.log('[room] tentando reconectar com', peer.name, `(tentativa ${peer.recoveryAttempts}${full ? ', do zero' : ''})`);
  requestReconnect(peer, { full });

  const delays = RECOVERY_RETRY_DELAYS_MS;
  const nextDelay = delays[Math.min(peer.recoveryAttempts - 1, delays.length - 1)];
  scheduleRecoveryTick(peer, Math.min(nextDelay, RECOVERY_GIVE_UP_MS - downFor));
  renderParticipants();
  renderGrid();
  renderFocusIfShowing();
  updateConnectionBanner();
}

function markPeerConnected(peer) {
  clearTimeout(peer.recoveryTimer);
  peer.recoveryTimer = null;
  const wasReconnecting = peer.reconnecting && peer.everConnected;
  peer.downSince = null;
  peer.reconnecting = false;
  peer.recoveryAttempts = 0;
  peer.timeoutReason = null;

  if (peer.sharing) {
    peer.sentView = null; // força reenviar, mesmo que seja 'full'
    updateViewRequests();
  }

  markJoinedRoom();

  if (!peer.everConnected) {
    peer.everConnected = true;
    if (peer.announceJoin) notify(`${peer.name} entrou na sala.`, 'info');
  } else if (wasReconnecting) {
    notify(`Conexão com ${peer.name} restabelecida.`, 'success');
    // O "sharing" que eu mandei durante a queda pode ter se perdido (ou eu
    // parei/comecei a compartilhar nesse meio tempo).
    sendToPeerReliable(peer, sharingMessage()).catch(() => {});
  }
  renderParticipants();
  renderGrid();
  renderFocusIfShowing();
  updateConnectionBanner();
}

function giveUpOnPeer(peer) {
  console.warn('[room] desistindo da conexão com', peer.name, 'depois de', RECOVERY_GIVE_UP_MS / 1000, 's');
  removePeer(peer.peerId);
  if (peer.everConnected) {
    lostPeers.set(peer.peerId, toPeerInfo(peer));
    notify(`${peer.name} caiu da sala (sem conexão há 1 minuto).`, 'error');
  } else if (peer.timeoutReason === 'ice') {
    notify(`Não consegui conectar com ${peer.name}: a combinação das redes de vocês não deixa conexão direta.`, 'error');
  } else {
    notify(`Não consegui conectar com ${peer.name}: as mensagens de conexão não chegaram.`, 'error');
  }
  maybeStartRejoin();
}

function removePeer(peerId) {
  const peer = roomPeers.get(peerId);
  if (!peer) return;
  clearTimeout(peer.recoveryTimer);
  clearTimeout(peer.localCandidateFlushTimer);
  if (peer.pc) peer.pc.close();
  roomPeers.delete(peerId);
  if (focusedPeerId === peerId) focusedPeerId = null;
  renderParticipants();
  renderGrid();
  renderFocusIfShowing();
  updateConnectionBanner();
}

// Fiquei sozinho na sala porque TODO MUNDO caiu (não porque saíram): quase
// certamente a queda foi minha. Tenta voltar sozinho mandando "join" de
// novo pra quem estava na sala — o mesmo caminho de entrar com o código,
// só que pros pontos de encontro que eu já conheço. Quem ainda estiver lá
// responde com "welcome" e a malha se refaz.
const REJOIN_INTERVAL_MS = 15000;
const REJOIN_MAX_MS = 5 * 60 * 1000;
let rejoinTimer = null;
let rejoinStartedAt = 0;
let rejoinGaveUp = false;

function maybeStartRejoin() {
  if (rejoinTimer !== null || roomPeers.size > 0 || lostPeers.size === 0 || !myListener) return;
  rejoinStartedAt = Date.now();
  rejoinGaveUp = false;
  attemptRejoin();
}

function attemptRejoin() {
  rejoinTimer = null;
  if (!myListener || roomPeers.size > 0) {
    stopRejoin();
    return;
  }
  if (Date.now() - rejoinStartedAt > REJOIN_MAX_MS) {
    stopRejoin();
    rejoinGaveUp = true;
    updateConnectionBanner();
    return;
  }
  const joinMessage = { t: 'join', peerId: myPeerId, name: myName, sid: myListener.sessionId, cands: myListener.candidates };
  lostPeers.forEach((info) => sendToPeer(info, joinMessage).catch(() => {}));
  rejoinTimer = setTimeout(attemptRejoin, REJOIN_INTERVAL_MS);
  updateConnectionBanner();
}

function stopRejoin() {
  clearTimeout(rejoinTimer);
  rejoinTimer = null;
  if (roomPeers.size > 0) lostPeers.clear();
  updateConnectionBanner();
}

// A rede do PC voltou: não espera o próximo ciclo de recoveryTick (até 20s)
// nem o watchdog do ntfy perceber que a conexão dele morreu.
window.addEventListener('online', () => {
  if (!myListener) return;
  console.log('[room] a rede voltou — reconectando agora');
  window.api.kickSignalListener(myListener.sessionId);
  roomPeers.forEach((peer) => {
    if (peer.downSince !== null) scheduleRecoveryTick(peer, 1000);
  });
  if (rejoinTimer !== null) {
    clearTimeout(rejoinTimer);
    rejoinTimer = setTimeout(attemptRejoin, 1500);
  }
  updateConnectionBanner();
});
window.addEventListener('offline', () => updateConnectionBanner());

// ---------- avisos na tela ----------

const roomToastsEl = document.getElementById('room-toasts');
const connectionBannerEl = document.getElementById('connection-banner');
const connectionBannerTextEl = connectionBannerEl.querySelector('.connection-banner-text');
const connectionBannerSpinnerEl = connectionBannerEl.querySelector('.btn-spinner');
const MAX_TOASTS = 4;

// Aviso passageiro no canto da sala (entrou/saiu/caiu/voltou). `kind`:
// 'info' | 'success' | 'warning' | 'error' — muda só a cor da borda.
function notify(text, kind = 'info') {
  if (!viewRoom.classList.contains('active')) return;
  const toast = document.createElement('div');
  toast.className = `toast toast-${kind}`;
  toast.setAttribute('role', kind === 'error' || kind === 'warning' ? 'alert' : 'status');
  toast.textContent = text;
  roomToastsEl.appendChild(toast);
  while (roomToastsEl.childElementCount > MAX_TOASTS) roomToastsEl.firstElementChild.remove();
  setTimeout(() => {
    toast.classList.add('toast-leaving');
    setTimeout(() => toast.remove(), 250);
  }, kind === 'error' ? 9000 : 5000);
}

function clearToasts() {
  roomToastsEl.innerHTML = '';
}

// Faixa fixa no topo enquanto a MINHA conexão estiver com problema (não a
// de uma pessoa só — isso vai no aviso passageiro e no card dela).
function updateConnectionBanner() {
  let text = '';
  let busy = true;
  if (myListener) {
    const everConnected = [...roomPeers.values()].filter((peer) => peer.everConnected);
    if (!navigator.onLine) {
      text = 'Sem internet — reconecto sozinho quando a conexão voltar.';
    } else if (rejoinTimer !== null) {
      text = 'Você perdeu a conexão com a sala — tentando voltar...';
    } else if (rejoinGaveUp && roomPeers.size === 0) {
      text = 'Não consegui voltar pra sala. Saia e entre de novo com um código.';
      busy = false;
    } else if (everConnected.length >= 2 && everConnected.every((peer) => peer.reconnecting)) {
      text = 'Sua conexão parece ter caído — reconectando com todo mundo...';
    }
  }
  connectionBannerTextEl.textContent = text;
  connectionBannerSpinnerEl.hidden = !busy;
  connectionBannerEl.hidden = !text;
}

// ===================================================================
// CAPTURA DE TELA/ÁUDIO (reaproveitado do fluxo 1:1 original)
// ===================================================================

const monitorSelect = document.getElementById('monitor-select');
const btnRefreshMonitors = document.getElementById('btn-refresh-monitors');
const monitorThumbnail = document.getElementById('monitor-thumbnail');

let screensCache = [];

async function refreshMonitors() {
  screensCache = await window.api.listScreens();
  const previousValue = monitorSelect.value;
  monitorSelect.innerHTML = '';

  screensCache.forEach((screen) => {
    const opt = document.createElement('option');
    opt.value = screen.id;
    opt.textContent = screen.name || screen.id;
    monitorSelect.appendChild(opt);
  });

  if (screensCache.some((s) => s.id === previousValue)) {
    monitorSelect.value = previousValue;
  }
  updateMonitorThumbnail();
  if (updateResolutionAvailability()) applyQualityInRoom();
}

function updateMonitorThumbnail() {
  const screen = screensCache.find((s) => s.id === monitorSelect.value);
  if (screen && screen.thumbnail) {
    monitorThumbnail.src = screen.thumbnail;
    monitorThumbnail.hidden = false;
  } else {
    monitorThumbnail.hidden = true;
  }
}

btnRefreshMonitors.addEventListener('click', refreshMonitors);

// ---------- qualidade da transmissão (resolução + taxa de quadros) ----------

const resolutionSelect = document.getElementById('resolution-select');
const frameRateSelect = document.getElementById('framerate-select');
const RESOLUTION_1440_OPTION = resolutionSelect.querySelector('option[value="1440"]');

// Teto de bitrate por conexão pra cada resolução — não é um valor fixo, o
// WebRTC ainda estima a banda real e usa menos se precisar; só evita mandar
// mais do que isso pra cada participante. 1440p tem ~1,8x os pixels de
// 1080p, então com o mesmo teto ficaria visivelmente pior que 1080p em tela
// com muito movimento.
const MAX_BITRATE_BY_RESOLUTION = { 720: 5_000_000, 1080: 8_000_000, 1440: 12_000_000 };

function selectedResolution() {
  return Number(resolutionSelect.value);
}

function selectedFrameRate() {
  return Number(frameRateSelect.value);
}

function selectedScreen() {
  return screensCache.find((s) => s.id === monitorSelect.value);
}

// "1440p" só faz sentido se o monitor tiver pelo menos 1440 linhas (a
// captura nunca aumenta a imagem, então num monitor 1080p ela sairia em
// 1080p do mesmo jeito). Usa o lado MENOR do monitor pra um monitor em
// retrato (1440x2560) também contar. Resolução desconhecida (null, ver
// physicalDisplaySize() no main.js) deixa a opção liberada — no pior caso
// sai na resolução nativa. No modo em que o seletor de monitor é ignorado
// (o seletor nativo do SO escolhe a tela), basta algum monitor ter 1440p.
function screenSupports1440(screen) {
  if (!screen || !screen.width || !screen.height) return true;
  return Math.min(screen.width, screen.height) >= 1440;
}

// Retorna true se precisou rebaixar a escolha de 1440p pra 1080p.
function updateResolutionAvailability() {
  const supported = monitorSelectIgnoredByAudioMode()
    ? screensCache.length === 0 || screensCache.some(screenSupports1440)
    : screenSupports1440(selectedScreen());
  RESOLUTION_1440_OPTION.disabled = !supported;
  RESOLUTION_1440_OPTION.textContent = supported ? '1440p' : '1440p (monitor menor)';
  if (!supported && resolutionSelect.value === '1440') {
    resolutionSelect.value = '1080';
    return true;
  }
  return false;
}

// Limites de tamanho da captura pra resolução escolhida. "720p/1080p/1440p"
// é o número de LINHAS: a largura segue a proporção do monitor (no mínimo
// 16:9) — sem isso, num ultrawide 3440x1440 a caixa 2560x1440 faria a
// imagem caber pela largura e sair com só ~1070 linhas. A captura reduz
// mantendo a proporção até caber nessa caixa, e nunca aumenta.
function captureBounds(screen) {
  const lines = selectedResolution();
  const hasSize = screen && screen.width && screen.height;
  const aspect = hasSize ? Math.max(screen.width, screen.height) / Math.min(screen.width, screen.height) : 16 / 9;
  const longSide = Math.round(lines * Math.max(aspect, 16 / 9));
  const portrait = hasSize && screen.height > screen.width;
  return portrait ? { width: lines, height: longSide } : { width: longSide, height: lines };
}

async function acquireVideoTrackForScreen(sourceId) {
  const bounds = captureBounds(screensCache.find((s) => s.id === sourceId));
  const stream = await navigator.mediaDevices.getUserMedia({
    audio: false,
    video: {
      mandatory: {
        chromeMediaSource: 'desktop',
        chromeMediaSourceId: sourceId,
        maxWidth: bounds.width,
        maxHeight: bounds.height,
        maxFrameRate: selectedFrameRate(),
      },
    },
  });
  return stream.getVideoTracks()[0];
}

// Vídeo vindo do getDisplayMedia (seletor nativo do SO, ver
// confirmStartSharing()) não tem como ser recapturado em silêncio — pedir de
// novo abriria o seletor do SO outra vez — então troca de qualidade nele vai
// por applyConstraints na própria track.
let localVideoFromDisplayMedia = false;

// 'motion' (e não 'detail'): quando a banda aperta, o encoder reduz a
// RESOLUÇÃO e mantém os quadros por segundo. Com 'detail' o Chromium faz o
// contrário — segura a resolução a qualquer custo e derruba o fps —, e
// numa rede instável isso virava travadas e atraso acumulado. Medido com o
// emulador de rede do próprio WebRTC (link alternando 30 Mbps / 2 Mbps com
// 2% de perda): com 'detail', 0 a 11 fps na rede ruim, latência de até
// ~1,9s e, depois que a rede voltava, ~400ms de atraso que levava ~20s pra
// sumir; com 'motion', ~30 fps o tempo todo, 90-150ms na rede ruim e
// 70-90ms depois. Com banda sobrando a resolução é a escolhida no popover
// do mesmo jeito; ela só cai temporariamente quando a rede não aguenta.
const SCREEN_CONTENT_HINT = 'motion';

// A pré-visualização da própria tela (o seu card no grid) usa uma CÓPIA da
// track de vídeo limitada a 24 quadros por segundo. Mostrar a captura
// de 60 fps direto na própria janela custava ~20% de um núcleo no processo
// de GPU (medido: 27,5% -> 7,8% ao pausar a pré-visualização) — só pra você
// ver o que está compartilhando. Quem assiste continua recebendo a track
// original, com todos os quadros.
const SELF_PREVIEW_MAX_FPS = 24;
let localPreviewStream = null;

function refreshLocalPreview() {
  if (localPreviewStream) localPreviewStream.getTracks().forEach((track) => track.stop());
  localPreviewStream = null;
  const videoTrack = localStream && localStream.getVideoTracks()[0];
  if (!videoTrack) return;
  const previewTrack = videoTrack.clone();
  previewTrack.applyConstraints({ frameRate: { max: SELF_PREVIEW_MAX_FPS } }).catch(() => {});
  localPreviewStream = new MediaStream([previewTrack]);
}

function displayMediaVideoConstraints() {
  const bounds = captureBounds(null);
  const fps = selectedFrameRate();
  return {
    width: { ideal: bounds.width, max: bounds.width },
    height: { ideal: bounds.height, max: bounds.height },
    frameRate: { ideal: fps, max: fps },
  };
}

// ---------- economia por espectador ----------
//
// Na malha, cada pessoa assistindo tem o SEU encoder da minha tela —
// medido: ~26% de um núcleo por espectador a 1080p60 (Electron 32). Quem
// não está vendo minha tela de verdade não precisa disso: cada um avisa
// como está me vendo e eu ajusto SÓ a conexão daquela pessoa:
// - 'full': grid ou foco — qualidade escolhida no popover;
// - 'thumb': miniatura na tira do foco (160x96 na tela) — 180p a 15 fps;
// - 'off': não aparece (tira recolhida ou janela minimizada) —
//   o encoder daquela conexão para. O ÁUDIO não muda em nenhum caso.
const THUMB_VIEW_HEIGHT = 180;
const THUMB_VIEW_MAX_FPS = 15;
const THUMB_VIEW_MAX_BITRATE = 300_000;
const VIEW_KINDS = ['full', 'thumb', 'off'];
let myViewVersion = 0;

function applyVideoEncodingToPeer(peer) {
  const sender = peer.videoSender;
  if (!sender) return;
  // getParameters/setParameters em sequência: duas chamadas sobrepostas
  // (ex: trocar a qualidade no popover enquanto chega um pedido de view)
  // fazem a segunda falhar por usar parâmetros já vencidos.
  peer.encodingQueue = peer.encodingQueue
    .then(async () => {
      if (peer.videoSender !== sender) return; // conexão recriada no meio
      const params = sender.getParameters();
      if (!params.encodings || !params.encodings.length) params.encodings = [{}];
      const encoding = params.encodings[0];
      const view = peer.remoteView;
      encoding.active = view !== 'off';
      if (view === 'thumb') {
        const videoTrack = localStream && localStream.getVideoTracks()[0];
        const height = (videoTrack && videoTrack.getSettings().height) || selectedResolution();
        encoding.scaleResolutionDownBy = Math.max(1, height / THUMB_VIEW_HEIGHT);
        encoding.maxFramerate = Math.min(THUMB_VIEW_MAX_FPS, selectedFrameRate());
        encoding.maxBitrate = THUMB_VIEW_MAX_BITRATE;
      } else {
        encoding.scaleResolutionDownBy = 1;
        encoding.maxFramerate = selectedFrameRate();
        encoding.maxBitrate = MAX_BITRATE_BY_RESOLUTION[selectedResolution()];
      }
      await sender.setParameters(params);
    })
    .catch((err) => console.warn('[room] não deu pra ajustar o vídeo enviado pra', peer.name, err));
}

// Lado de quem compartilha: a pessoa avisou como está me vendo. `forShare`
// é a versão do MEU compartilhamento que ela conhecia: um pedido de um
// compartilhamento anterior (ex: um 'off' de quando ela estava minimizada,
// chegando atrasado depois de eu parar e começar de novo) não vale mais —
// sem isso ela podia ficar sem vídeo com a janela aberta.
function applyRemoteView(peer, message) {
  if (!mySharing || !VIEW_KINDS.includes(message.view) || message.forShare !== mySharingVersion) return;
  const version = Number(message.v) || 0;
  if (version <= peer.remoteViewVersion) return; // mais velho que o último aplicado
  peer.remoteViewVersion = version;
  if (peer.remoteView === message.view) return;
  peer.remoteView = message.view;
  console.log('[room]', peer.name, 'está vendo minha tela como', message.view);
  applyVideoEncodingToPeer(peer);
}

// Lado de quem assiste: como estou vendo a tela de `peer` agora.
function desiredViewOf(peer) {
  if (!windowVisible) return 'off';
  if (focusedPeerId === null || focusedPeerId === peer.peerId) return 'full';
  return focusStripCollapsed ? 'off' : 'thumb';
}

// Avisa quem está compartilhando sempre que muda como eu vejo a tela
// deles. Barata de chamar à toa: só manda quando muda (sentView).
function updateViewRequests() {
  roomPeers.forEach((peer) => {
    if (!peer.sharing) return;
    const view = desiredViewOf(peer);
    if (peer.sentView === view) return;
    peer.sentView = view;
    sendToPeerReliable(peer, {
      t: 'view',
      sender: myPeerInfo(),
      view,
      v: ++myViewVersion,
      forShare: peer.sharingVersion,
    }).catch(() => {});
  });
}

// Janela minimizada: ninguém precisa me mandar vídeo enquanto isso (o
// áudio continua). Vem do processo principal porque, com
// backgroundThrottling desligado, a Page Visibility API diz "visible"
// mesmo minimizada (testado).
let windowVisible = true;
window.api.onWindowVisible((visible) => {
  windowVisible = visible;
  updateViewRequests();
});

async function applyQualityInRoom() {
  if (!localStream || !mySharing) return; // nada compartilhando ainda; "Começar" já usa o que estiver escolhido

  if (localVideoFromDisplayMedia) {
    const track = localStream.getVideoTracks()[0];
    try {
      await track.applyConstraints(displayMediaVideoConstraints());
    } catch (err) {
      alert('Não foi possível trocar a qualidade: ' + err.message);
      return;
    }
    roomPeers.forEach((peer) => applyVideoEncodingToPeer(peer));
    return;
  }

  await replaceScreenVideoInRoom('Não foi possível trocar a qualidade: ');
}

resolutionSelect.addEventListener('change', () => applyQualityInRoom());
frameRateSelect.addEventListener('change', () => applyQualityInRoom());

const audioSourceSelect = document.getElementById('audio-source-select');
const btnRefreshAudioSources = document.getElementById('btn-refresh-audio-sources');
const LOOPBACK_VALUE = '__loopback__';
const PROCESS_VALUE = '__process__';
let supportsLoopback = false;
let supportsProcessAudio = false;
let audioSourceInitialized = false;

async function refreshAudioSources() {
  try {
    const tmp = await navigator.mediaDevices.getUserMedia({ audio: true });
    tmp.getTracks().forEach((t) => t.stop());
  } catch (err) {
    // segue sem permissão; a lista pode vir sem labels
  }

  const devices = await navigator.mediaDevices.enumerateDevices();
  const audioInputs = devices.filter((d) => d.kind === 'audioinput');

  const previousValue = audioSourceInitialized ? audioSourceSelect.value : undefined;
  audioSourceInitialized = true;
  audioSourceSelect.innerHTML = '';

  if (supportsLoopback) {
    const loopbackOption = document.createElement('option');
    loopbackOption.value = LOOPBACK_VALUE;
    loopbackOption.textContent = supportsProcessAudio
      ? 'Áudio do sistema (tudo, exceto este app)'
      : 'Áudio do sistema (tudo, padrão)';
    audioSourceSelect.appendChild(loopbackOption);
  }

  if (supportsProcessAudio) {
    const processOption = document.createElement('option');
    processOption.value = PROCESS_VALUE;
    processOption.textContent = 'App específico (incluir ou excluir)';
    audioSourceSelect.appendChild(processOption);
  }

  const noneOption = document.createElement('option');
  noneOption.value = '';
  noneOption.textContent = 'Nenhum áudio';
  audioSourceSelect.appendChild(noneOption);

  audioInputs.forEach((d) => {
    const opt = document.createElement('option');
    opt.value = d.deviceId;
    opt.textContent = d.label || `Dispositivo de áudio (${d.deviceId.slice(0, 8)})`;
    audioSourceSelect.appendChild(opt);
  });

  const previousStillValid =
    (previousValue === LOOPBACK_VALUE && supportsLoopback) ||
    (previousValue === PROCESS_VALUE && supportsProcessAudio) ||
    previousValue === '' ||
    audioInputs.some((d) => d.deviceId === previousValue);

  if (previousStillValid) {
    audioSourceSelect.value = previousValue;
  } else if (supportsLoopback) {
    audioSourceSelect.value = LOOPBACK_VALUE;
  } else {
    const monitor = audioInputs.find((d) => /monitor/i.test(d.label));
    audioSourceSelect.value = monitor ? monitor.deviceId : '';
  }

  updateAudioSourceUiState();
}

btnRefreshAudioSources.addEventListener('click', refreshAudioSources);

const processAudioBlock = document.getElementById('process-audio-block');
const processAudioSelect = document.getElementById('process-audio-select');
// Grupo de rádios "Só este app" / "Tudo, menos este app" — o evento
// 'change' dos rádios borbulha até ele.
const processAudioMode = document.getElementById('process-audio-mode');
const btnRefreshAudioProcesses = document.getElementById('btn-refresh-audio-processes');

// O vídeo de "Áudio do sistema" sempre vem do getDisplayMedia (é assim que o
// Electron expõe o seletor nativo do SO no Windows/macOS, ou a primeira tela
// no Linux) — o dropdown de monitor deste popover não tem efeito nesse modo
// específico. O ÁUDIO desse modo, quando a captura por processo está
// disponível (Windows/Linux, ver native/audio-loopback), vem dela em vez do
// loopback embutido do Electron — ver acquireAudioTrack() — o que deixa
// trocável em pleno andamento e evita ecoar o próprio som do Sinal P2P.
// Lembra o último valor visto de audioSourceSelect só pra saber se estamos
// ENTRANDO no modo "Processo específico" agora (pra pré-selecionar excluir +
// Discord automaticamente) ou só atualizando a lista de apps de um modo em
// que já estávamos (nesse caso não mexe no que a pessoa já escolheu).
let lastAudioSourceMode = null;

async function updateAudioSourceUiState() {
  const isProcessMode = audioSourceSelect.value === PROCESS_VALUE;
  processAudioBlock.hidden = !isProcessMode;
  if (isProcessMode) {
    // Espera a lista de apps carregar antes de deixar trocar a fonte de
    // fato — sem isso, escolher "Processo específico" tentava trocar
    // imediatamente, antes do <select> de apps ter qualquer opção, e sempre
    // falhava com "Escolha um app...".
    await refreshAudioProcesses();
    if (lastAudioSourceMode !== PROCESS_VALUE) autoPickDiscordExclude();
  }
  lastAudioSourceMode = audioSourceSelect.value;

  const monitorIgnored = monitorSelectIgnoredByAudioMode();
  monitorSelect.disabled = monitorIgnored;
  document.getElementById('loopback-hint').hidden = !monitorIgnored;
  if (updateResolutionAvailability()) applyQualityInRoom();
}

// Ao entrar em "Processo específico" pela primeira vez, já deixa pronto pro
// caso de uso mais comum: excluir a chamada de voz do Discord do que é
// compartilhado. Procura um app cujo título termine em "discord"
// (case-insensitive, ex: janelas do Discord costumam terminar assim); se
// não achar nenhum, ainda assim liga o modo excluir e escolhe o primeiro
// app da lista (melhor um alvo qualquer em modo excluir, que a pessoa troca
// se quiser, do que deixar sem nada selecionado).
function autoPickDiscordExclude() {
  processAudioMode.querySelector('input[value="exclude"]').checked = true;
  const options = Array.from(processAudioSelect.options);
  const discordOption = options.find((o) => /discord$/i.test(o.textContent.trim()));
  const pick = discordOption || options[0];
  if (pick) processAudioSelect.value = pick.value;
}

audioSourceSelect.addEventListener('change', async () => {
  await updateAudioSourceUiState();
  switchAudioSourceInRoom();
});

processAudioMode.addEventListener('change', () => switchAudioSourceInRoom());
processAudioSelect.addEventListener('change', () => switchAudioSourceInRoom());

async function refreshAudioProcesses() {
  const processes = await window.api.listAudioProcesses();
  const previousValue = processAudioSelect.value;
  processAudioSelect.innerHTML = '';

  processes.forEach((p) => {
    const opt = document.createElement('option');
    opt.value = String(p.pid);
    opt.textContent = p.title.length > 60 ? p.title.slice(0, 57) + '...' : p.title;
    processAudioSelect.appendChild(opt);
  });

  if (processes.some((p) => String(p.pid) === previousValue)) {
    processAudioSelect.value = previousValue;
  }
}

btnRefreshAudioProcesses.addEventListener('click', refreshAudioProcesses);

let processAudioState = null;
let loopbackAudioTrack = null;
let silentAudioTrack = null;
// Um AudioContext só pra todas as tracks silenciosas, reaproveitado. Antes
// cada track nova (toda vez que alguém parava de compartilhar) criava um
// AudioContext novo e nunca fechava o anterior — e um AudioContext rodando
// não é coletado: cada um ficava pra sempre com sua thread de áudio em
// tempo real e seu stream aberto na placa de som, acumulando a cada
// compartilhar/parar.
let silentAudioContext = null;

function getOrCreateSilentAudioTrack() {
  if (silentAudioTrack && silentAudioTrack.readyState === 'live') return silentAudioTrack;
  if (!silentAudioContext || silentAudioContext.state === 'closed') silentAudioContext = new AudioContext();
  const destination = silentAudioContext.createMediaStreamDestination();
  silentAudioTrack = destination.stream.getAudioTracks()[0];
  return silentAudioTrack;
}

async function acquireAudioTrack() {
  const selected = audioSourceSelect.value;

  if (selected === LOOPBACK_VALUE) {
    // Com o addon nativo (Windows), "áudio do sistema" também passa pela
    // captura por processo — pid 0 é o sentinela de "tudo, exceto este
    // próprio app" (ver process_loopback.cpp) — o que deixa esse modo
    // trocável a qualquer momento, igual ao "processo específico".
    if (supportsProcessAudio) return startProcessAudioTrack(0, true);

    if (!loopbackAudioTrack) {
      throw new Error('"Áudio do sistema" só pode ser escolhido ao começar a compartilhar.');
    }
    return loopbackAudioTrack;
  }

  if (selected === PROCESS_VALUE) {
    const pid = Number(processAudioSelect.value);
    if (!pid) throw new Error('Escolha um app na lista de "App específico".');
    const exclude = processAudioMode.querySelector('input:checked').value === 'exclude';
    return startProcessAudioTrack(pid, exclude);
  }

  if (selected) {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: { deviceId: { exact: selected } } });
    return stream.getAudioTracks()[0];
  }

  return getOrCreateSilentAudioTrack();
}

async function startProcessAudioTrack(pid, exclude) {
  const audioCtx = new AudioContext({ sampleRate: 48000 });
  let unsubscribeChunk = () => {};
  let unsubscribeError = () => {};
  let handle;
  let destination;
  try {
    await audioCtx.audioWorklet.addModule('pcm-injector-worklet.js');

    const workletNode = new AudioWorkletNode(audioCtx, 'pcm-injector', { outputChannelCount: [2] });
    destination = audioCtx.createMediaStreamDestination();
    workletNode.connect(destination);

    unsubscribeChunk = window.api.onProcessAudioChunk((samples, sampleRate, channels) => {
      workletNode.port.postMessage({ interleaved: samples, channels }, [samples.buffer]);
    });
    unsubscribeError = window.api.onProcessAudioError((message) => {
      alert('Captura de áudio por processo falhou: ' + message);
    });

    handle = await window.api.startProcessAudioCapture(pid, exclude);
  } catch (err) {
    // Sem isso, uma falha aqui (ex: o addon recusando o processo) deixava
    // este AudioContext rodando pra sempre — ninguém guardava referência
    // pra fechar depois.
    unsubscribeChunk();
    unsubscribeError();
    audioCtx.close().catch(() => {});
    throw err;
  }

  processAudioState = {
    handle,
    audioCtx,
    cleanup: () => {
      unsubscribeChunk();
      unsubscribeError();
      window.api.stopProcessAudioCapture(handle);
      audioCtx.close().catch(() => {});
    },
  };

  return destination.stream.getAudioTracks()[0];
}

// ---------- aplica as tracks locais (vídeo/áudio) em cada RTCPeerConnection ----------

async function applyLocalTracksToPeer(peer) {
  if (!peer.videoSender || !peer.audioSender) return;
  const videoTrack = localStream ? localStream.getVideoTracks()[0] || null : null;
  const audioTrack = localStream ? localStream.getAudioTracks()[0] || null : null;

  await peer.videoSender.replaceTrack(videoTrack).catch(() => {});
  if (videoTrack) applyVideoEncodingToPeer(peer);

  await peer.audioSender.replaceTrack(audioTrack || getOrCreateSilentAudioTrack()).catch(() => {});
}

function applyLocalTracksToAllPeers() {
  roomPeers.forEach((peer) => applyLocalTracksToPeer(peer));
}

function broadcastSharingState() {
  roomPeers.forEach((peer) => {
    sendToPeerReliable(peer, sharingMessage()).catch(() => {});
  });
}

// ===================================================================
// BARRA INFERIOR — começar/parar de compartilhar + popovers
// ===================================================================

const btnToggleShare = document.getElementById('btn-toggle-share');
const btnShareMenu = document.getElementById('btn-share-menu');
const sharePopover = document.getElementById('share-setup-popover');
const btnConfirmShare = document.getElementById('btn-confirm-share');

// Botões que devem poder ABRIR o popover sem que o listener de "fechar ao
// clicar fora" (abaixo) feche ele de volta no mesmo clique — cada um deles
// já cuida de mostrar o popover no próprio handler de click.
const sharePopoverTriggers = [btnToggleShare, btnShareMenu];

function updateShareButtonUI() {
  btnToggleShare.classList.toggle('is-live', mySharing);
  btnToggleShare.title = mySharing ? 'Parar de compartilhar' : 'Compartilhar tela';
  btnToggleShare.innerHTML = mySharing ? STOP_ICON_SVG : SHARE_ICON_SVG;
  btnShareMenu.hidden = !mySharing;
  btnConfirmShare.hidden = mySharing;
  if (!mySharing) hideSharePopover();
}

// O seletor de monitor só é realmente ignorado quando o vídeo em si vem do
// getDisplayMedia com o seletor nativo do SO (que escolhe a tela sozinho) —
// isso só acontece pra "Áudio do sistema" SEM o addon nativo (Windows tem o
// addon, então lá o vídeo sempre vem do seletor de monitor normal, mesmo
// nesse modo de áudio — ver confirmStartSharing()).
function monitorSelectIgnoredByAudioMode() {
  return audioSourceSelect.value === LOOPBACK_VALUE && !supportsProcessAudio;
}

function showSharePopover() {
  sharePopover.hidden = false;
  showDockControls(); // cancela o auto-esconder enquanto o popover estiver aberto
  monitorSelect.disabled = monitorSelectIgnoredByAudioMode();
  updateMonitorThumbnail();
}

function hideSharePopover() {
  if (sharePopover.hidden) return;
  sharePopover.hidden = true;
  showDockControls(); // volta a contar os 2s parado a partir de agora
}

// Antes de começar a compartilhar, o botão principal abre o popover de
// escolher tela/áudio; depois de já estar ao vivo, ele vira o botão de
// PARAR direto (sem popover) e a setinha ao lado reabre o mesmo popover
// (agora pra trocar de monitor/fonte de áudio em pleno andamento).
btnToggleShare.addEventListener('click', () => {
  if (mySharing) {
    stopSharing();
  } else if (sharePopover.hidden) {
    showSharePopover();
  } else {
    hideSharePopover();
  }
});

btnShareMenu.addEventListener('click', () => {
  if (sharePopover.hidden) showSharePopover();
  else hideSharePopover();
});

document.addEventListener('click', (event) => {
  const target = event.target;
  if (
    !sharePopover.hidden &&
    !sharePopover.contains(target) &&
    !sharePopoverTriggers.some((btn) => target === btn || btn.contains(target))
  ) {
    hideSharePopover();
  }
});

monitorSelect.addEventListener('change', () => {
  updateMonitorThumbnail();
  // Se o monitor novo não tem 1440p, a resolução cai pra 1080p aqui mesmo,
  // antes de recapturar — a troca abaixo já sai com a resolução certa.
  updateResolutionAvailability();
  if (mySharing) replaceScreenVideoInRoom('Não foi possível trocar de monitor: ');
});

btnConfirmShare.addEventListener('click', () => confirmStartSharing());

async function confirmStartSharing() {
  // Sem o addon nativo (Windows), "Áudio do sistema" só existe junto do
  // getDisplayMedia (só assim o Electron expõe loopback), que por sua vez
  // escolhe a tela sozinho via seletor nativo do SO. Com o addon, o áudio já
  // não depende mais disso (ver acquireAudioTrack()), então o vídeo segue o
  // caminho normal — seletor de monitor deste popover — igual aos outros
  // modos de áudio, o que deixa trocar de monitor funcionando também aqui.
  const useNativeDisplayMediaLoopback = audioSourceSelect.value === LOOPBACK_VALUE && !supportsProcessAudio;

  let videoTrack;
  let audioTrack;
  try {
    if (useNativeDisplayMediaLoopback) {
      const stream = await navigator.mediaDevices.getDisplayMedia({
        video: displayMediaVideoConstraints(),
        audio: true,
      });
      videoTrack = stream.getVideoTracks()[0];
      loopbackAudioTrack = stream.getAudioTracks()[0] || null;
      audioTrack = loopbackAudioTrack || getOrCreateSilentAudioTrack();
    } else {
      const sourceId = monitorSelect.value;
      if (!sourceId) {
        alert('Escolha um monitor.');
        return;
      }
      videoTrack = await acquireVideoTrackForScreen(sourceId);
      audioTrack = await acquireAudioTrack();
    }
  } catch (err) {
    alert('Não foi possível capturar a tela: ' + err.message);
    return;
  }

  videoTrack.contentHint = SCREEN_CONTENT_HINT;
  localVideoFromDisplayMedia = useNativeDisplayMediaLoopback;
  localStream = new MediaStream([videoTrack, audioTrack]);
  videoTrack.addEventListener('ended', stopSharing);
  refreshLocalPreview();

  mySharing = true;
  mySharingVersion++;
  roomPeers.forEach((peer) => {
    peer.remoteView = 'full';
    peer.remoteViewVersion = 0;
  });
  window.api.setSharingActive(true);
  // Só troca as tracks — sem renegociar. Com os transceivers negociados
  // direito (ver isOfferer), isso basta pros dois sentidos; a renegociação
  // que existia aqui só mascarava o bug dos transceivers órfãos, e ainda
  // dependia da sinalização chegar a cada vez que alguém começava a
  // compartilhar.
  applyLocalTracksToAllPeers();
  broadcastSharingState();
  hideSharePopover();
  updateShareButtonUI();
  renderGrid();
  renderParticipants();
  renderFocusIfShowing();
}

// Recaptura o monitor escolhido no popover com a qualidade escolhida e troca
// a track em todas as conexões sem renegociar — usado tanto pra trocar de
// monitor quanto de resolução/taxa de quadros em pleno andamento.
let screenVideoReplaceSeq = 0;

async function replaceScreenVideoInRoom(errorPrefix) {
  if (!localStream || !mySharing) return;
  const sourceId = monitorSelect.value;
  if (!sourceId) return;

  const seq = ++screenVideoReplaceSeq;
  let newTrack;
  try {
    newTrack = await acquireVideoTrackForScreen(sourceId);
  } catch (err) {
    alert(errorPrefix + err.message);
    return;
  }
  // Pode ter parado de compartilhar enquanto a captura nova abria, ou outra
  // troca (ex: duas mudanças seguidas no popover) já ter começado depois
  // desta — a mais recente é a que vale.
  if (!localStream || !mySharing || seq !== screenVideoReplaceSeq) {
    newTrack.stop();
    return;
  }
  newTrack.contentHint = SCREEN_CONTENT_HINT;

  const oldTrack = localStream.getVideoTracks()[0];
  if (oldTrack) {
    localStream.removeTrack(oldTrack);
    oldTrack.stop();
  }
  localStream.addTrack(newTrack);
  localVideoFromDisplayMedia = false;

  roomPeers.forEach((peer) => {
    if (!peer.videoSender) return;
    peer.videoSender.replaceTrack(newTrack).catch(() => {});
    applyVideoEncodingToPeer(peer);
  });

  localStream.getVideoTracks()[0].addEventListener('ended', stopSharing);
  refreshLocalPreview();
  renderGrid();
  renderFocusIfShowing();
}

async function switchAudioSourceInRoom() {
  if (!localStream || !mySharing) return; // nada compartilhando ainda; "Começar" cuida disso

  const previousProcessState = processAudioState;
  processAudioState = null;

  let newTrack;
  try {
    newTrack = await acquireAudioTrack();
  } catch (err) {
    alert('Não foi possível trocar a fonte de áudio: ' + err.message);
    processAudioState = previousProcessState;
    return;
  }

  const previousTrack = localStream.getAudioTracks()[0];
  if (previousTrack && previousTrack !== newTrack) {
    localStream.removeTrack(previousTrack);
    if (previousTrack !== loopbackAudioTrack && previousTrack !== silentAudioTrack) {
      previousTrack.stop();
    }
  }
  if (!localStream.getAudioTracks().includes(newTrack)) {
    localStream.addTrack(newTrack);
  }

  roomPeers.forEach((peer) => {
    if (peer.audioSender) peer.audioSender.replaceTrack(newTrack).catch(() => {});
  });

  if (previousProcessState) previousProcessState.cleanup();
}

function stopSharing() {
  if (!mySharing && !localStream) return;
  const wasSharing = mySharing;
  mySharing = false;
  if (wasSharing) mySharingVersion++;
  window.api.setSharingActive(false);

  if (localStream) {
    localStream.getTracks().forEach((t) => t.stop());
    localStream = null;
  }
  refreshLocalPreview();
  localVideoFromDisplayMedia = false;
  if (processAudioState) {
    processAudioState.cleanup();
    processAudioState = null;
  }
  if (loopbackAudioTrack) {
    loopbackAudioTrack.stop();
    loopbackAudioTrack = null;
  }
  if (silentAudioTrack) {
    silentAudioTrack.stop();
    silentAudioTrack = null;
  }

  roomPeers.forEach((peer) => {
    if (peer.videoSender) peer.videoSender.replaceTrack(null).catch(() => {});
    if (peer.audioSender) peer.audioSender.replaceTrack(getOrCreateSilentAudioTrack()).catch(() => {});
  });

  if (wasSharing) broadcastSharingState();
  updateShareButtonUI();
  renderGrid();
  renderParticipants();
  renderFocusIfShowing();
}

// ===================================================================
// GRID / FOCO / PARTICIPANTES
// ===================================================================

function sharingItemsList() {
  const items = [];
  if (mySharing) items.push({ kind: 'self', id: 'self', name: `${myName} (você)` });
  roomPeers.forEach((peer) => {
    if (peer.sharing) items.push({ kind: 'peer', id: peer.peerId, name: peer.name, peer });
  });
  return items;
}

// Garante o vídeo + selo AO VIVO + nome dentro de `container`, criando cada
// um SÓ NA PRIMEIRA VEZ e reaproveitando depois — nunca recriando o
// elemento <video> nem reatribuindo `srcObject` quando o stream já é o
// mesmo. Isso importa de verdade: recriar o <video> (ou reatribuir o mesmo
// MediaStream a um <video> novo) toda vez que a sala re-renderiza — o que
// acontece a cada troca de foco/grid e a cada mensagem "sharing" de
// qualquer pessoa na sala, não só quando o item muda de fato — é a causa
// confirmada de um bug real: depois de muitas trocas, o próprio preview
// (elemento local) parava de mostrar frames e ficava preto, mesmo com a
// track/stream continuando perfeitamente viva (por isso quem assistia via
// WebRTC nunca via esse problema — o RTCRtpSender usa a track direto, sem
// passar por nenhum elemento <video>).
const VOLUME_ICON_SVG =
  '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
  '<polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon>' +
  '<path d="M15.54 8.46a5 5 0 0 1 0 7.07"></path>' +
  '<path d="M19.07 4.93a10 10 0 0 1 0 14.14"></path></svg>';
const VOLUME_MUTED_ICON_SVG =
  '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
  '<polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon>' +
  '<line x1="23" y1="9" x2="17" y2="15"></line>' +
  '<line x1="17" y1="9" x2="23" y2="15"></line></svg>';
const PIN_ICON_SVG =
  '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
  '<line x1="12" y1="17" x2="12" y2="22"></line>' +
  '<path d="M5 17h14l-1.6-1.6a2 2 0 0 1-.6-1.42V9a4.8 4.8 0 0 0-9.6 0v5c0 .53-.21 1.04-.58 1.42L5 17z"></path></svg>';
const UNPIN_ICON_SVG =
  '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
  '<line x1="12" y1="17" x2="12" y2="22"></line>' +
  '<path d="M5 17h14l-1.6-1.6a2 2 0 0 1-.6-1.42V9a4.8 4.8 0 0 0-9.6 0v5c0 .53-.21 1.04-.58 1.42L5 17z"></path>' +
  '<line x1="3" y1="3" x2="21" y2="21"></line></svg>';

function ensureMediaTile(container, isSelf) {
  let video = container.querySelector('video');
  if (!video) {
    video = document.createElement('video');
    video.autoplay = true;
    video.playsInline = true;
    container.appendChild(video);
  }
  let badge = container.querySelector('.live-badge');
  if (!badge) {
    badge = document.createElement('div');
    badge.className = 'live-badge';
    badge.innerHTML = '<span class="live-dot"></span><span>AO VIVO</span>';
    container.appendChild(badge);
  }
  let name = container.querySelector('.stream-card-name');
  if (!name) {
    name = document.createElement('div');
    name.className = 'stream-card-name';
    container.appendChild(name);
  }

  // Controle de volume por pessoa — não faz sentido pro próprio preview
  // (autoexcluído do áudio/sempre mutado). Ícone sempre visível, slider só
  // aparece ao passar o mouse (puro CSS, ver .volume-control:hover).
  let volumeSlider = container.querySelector('.volume-slider');
  if (!isSelf && !volumeSlider) {
    const volumeControl = document.createElement('div');
    volumeControl.className = 'volume-control';
    // Sem isso, clicar/arrastar o slider também dispara o clique do card
    // (entrar em foco) por baixo dele.
    volumeControl.addEventListener('click', (event) => event.stopPropagation());

    const volumeBtn = document.createElement('button');
    volumeBtn.type = 'button';
    volumeBtn.className = 'volume-icon-btn';
    volumeBtn.innerHTML = VOLUME_ICON_SVG;
    volumeControl.appendChild(volumeBtn);

    const sliderWrap = document.createElement('div');
    sliderWrap.className = 'volume-slider-wrap';
    volumeSlider = document.createElement('input');
    volumeSlider.type = 'range';
    volumeSlider.min = '0';
    volumeSlider.max = '100';
    volumeSlider.value = '100';
    volumeSlider.className = 'volume-slider';
    sliderWrap.appendChild(volumeSlider);
    volumeControl.appendChild(sliderWrap);

    container.appendChild(volumeControl);
  }

  const volumeBtn = container.querySelector('.volume-icon-btn');

  // Overlay de fixar/desafixar (estilo Discord) e o ícone de volume: os dois
  // só aparecem enquanto o mouse se MEXE por cima do card, somem depois de
  // 2s parado, igual ao resto da UI (dock etc). Controlados pela mesma
  // classe no CONTAINER (.tile-controls-active, ver .pin-overlay/
  // .volume-control no CSS) em vez de cada um ter seu próprio timer. O
  // clique de fixar/desafixar continua valendo em qualquer lugar do card
  // mesmo com o ícone escondido (é só uma pista visual, nunca intercepta
  // clique — pointer-events: none — e o onclick fica no card/tile inteiro,
  // não no ícone); o de volume já reaparece antes de poder ser clicado.
  let pinOverlay = container.querySelector('.pin-overlay');
  if (!pinOverlay) {
    pinOverlay = document.createElement('div');
    pinOverlay.className = 'pin-overlay';
    pinOverlay.innerHTML = '<span class="pin-icon"></span>';
    container.appendChild(pinOverlay);

    let idleTimer = null;
    const showTileControls = () => {
      container.classList.add('tile-controls-active');
      clearTimeout(idleTimer);
      idleTimer = setTimeout(() => container.classList.remove('tile-controls-active'), 2000);
    };
    const hideTileControls = () => {
      clearTimeout(idleTimer);
      container.classList.remove('tile-controls-active');
    };
    container.addEventListener('mouseenter', showTileControls);
    container.addEventListener('mousemove', showTileControls);
    container.addEventListener('mouseleave', hideTileControls);
  }
  const pinIcon = pinOverlay.querySelector('.pin-icon');

  // "Reconectando..." por cima do vídeo de quem caiu — sem isso o card
  // ficava preto (ou congelado no último frame) sem explicação nenhuma.
  let reconnectingOverlay = container.querySelector('.tile-reconnecting');
  if (!isSelf && !reconnectingOverlay) {
    reconnectingOverlay = document.createElement('div');
    reconnectingOverlay.className = 'tile-reconnecting';
    reconnectingOverlay.innerHTML = '<span class="btn-spinner" aria-hidden="true"></span><span>Reconectando...</span>';
    reconnectingOverlay.hidden = true;
    container.appendChild(reconnectingOverlay);
  }

  return { video, name, volumeSlider, volumeBtn, pinIcon, reconnectingOverlay };
}

// Muda o volume de um peer e, se o valor for maior que zero, também guarda
// como "o volume de antes de mutar" — assim o botão de mute sempre sabe pra
// onde restaurar, seja o mute tendo vindo de um clique no ícone ou de
// arrastar o slider até o zero na mão.
function setPeerVolume(peer, v) {
  peer.volume = v;
  if (v > 0) peer.volumeBeforeMute = v;
}

// `pinMode`: 'pin' pro grid/tira de miniaturas (clicar fixa esse em foco) ou
// 'unpin' pro card grande do foco (clicar volta pro grid).
function updateMediaTile(container, item, pinMode) {
  const { video, name, volumeSlider, volumeBtn, pinIcon, reconnectingOverlay } = ensureMediaTile(container, item.kind === 'self');
  const desiredStream = item.kind === 'self' ? localPreviewStream : item.peer.remoteStream || null;
  video.muted = item.kind === 'self';
  if (video.srcObject !== desiredStream) video.srcObject = desiredStream;
  name.textContent = item.name;
  pinIcon.innerHTML = pinMode === 'unpin' ? UNPIN_ICON_SVG : PIN_ICON_SVG;
  if (reconnectingOverlay) reconnectingOverlay.hidden = !(item.kind === 'peer' && item.peer.reconnecting);

  if (volumeSlider && item.kind !== 'self') {
    const peer = item.peer;
    if (peer.volume == null) peer.volume = 1;
    if (peer.volumeBeforeMute == null) peer.volumeBeforeMute = 1;
    video.volume = peer.volume;
    volumeBtn.innerHTML = peer.volume > 0 ? VOLUME_ICON_SVG : VOLUME_MUTED_ICON_SVG;
    // Não pisa no valor enquanto a pessoa está arrastando (evita "puxar" o
    // slider de volta pro valor antigo no meio do gesto).
    if (document.activeElement !== volumeSlider) {
      volumeSlider.value = String(Math.round(peer.volume * 100));
    }
    // Mexer no slider sempre "reativa" (o valor arrastado passa a valer na
    // hora, mesmo vindo de um estado mutado).
    volumeSlider.oninput = () => {
      setPeerVolume(peer, Number(volumeSlider.value) / 100);
      video.volume = peer.volume;
      volumeBtn.innerHTML = peer.volume > 0 ? VOLUME_ICON_SVG : VOLUME_MUTED_ICON_SVG;
    };
    // Clique no ícone alterna: muta (lembrando o volume atual) ou restaura
    // pro volume de antes de mutar.
    volumeBtn.onclick = () => {
      setPeerVolume(peer, peer.volume > 0 ? 0 : peer.volumeBeforeMute);
      video.volume = peer.volume;
      volumeSlider.value = String(Math.round(peer.volume * 100));
      volumeBtn.innerHTML = peer.volume > 0 ? VOLUME_ICON_SVG : VOLUME_MUTED_ICON_SVG;
    };
  }

  if (desiredStream) {
    video.play().catch((err) => console.warn('[room] play() recusado pra', item.name, '—', err.message));
  }
}

// Registros dos elementos já criados pra cada "slot" (grid, foco principal,
// tira de miniaturas do foco) — reaproveitados entre renders em vez de
// recriados; só criam/removem quando um item realmente aparece/some.
const gridTileEls = new Map(); // id -> elemento
const focusStripTileEls = new Map(); // id -> elemento

function resetMediaTileRegistries() {
  gridTileEls.forEach((el) => el.remove());
  gridTileEls.clear();
  focusStripTileEls.forEach((el) => el.remove());
  focusStripTileEls.clear();
  focusMainEl.innerHTML = '';
}

function renderGrid() {
  if (focusedPeerId !== null) return; // a view de foco cuida da própria renderização
  const items = sharingItemsList();
  const ids = new Set(items.map((item) => item.id));

  gridEmptyEl.hidden = items.length > 0;
  streamGridEl.hidden = items.length === 0;

  gridTileEls.forEach((el, id) => {
    if (!ids.has(id)) {
      el.remove();
      gridTileEls.delete(id);
    }
  });

  items.forEach((item) => {
    let el = gridTileEls.get(item.id);
    if (!el) {
      el = document.createElement('div');
      el.className = 'stream-card';
      streamGridEl.appendChild(el);
      gridTileEls.set(item.id, el);
    }
    el.onclick = () => enterFocus(item.id);
    updateMediaTile(el, item, 'pin');
  });
  updateViewRequests();
}

// Deixar de renderizar um lado (grid ou foco) só esconde o container por
// CSS — os elementos <video> continuam vivos e tocando áudio por trás,
// sem que mais ninguém atualize o volume deles (porque aquele lado parou
// de renderizar). Sem mutar explicitamente quem vai ficar escondido, dava
// pra ouvir a mesma pessoa duas vezes (uma pelo card antigo, mudo pro
// controle de volume; outra pelo novo) até sair e voltar do foco de novo.
// O lado que vai ficar visível se corrige sozinho (`updateMediaTile` já
// desmuta quando não é o próprio preview e dá play), então só precisa
// cuidar de quem está saindo de cena.
//
// Além de mutar, PAUSA: um <video> escondido continua recebendo e
// desenhando cada frame (medido: ~3,5% de um núcleo por vídeo 1080p60 só
// pros cards do grid escondidos atrás do foco). Os pausados aqui são
// sempre cópias mudas de quem já está tocando no lado visível — o áudio
// da pessoa continua saindo por lá.
function pauseAllVideosIn(elements) {
  for (const el of elements) {
    const video = el.querySelector('video');
    if (!video) continue;
    video.muted = true;
    video.pause();
  }
}

function enterFocus(id) {
  focusedPeerId = id;
  pauseAllVideosIn(gridTileEls.values());
  renderFocus();
}

function exitFocus() {
  focusedPeerId = null;
  focusViewEl.hidden = true;
  pauseAllVideosIn(focusStripTileEls.values());
  pauseAllVideosIn([focusMainEl]);
  renderGrid();
}

// Clicar em qualquer lugar do card grande do foco desafixa e volta pro grid
// — não muda por quem está focado, então é fixado uma vez só, fora do
// ciclo de render (evita reatribuir o mesmo handler sem necessidade).
focusMainEl.onclick = () => exitFocus();

// Oculta/mostra a tira com a transmissão de todo mundo além da pessoa
// fixada, só a visibilidade, sem mexer no áudio (continuam ouvíveis
// mesmo escondidos, só o vídeo some).
btnToggleFocusStrip.addEventListener('click', (event) => {
  event.stopPropagation(); // não deixa o clique "vazar" pro fundo (ex.: sair do foco)
  focusStripCollapsed = !focusStripCollapsed;
  // "^" indica que já está no modo exclusivo (só a pessoa fixada); "v"
  // indica que clicar entra no modo exclusivo (esconde os outros).
  btnToggleFocusStrip.innerHTML = focusStripCollapsed ? PEOPLE_CHEVRON_UP_SVG : PEOPLE_CHEVRON_DOWN_SVG;
  btnToggleFocusStrip.title = focusStripCollapsed ? 'Mostrar as outras transmissões' : 'Ocultar as outras transmissões';
  focusStripEl.hidden = focusStripCollapsed || focusStripEl.childElementCount === 0;
  // Só no modo exclusivo o vídeo pinado desce até o fundo da tela, é só aí
  // que o botão precisa subir pra não ficar atrás da dock em tela cheia
  // (ver .room-view.stage-zoomed.focus-strip-collapsed no CSS). Com a tira
  // visível ele já sobra bem acima da dock, sem precisar disso.
  viewRoom.classList.toggle('focus-strip-collapsed', focusStripCollapsed);
  updateViewRequests();
});

function renderFocusIfShowing() {
  if (focusedPeerId !== null) renderFocus();
}

function renderFocus() {
  const items = sharingItemsList();
  const focusedItem = items.find((item) => item.id === focusedPeerId);
  if (!focusedItem) {
    exitFocus();
    return;
  }

  streamGridEl.hidden = true;
  gridEmptyEl.hidden = true;
  focusViewEl.hidden = false;

  updateMediaTile(focusMainEl, focusedItem, 'unpin');

  const stripItems = items.filter((item) => item.id !== focusedPeerId);
  const stripIds = new Set(stripItems.map((item) => item.id));

  // O botão só faz sentido quando tem alguém além da pessoa fixada pra
  // esconder; sem ninguém na tira não há o que ocultar.
  const hasOthers = stripItems.length > 0;
  btnToggleFocusStrip.hidden = !hasOthers;
  focusStripEl.hidden = !hasOthers || focusStripCollapsed;

  focusStripTileEls.forEach((el, id) => {
    if (!stripIds.has(id)) {
      el.remove();
      focusStripTileEls.delete(id);
    }
  });

  stripItems.forEach((item) => {
    let el = focusStripTileEls.get(item.id);
    if (!el) {
      el = document.createElement('div');
      el.className = 'focus-thumb';
      focusStripEl.appendChild(el);
      focusStripTileEls.set(item.id, el);
    }
    el.onclick = () => enterFocus(item.id);
    updateMediaTile(el, item, 'pin');
  });
  updateViewRequests();
}

const connectionStateLabels = {
  new: 'conectando',
  connecting: 'conectando',
  connected: 'conectado',
  disconnected: 'desconectado',
  failed: 'falhou',
  closed: 'fechado',
};

function renderParticipants() {
  participantsListEl.innerHTML = '';

  const entries = [{ isSelf: true, name: `${myName} (você)`, sharing: mySharing }];
  roomPeers.forEach((peer) => entries.push(peer));

  entries.forEach((entry) => {
    const li = document.createElement('li');

    const avatar = document.createElement('span');
    avatar.className = 'viewer-avatar';
    avatar.textContent = (entry.name || '?').trim().charAt(0).toUpperCase() || '?';

    const name = document.createElement('span');
    name.className = 'viewer-name';
    name.textContent = entry.name;

    const pill = document.createElement('span');
    let statusClass = 'status-connecting';
    let statusText = connectionStateLabels[entry.connectionState] || 'conectando';
    if (entry.isSelf) {
      statusClass = 'status-connected';
      statusText = entry.sharing ? 'compartilhando' : 'você';
    } else if (entry.connectionState === 'connected') {
      statusClass = 'status-connected';
      statusText = entry.sharing ? 'compartilhando' : 'conectado';
    } else if (entry.everConnected && entry.downSince !== null) {
      // Caiu e está tentando voltar (ver recoveryTick).
      statusText = 'reconectando';
    } else if (entry.timeoutReason) {
      // Nunca chegou a conectar e já passou do prazo inicial (ver
      // recoveryTick) — diz onde travou em vez de "conectando" pra sempre.
      statusClass = 'status-failed';
      statusText = entry.timeoutReason === 'signaling' ? 'sem conexão (sinalização)' : 'sem conexão (rede)';
    }
    pill.className = 'status-pill ' + statusClass;
    pill.textContent = statusText;

    const meta = document.createElement('span');
    meta.className = 'viewer-meta';
    meta.appendChild(name);
    meta.appendChild(pill);

    const left = document.createElement('span');
    left.className = 'viewer-row-left';
    left.appendChild(avatar);
    left.appendChild(meta);

    li.appendChild(left);
    participantsListEl.appendChild(li);
  });
}

// Diagnóstico de bitrate/fps por conexão (visível só no console/DevTools,
// que fica desligado nos executáveis empacotados) — mesma finalidade do
// diagnóstico que já existia no fluxo 1:1, generalizada pra cada peer da
// malha em vez de cada espectador.
setInterval(async () => {
  if (!mySharing) return;
  for (const peer of roomPeers.values()) {
    if (!peer.videoSender || !peer.pc || peer.pc.connectionState !== 'connected') continue;
    const stats = await peer.pc.getStats().catch(() => null);
    if (!stats) continue;
    stats.forEach((report) => {
      if (report.type !== 'outbound-rtp' || report.kind !== 'video') return;
      if (peer.lastStatsSample) {
        const dtSeconds = (report.timestamp - peer.lastStatsSample.timestamp) / 1000;
        const dBytes = report.bytesSent - peer.lastStatsSample.bytesSent;
        if (dtSeconds > 0) {
          const kbps = Math.round((dBytes * 8) / dtSeconds / 1000);
          const limitation = report.qualityLimitationReason && report.qualityLimitationReason !== 'none' ? report.qualityLimitationReason : null;
          console.log(
            `[stats] ${peer.name}: ${(kbps / 1000).toFixed(1)} Mbps` +
              (report.framesPerSecond ? ` · ${report.framesPerSecond} fps` : '') +
              (limitation ? ` · limitado por ${limitation}` : '')
          );
        }
      }
      peer.lastStatsSample = { timestamp: report.timestamp, bytesSent: report.bytesSent };
    });
  }
}, 4000);

// Diagnóstico decisivo pra separar "não chega frame nenhum" (rede/codec) de
// "chega frame mas não aparece na tela" (renderização/CSS): olha tanto o
// que a RTCPeerConnection diz ter DECODIFICADO de verdade (inbound-rtp)
// quanto o próprio elemento <video> (dimensão real do vídeo carregado,
// estado de carregamento, se está pausado) pra cada participante conectado
// — independente de eu estar compartilhando ou não.
setInterval(async () => {
  for (const peer of roomPeers.values()) {
    if (!peer.pc || peer.pc.connectionState !== 'connected') continue;
    const stats = await peer.pc.getStats().catch(() => null);
    if (!stats) continue;
    stats.forEach((report) => {
      if (report.type !== 'inbound-rtp' || report.kind !== 'video') return;

      const prev = peer.lastInboundSample;
      let rate = '';
      if (prev) {
        const dtSeconds = (report.timestamp - prev.timestamp) / 1000;
        const dBytes = report.bytesReceived - prev.bytesReceived;
        const dFrames = (report.framesDecoded ?? 0) - (prev.framesDecoded ?? 0);
        if (dtSeconds > 0) {
          rate = ` · ${Math.round((dBytes * 8) / dtSeconds / 1000)} kbps recebidos · ${dFrames} frames decodificados`;
        }
      }
      peer.lastInboundSample = { timestamp: report.timestamp, bytesReceived: report.bytesReceived, framesDecoded: report.framesDecoded };

      const container = gridTileEls.get(peer.peerId) || focusStripTileEls.get(peer.peerId) || (focusedPeerId === peer.peerId ? focusMainEl : null);
      const video = container ? container.querySelector('video') : null;
      const videoInfo = video
        ? ` · <video>: ${video.videoWidth}x${video.videoHeight}px, readyState=${video.readyState}, paused=${video.paused}`
        : ' · sem <video> na tela agora (não está compartilhando pra mim ou não está com foco/grid mostrando)';

      console.log(`[recv-stats] ${peer.name}: resolução recebida ${report.frameWidth || '?'}x${report.frameHeight || '?'}${rate}${videoInfo}`);
    });
  }
}, 4000);
