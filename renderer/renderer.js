const ICE_SERVERS = [{ urls: 'stun:stun.l.google.com:19302' }];

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
const homeStatusEl = document.getElementById('home-status');

function setHomeStatus(text, isError) {
  homeStatusEl.textContent = text;
  homeStatusEl.hidden = !text;
  homeStatusEl.style.color = isError ? 'var(--accent-strong)' : '';
}

pasteJoinCodeBtn.addEventListener('click', async () => {
  joinCodeInput.value = await window.api.readClipboard();
});

btnCreateRoom.addEventListener('click', async () => {
  const name = createNameInput.value.trim() || 'Anônimo';
  const passphrase = createPassphraseInput.value.trim();
  btnCreateRoom.disabled = true;
  setHomeStatus('Criando sala...', false);
  try {
    await enterRoom({ name, passphrase });
  } finally {
    btnCreateRoom.disabled = false;
  }
});

btnJoinRoom.addEventListener('click', async () => {
  const name = joinNameInput.value.trim() || 'Anônimo';
  const passphrase = joinPassphraseInput.value.trim();
  let decoded;
  try {
    decoded = await decode(joinCodeInput.value, passphrase);
  } catch (err) {
    setHomeStatus('Código inválido: ' + err.message, true);
    return;
  }
  if (!decoded || typeof decoded.sid !== 'string' || !Array.isArray(decoded.cands)) {
    setHomeStatus('Código inválido: não parece ser um código de sala.', true);
    return;
  }

  btnJoinRoom.disabled = true;
  setHomeStatus('Entrando na sala...', false);
  try {
    await enterRoom({ name, passphrase, hostSid: decoded.sid, hostCands: decoded.cands });
  } finally {
    btnJoinRoom.disabled = false;
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
let roomPeers = new Map(); // peerId -> { peerId, name, sid, cands, pc, videoSender, audioSender, remoteStream, sharing, connectionState }
let myInviteCodePromise = null;
let focusedPeerId = null; // null | 'self' | peerId
let focusStripCollapsed = false; // esconde a tira de miniaturas na view de foco (ver btnToggleFocusStrip)
let mySharing = false;
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
function joinFailureMessage(ntfyOutcome) {
  switch (ntfyOutcome) {
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

async function enterRoom({ name, passphrase, hostSid, hostCands }) {
  myPeerId = randomPeerId();
  myName = name;
  myPassphrase = passphrase;
  mySharing = false;
  focusedPeerId = null;
  roomPeers = new Map();
  localStream = null;
  // Limpa qualquer mensagem deixada por uma tentativa anterior (ex: "não
  // consegui entrar na sala" de um código antigo que falhou) — sem isso, ela
  // ficava perdida em #room-status e reaparecia na sala nova, mesmo
  // funcionando normalmente, porque só o fluxo de "Entrar" (hostSid) mexe
  // nesse texto: criar uma sala nova nunca escrevia nada nele pra sobrescrever.
  setRoomStatus('');

  myListener = await window.api.startSignalListener();
  if (!myListener) {
    setHomeStatus('Conexão automática indisponível nessa rede — não é possível criar ou entrar em salas.', true);
    return;
  }

  unsubscribeSignal = window.api.onSignalMessage(({ message, from }) => handleSignalMessage(message, from));

  roomNameLabel.textContent = hostSid ? 'Sala' : `Sala de ${myName}`;
  myInviteCodePromise = encode({ v: 1, sid: myListener.sessionId, cands: myListener.candidates }, myPassphrase);

  showRoomScreen();
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
    const result = await window.api.sendSignalMessage({
      mySessionId: myListener.sessionId,
      candidates: hostCands,
      targetSessionId: hostSid,
      message: joinMessage,
    });
    if (!result.ok) {
      setRoomStatus(joinFailureMessage(result.ntfy) + ' Voltando ao início...');
      // Sem isso a pessoa ficava presa numa "sala" sozinha, sem ninguém
      // conectado, até clicar em "Sair da sala" por conta própria — agora
      // volta pra tela inicial sozinha depois de um tempo pra dar chance de
      // ler a mensagem, a menos que ela já tenha saído manualmente antes
      // (leaveRoom() cancela este timer).
      joinFailureAutoLeaveTimer = setTimeout(() => {
        joinFailureAutoLeaveTimer = null;
        leaveRoom();
      }, 10000);
    } else {
      setRoomStatus('');
    }
  }
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
// (ou o mouse sair da janela) mostra/esconde na hora.
let dockIdleTimer = null;
function showDockControls() {
  viewRoom.classList.remove('controls-hidden');
  clearTimeout(dockIdleTimer);
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
  viewRoom.classList.add('controls-hidden');
});

btnLeaveRoom.addEventListener('click', () => leaveRoom());

function leaveRoom() {
  if (joinFailureAutoLeaveTimer) {
    clearTimeout(joinFailureAutoLeaveTimer);
    joinFailureAutoLeaveTimer = null;
  }

  roomPeers.forEach((peer) => {
    sendToPeer(peer, { t: 'peer-left', peerId: myPeerId }).catch(() => {});
  });
  roomPeers.forEach((peer) => {
    if (peer.pc) peer.pc.close();
  });
  roomPeers.clear();

  stopSharing();

  if (myListener) {
    window.api.stopSignalListener(myListener.sessionId);
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
  // Sem isso, uma mensagem tipo "Criando sala..."/"Entrando na sala..." que
  // ficou parada em #home-status (nunca sobrescrita porque a sala anterior
  // abriu com sucesso e nunca mais voltou pra tela inicial) reaparecia do
  // nada ao sair da sala, como se algo ainda estivesse em andamento.
  setHomeStatus('', false);
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
function handleSignalMessage(message, from) {
  if (!message || typeof message.t !== 'string') return;
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
      if (message.peerId) removePeer(message.peerId);
      break;
    case 'offer': {
      if (message.sender) connectToPeer(message.sender);
      const peer = findPeerBySid(from);
      if (peer) handleOffer(peer, message.sdp);
      else console.warn('[room] oferta recebida de peer desconhecido (sem sender embutido?)', from);
      break;
    }
    case 'ice-candidate': {
      if (message.sender) connectToPeer(message.sender);
      const peer = findPeerBySid(from);
      if (peer) handleIceCandidate(peer, message.candidate);
      break;
    }
    case 'answer': {
      if (message.sender) connectToPeer(message.sender);
      const peer = findPeerBySid(from);
      if (peer) handleAnswer(peer, message.sdp);
      else console.warn('[room] resposta recebida de peer desconhecido (sem sender embutido?)', from);
      break;
    }
    case 'sharing': {
      if (message.sender) connectToPeer(message.sender);
      const peer = findPeerBySid(from);
      if (peer) {
        peer.sharing = !!message.on;
        console.log('[room] status de compartilhamento de', peer.name, '->', peer.sharing);
        renderGrid();
        renderParticipants();
        renderFocusIfShowing();
      } else {
        console.warn('[room] "sharing" recebido de peer desconhecido (sem sender embutido?)', from);
      }
      break;
    }
  }
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
  if (peerInfo.peerId === myPeerId || roomPeers.has(peerInfo.peerId)) return;
  console.log('[room] recebi "join" de', peerInfo.name, '— apresentando pro resto da sala');

  const roster = [...roomPeers.values()].map(toPeerInfo);
  roster.push({ peerId: myPeerId, name: myName, sid: myListener.sessionId, cands: myListener.candidates });

  connectToPeer(peerInfo);
  const newPeer = roomPeers.get(peerInfo.peerId);
  if (newPeer) sendToPeer(newPeer, { t: 'welcome', roster }).catch(() => {});

  roomPeers.forEach((peer) => {
    if (peer.peerId === peerInfo.peerId) return;
    sendToPeer(peer, { t: 'peer-joined', peer: peerInfo }).catch(() => {});
  });
}

function handleWelcome(message) {
  if (!Array.isArray(message.roster)) return;
  console.log('[room] recebi "welcome" com', message.roster.length, 'participante(s) já na sala');
  message.roster.forEach((peerInfo) => connectToPeer(peerInfo));
  setRoomStatus('');
}

function sendToPeer(peer, message, opts) {
  // `myListener` pode virar null no meio de um envio ainda em andamento (ex:
  // saiu da sala/fechou o app enquanto uma retentativa de sendToPeerReliable
  // ainda estava pendente) — sem essa checagem, isso derrubava a função com
  // "Cannot read properties of null (reading 'sessionId')" em vez de só
  // desistir silenciosamente, algo que só o try/catch de quem chama não
  // cobria porque a exceção vinha antes de qualquer Promise existir.
  if (!myListener) return Promise.resolve({ ok: false, via: null });
  return window.api.sendSignalMessage({
    mySessionId: myListener.sessionId,
    candidates: peer.cands,
    targetSessionId: peer.sid,
    message,
    opts,
  });
}

// Uma tentativa de sendToPeer já é bem persistente por si só (reenvia por
// UDP por ~6s e corre em paralelo com o retransmissor ntfy — ver
// signal-punch.js), mas se as DUAS vias falharem nessa janela (rede
// congestionada, o stream ntfy do outro lado reconectando bem nesse
// instante etc.), a tentativa acaba e NINGUÉM tenta de novo — a oferta ou
// resposta simplesmente se perde pra sempre e aquele par fica travado
// (tela preta permanente, só resolvia saindo e entrando de novo). Pra
// mensagens que realmente precisam chegar pra a conexão funcionar
// (oferta/resposta), tenta de novo algumas vezes antes de desistir de
// verdade.
async function sendToPeerReliable(peer, message, { attempts = 3, opts } = {}) {
  let result = { ok: false, via: null };
  for (let i = 0; i < attempts; i++) {
    result = await sendToPeer(peer, message, opts);
    if (result.ok) return result;
    console.warn(
      `[room] envio de "${message.t}" pra`, peer.name,
      `falhou (tentativa ${i + 1}/${attempts}) — ntfy:`, result.ntfy || 'n/d'
    );
  }
  return result;
}

// ---------- malha de conexões WebRTC (uma RTCPeerConnection por par) ----------

function connectToPeer(peerInfo) {
  if (!peerInfo || peerInfo.peerId === myPeerId || roomPeers.has(peerInfo.peerId)) return;
  console.log('[room] conhecendo novo participante:', peerInfo.name, peerInfo.peerId);
  const peer = {
    peerId: peerInfo.peerId,
    name: peerInfo.name || 'Participante',
    sid: peerInfo.sid,
    cands: peerInfo.cands,
    pc: null,
    videoSender: null,
    audioSender: null,
    remoteStream: null,
    remoteStreamFromEvent: false,
    pendingIceCandidates: [],
    makingOffer: false,
    sharing: false,
    volume: 1,
    volumeBeforeMute: 1,
    connectionState: 'new',
    connectionTimedOut: false,
    iceWatchdogTimer: null,
  };
  roomPeers.set(peer.peerId, peer);
  setupPeerConnection(peer);
  renderParticipants();
}

// A malha é formada uma vez, ao conhecer cada participante: toda conexão já
// nasce com um sender de vídeo e um de áudio (o de áudio sempre com uma
// track — real ou silenciosa, mesmo truque que já existia pro áudio no
// fluxo 1:1). Começar/parar de compartilhar depois disso é só trocar o
// conteúdo dessas tracks via replaceTrack, sem renegociar nada — é o que
// faz a conexão continuar de pé na sala quando alguém para de transmitir.
async function setupPeerConnection(peer) {
  const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
  peer.pc = pc;

  // Alguns pares nunca chegam a 'failed' sozinhos mesmo quando o NAT estrito
  // de um dos lados torna essa conexão P2P (só STUN, sem TURN aqui — ver
  // ICE_SERVERS) impossível de verdade: o agente de ICE do Chromium pode
  // ficar preso em 'checking'/'new' pra sempre, sem nunca avisar. Sem isso,
  // a pessoa ficava "conectando" na lista de participantes indefinidamente,
  // com a tela preta, sem feedback nenhum de que aquele par específico
  // nunca vai conectar. Não fecha a conexão (ainda pode conectar de
  // verdade, só devagar) — só avisa visualmente; `connectionstatechange`
  // limpa isso se ela realmente conectar depois.
  peer.iceWatchdogTimer = setTimeout(() => {
    if (pc.connectionState !== 'connected') {
      console.warn(
        '[room] conexão com', peer.name, 'não fechou em 20s — provável NAT estrito sem TURN',
        'nessa combinação de redes (connectionState:', pc.connectionState + ')'
      );
      peer.connectionTimedOut = true;
      renderParticipants();
    }
  }, 20000);

  // Associa os dois transceivers a UM MediaStream próprio (mesmo sem track
  // nenhuma ainda) — sem isso, o m-line negociado não carrega um "msid"
  // de verdade, e o `event.streams` do lado de quem recebe chega vazio.
  // Confirmado num teste real: sem essa associação, o <video> ficava com
  // `srcObject` atribuído certinho (mesmo id, sem erro nenhum) mas
  // `readyState` nunca saía de 0 — só reproduzindo com o MediaStream
  // "oficial" do evento "track" (em vez de um montado na mão via
  // getReceivers) que passou a carregar de verdade.
  const outgoingStream = new MediaStream();
  peer.videoSender = pc.addTransceiver('video', { direction: 'sendrecv', streams: [outgoingStream] }).sender;
  peer.audioSender = pc.addTransceiver('audio', { direction: 'sendrecv', streams: [outgoingStream] }).sender;
  peer.audioSender.replaceTrack(getOrCreateSilentAudioTrack()).catch(() => {});

  if (localStream) applyLocalTracksToPeer(peer);

  // Prefere o MediaStream que o próprio evento "track" já entrega
  // (`event.streams[0]`) — é o caminho "oficial"/testado do navegador, ao
  // contrário de montar um MediaStream na mão a partir de
  // `pc.getReceivers()` (ver `syncRemoteStreamFromReceivers`, mantida só
  // como reforço pro caso raro de `event.streams` vir vazio mesmo assim).
  pc.addEventListener('track', (event) => {
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
    peer.connectionState = pc.connectionState;
    console.log('[room] conexão com', peer.name, '->', pc.connectionState);
    if (pc.connectionState === 'connected') {
      clearTimeout(peer.iceWatchdogTimer);
      peer.connectionTimedOut = false;
    }
    if (pc.connectionState === 'failed' || pc.connectionState === 'closed') {
      removePeer(peer.peerId);
      return;
    }
    syncRemoteStreamFromReceivers(peer); // qualquer transição serve de gatilho; a função decide sozinha se há o que fazer
    renderParticipants();
  });

  // ICE incremental ("trickle"): manda cada candidato assim que é
  // descoberto, em vez de esperar a descoberta inteira terminar pra só
  // então mandar a oferta/resposta completa (como era antes). Best-effort
  // (sem retentativa) — perder um candidato específico não é fatal, o ICE
  // só não vai poder tentar aquele caminho de rede, desde que outros
  // cheguem. Ver `handleIceCandidate`/`flushPendingIceCandidates` do lado
  // de quem recebe.
  pc.addEventListener('icecandidate', (event) => {
    if (!event.candidate) return; // null = descoberta terminou, nada a mandar
    sendToPeer(peer, { t: 'ice-candidate', sender: myPeerInfo(), candidate: event.candidate.toJSON() }).catch(() => {});
  });

  // Desempate de quem manda a oferta inicial: o peerId lexicograficamente
  // menor oferece, o outro espera — evita ofertas duplicadas quando os dois
  // lados descobrem um ao outro ao mesmo tempo. Com ICE incremental não
  // precisa mais esperar a descoberta de rede terminar antes de mandar — os
  // candidatos vão chegando depois, um por um. Reaproveita `negotiate()`
  // (mesma função usada pra renegociar depois, ver mais abaixo) pra manter
  // o `makingOffer` corretamente marcado desde a primeiríssima oferta.
  if (myPeerId < peer.peerId) {
    negotiate(peer);
  }

  if (mySharing) sendToPeerReliable(peer, { t: 'sharing', sender: myPeerInfo(), on: true }).catch(() => {});
}

// Lê diretamente o que a RTCPeerConnection já está recebendo agora
// (independente de o evento "track" ter disparado ou não). Só age UMA VEZ
// por peer, pra sempre — nunca reconstrói depois disso.
//
// Isso não é preguiça: foi um bug real e sério. A versão anterior
// reconstruía o MediaStream a cada 3s enquanto o <video> não desse sinal de
// vida — mas atribuir um MediaStream NOVO a `srcObject` interrompe
// qualquer carregamento em andamento ("play() request was interrupted by a
// new load request", visto se repetindo pra sempre no console de um teste
// real). Ou seja, o próprio reforço se sabotava: cada nova tentativa
// cancelava a anterior antes dela ter qualquer chance de terminar de
// carregar, num loop que nunca podia dar certo. A correção é confiar que
// uma atribuição única e sem interrupção tem tempo de carregar de verdade
// (é exatamente o que já funciona no `<video>` do próprio preview e no
// caminho oficial via `event.streams[0]`) — nunca reatribuir de novo.
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

// Quem NÃO era o ofertante original (peerId maior no desempate) cede em
// caso de colisão de ofertas — convenção arbitrária mas precisa ser a MESMA
// dos dois lados, e reaproveitar o mesmo desempate já usado pra decidir
// quem oferece na conexão inicial mantém isso consistente.
function isPolite(peer) {
  return !(myPeerId < peer.peerId);
}

// Refaz a oferta numa conexão que já existe — usado quando alguém começa a
// compartilhar (ver confirmStartSharing/applyLocalTracksToAllPeers). Só
// trocar a track (replaceTrack) sobre a conexão original tecnicamente
// deveria bastar, mas um teste real mostrou isso ficando instável de forma
// não-determinística — a MESMA dupla de pessoas, no mesmo papel, funcionava
// numa rodada de compartilhar e travava (tela presa em "nada carregado") na
// próxima, sem nenhuma mudança de código entre uma e outra. Renegociar do
// zero toda vez que alguém começa a compartilhar tem uma vantagem concreta:
// quem está COMPARTILHANDO sempre manda a oferta dessa negociação, o que
// deixa quem está ASSISTINDO sempre no papel de quem responde — o único
// papel que se mostrou confiável em receber o evento "track" em todos os
// testes até aqui.
async function negotiate(peer) {
  if (!peer.pc) return;
  try {
    peer.makingOffer = true;
    const offer = await peer.pc.createOffer();
    await peer.pc.setLocalDescription(offer);
    console.log('[room] renegociando (nova oferta) com', peer.name);
    const result = await sendToPeerReliable(peer, { t: 'offer', sender: myPeerInfo(), sdp: peer.pc.localDescription.toJSON() });
    if (!result.ok) console.warn('[room] renegociação com', peer.name, 'não foi confirmada em nenhuma tentativa');
  } catch (err) {
    console.error('[room] falha ao renegociar com', peer.name, err);
  } finally {
    peer.makingOffer = false;
  }
}

async function handleOffer(peer, sdp) {
  if (!peer.pc) return;

  // Colisão: os dois lados tentaram ofertar ao mesmo tempo (comum agora que
  // qualquer um pode renegociar a qualquer momento, não só na conexão
  // inicial). Quem é "educado" (ver isPolite) desfaz a própria oferta e
  // aceita a do outro lado; quem não é, ignora a oferta alheia e segue com
  // a própria — assim os dois lados sempre concordam em qual oferta vence.
  const offerCollision = peer.makingOffer || peer.pc.signalingState !== 'stable';
  if (offerCollision) {
    if (!isPolite(peer)) {
      console.log('[room] ignorando oferta de', peer.name, '— colisão, e não sou o lado que cede aqui');
      return;
    }
    console.log('[room] colisão de ofertas com', peer.name, '— desfazendo minha oferta local pra aceitar a dele');
    try {
      await peer.pc.setLocalDescription({ type: 'rollback' });
    } catch (err) {
      console.error('[room] falha ao desfazer oferta local pra', peer.name, err);
      return;
    }
  }

  try {
    await peer.pc.setRemoteDescription(sdp);
    await flushPendingIceCandidates(peer);
    const answer = await peer.pc.createAnswer();
    await peer.pc.setLocalDescription(answer);
    console.log('[room] enviando resposta pra', peer.name);
    const result = await sendToPeerReliable(peer, { t: 'answer', sender: myPeerInfo(), sdp: peer.pc.localDescription.toJSON() });
    if (!result.ok) console.warn('[room] resposta pra', peer.name, 'não foi confirmada em nenhuma tentativa');
  } catch (err) {
    console.error('[room] falha ao responder oferta de', peer.name, err);
  }
}

async function handleAnswer(peer, sdp) {
  if (!peer.pc) return;
  try {
    console.log('[room] recebi resposta de', peer.name, '— aplicando');
    await peer.pc.setRemoteDescription(sdp);
    await flushPendingIceCandidates(peer);
    syncRemoteStreamFromReceivers(peer);
  } catch (err) {
    console.error('[room] falha ao aplicar resposta de', peer.name, err);
  }
}

// Candidatos ICE do outro lado podem chegar (via nosso canal de
// sinalização, independente da SDP) ANTES da gente ter aplicado a
// oferta/resposta dele — `addIceCandidate` exige que `remoteDescription` já
// exista, então guarda numa fila e aplica assim que ela for setada (ver
// `flushPendingIceCandidates`, chamada logo depois de cada
// `setRemoteDescription` acima).
async function handleIceCandidate(peer, candidate) {
  if (!peer.pc) return;
  if (!peer.pc.remoteDescription) {
    peer.pendingIceCandidates = peer.pendingIceCandidates || [];
    peer.pendingIceCandidates.push(candidate);
    return;
  }
  try {
    await peer.pc.addIceCandidate(candidate);
  } catch (err) {
    console.warn('[room] falha ao aplicar candidato ICE de', peer.name, err);
  }
}

async function flushPendingIceCandidates(peer) {
  if (!peer.pendingIceCandidates || !peer.pendingIceCandidates.length) return;
  const candidates = peer.pendingIceCandidates;
  peer.pendingIceCandidates = [];
  for (const candidate of candidates) {
    try {
      await peer.pc.addIceCandidate(candidate);
    } catch (err) {
      console.warn('[room] falha ao aplicar candidato ICE (fila) de', peer.name, err);
    }
  }
}

function removePeer(peerId) {
  const peer = roomPeers.get(peerId);
  if (!peer) return;
  clearTimeout(peer.iceWatchdogTimer);
  if (peer.pc) peer.pc.close();
  roomPeers.delete(peerId);
  if (focusedPeerId === peerId) focusedPeerId = null;
  renderParticipants();
  renderGrid();
  renderFocusIfShowing();
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

async function acquireVideoTrackForScreen(sourceId) {
  const stream = await navigator.mediaDevices.getUserMedia({
    audio: false,
    video: {
      mandatory: {
        chromeMediaSource: 'desktop',
        chromeMediaSourceId: sourceId,
        maxWidth: 1920,
        maxHeight: 1080,
        maxFrameRate: 60,
      },
    },
  });
  return stream.getVideoTracks()[0];
}

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
    processOption.textContent = 'Processo específico (incluir ou excluir um app)';
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
}

// Ao entrar em "Processo específico" pela primeira vez, já deixa pronto pro
// caso de uso mais comum: excluir a chamada de voz do Discord do que é
// compartilhado. Procura um app cujo título termine em "discord"
// (case-insensitive, ex: janelas do Discord costumam terminar assim); se
// não achar nenhum, ainda assim liga o modo excluir e escolhe o primeiro
// app da lista (melhor um alvo qualquer em modo excluir, que a pessoa troca
// se quiser, do que deixar sem nada selecionado).
function autoPickDiscordExclude() {
  processAudioMode.value = 'exclude';
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

function getOrCreateSilentAudioTrack() {
  if (silentAudioTrack && silentAudioTrack.readyState === 'live') return silentAudioTrack;
  const ctx = new AudioContext();
  const destination = ctx.createMediaStreamDestination();
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
    if (!pid) throw new Error('Escolha um app na lista de "Processo específico".');
    const exclude = processAudioMode.value === 'exclude';
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
  await audioCtx.audioWorklet.addModule('pcm-injector-worklet.js');

  const workletNode = new AudioWorkletNode(audioCtx, 'pcm-injector', { outputChannelCount: [2] });
  const destination = audioCtx.createMediaStreamDestination();
  workletNode.connect(destination);

  const unsubscribeChunk = window.api.onProcessAudioChunk((samples, sampleRate, channels) => {
    workletNode.port.postMessage({ interleaved: samples, channels }, [samples.buffer]);
  });
  const unsubscribeError = window.api.onProcessAudioError((message) => {
    alert('Captura de áudio por processo falhou: ' + message);
  });

  const handle = await window.api.startProcessAudioCapture(pid, exclude);

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
  if (videoTrack) {
    // Teto de 8 Mbps por conexão — não é um valor fixo, o WebRTC ainda
    // estima a banda real e usa menos se precisar; só evita mandar mais do
    // que isso pra cada participante.
    const params = peer.videoSender.getParameters();
    params.encodings = [{ maxBitrate: 8_000_000, maxFramerate: 60 }];
    peer.videoSender.setParameters(params).catch(() => {});
  }

  await peer.audioSender.replaceTrack(audioTrack || getOrCreateSilentAudioTrack()).catch(() => {});
}

function applyLocalTracksToAllPeers() {
  roomPeers.forEach((peer) => applyLocalTracksToPeer(peer));
}

function broadcastSharingState(on) {
  roomPeers.forEach((peer) => {
    sendToPeerReliable(peer, { t: 'sharing', sender: myPeerInfo(), on }).catch(() => {});
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
  monitorSelect.disabled = monitorSelectIgnoredByAudioMode();
  updateMonitorThumbnail();
}

function hideSharePopover() {
  sharePopover.hidden = true;
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
  if (mySharing) switchMonitorInRoom();
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
        video: { width: { ideal: 1920, max: 1920 }, height: { ideal: 1080, max: 1080 }, frameRate: { ideal: 60, max: 60 } },
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

  videoTrack.contentHint = 'detail';
  localStream = new MediaStream([videoTrack, audioTrack]);
  videoTrack.addEventListener('ended', stopSharing);

  mySharing = true;
  window.api.setSharingActive(true);
  applyLocalTracksToAllPeers();
  roomPeers.forEach((peer) => negotiate(peer));
  broadcastSharingState(true);
  hideSharePopover();
  updateShareButtonUI();
  renderGrid();
  renderParticipants();
  renderFocusIfShowing();
}

async function switchMonitorInRoom() {
  if (!localStream || !mySharing) return;
  const sourceId = monitorSelect.value;
  if (!sourceId) return;

  let newTrack;
  try {
    newTrack = await acquireVideoTrackForScreen(sourceId);
  } catch (err) {
    alert('Não foi possível trocar de monitor: ' + err.message);
    return;
  }
  newTrack.contentHint = 'detail';

  const oldTrack = localStream.getVideoTracks()[0];
  if (oldTrack) {
    localStream.removeTrack(oldTrack);
    oldTrack.stop();
  }
  localStream.addTrack(newTrack);

  roomPeers.forEach((peer) => {
    if (!peer.videoSender) return;
    peer.videoSender.replaceTrack(newTrack).catch(() => {});
    const params = peer.videoSender.getParameters();
    params.encodings = [{ maxBitrate: 8_000_000, maxFramerate: 60 }];
    peer.videoSender.setParameters(params).catch(() => {});
  });

  localStream.getVideoTracks()[0].addEventListener('ended', stopSharing);
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
  window.api.setSharingActive(false);

  if (localStream) {
    localStream.getTracks().forEach((t) => t.stop());
    localStream = null;
  }
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

  if (wasSharing) broadcastSharingState(false);
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

  return { video, name, volumeSlider, volumeBtn, pinIcon };
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
  const { video, name, volumeSlider, volumeBtn, pinIcon } = ensureMediaTile(container, item.kind === 'self');
  const desiredStream = item.kind === 'self' ? localStream : item.peer.remoteStream || null;
  video.muted = item.kind === 'self';
  if (video.srcObject !== desiredStream) video.srcObject = desiredStream;
  name.textContent = item.name;
  pinIcon.innerHTML = pinMode === 'unpin' ? UNPIN_ICON_SVG : PIN_ICON_SVG;

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
}

// Deixar de renderizar um lado (grid ou foco) só esconde o container por
// CSS — os elementos <video> continuam vivos e tocando áudio por trás,
// sem que mais ninguém atualize o volume deles (porque aquele lado parou
// de renderizar). Sem mutar explicitamente quem vai ficar escondido, dava
// pra ouvir a mesma pessoa duas vezes (uma pelo card antigo, mudo pro
// controle de volume; outra pelo novo) até sair e voltar do foco de novo.
// O lado que vai ficar visível se corrige sozinho (`updateMediaTile` já
// desmuta quando não é o próprio preview), então só precisa mutar quem
// está saindo de cena.
function muteAllVideosIn(elements) {
  for (const el of elements) {
    const video = el.querySelector('video');
    if (video) video.muted = true;
  }
}

function enterFocus(id) {
  focusedPeerId = id;
  muteAllVideosIn(gridTileEls.values());
  renderFocus();
}

function exitFocus() {
  focusedPeerId = null;
  focusViewEl.hidden = true;
  muteAllVideosIn(focusStripTileEls.values());
  muteAllVideosIn([focusMainEl]);
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
      statusText = 'você';
    } else if (entry.connectionState === 'connected') {
      statusClass = 'status-connected';
      statusText = 'conectado';
    } else if (entry.connectionState === 'failed' || entry.connectionState === 'disconnected') {
      statusClass = 'status-failed';
    } else if (entry.connectionTimedOut) {
      // Ver o setTimeout em setupPeerConnection: o navegador às vezes nunca
      // marca a conexão como 'failed' sozinho, mesmo quando ela realmente
      // não vai dar certo (NAT estrito, sem TURN) — sem isso a pessoa ficava
      // "conectando" pra sempre sem nenhum aviso.
      statusClass = 'status-failed';
      statusText = 'sem conexão (rede)';
    }
    if (entry.sharing) statusText = 'compartilhando';
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

// Confere periodicamente (não só nos eventos) se cada conexão já tem vídeo
// chegando que `peer.remoteStream` ainda não reflete — rede de segurança
// pro caso do evento "track" não disparar (ver syncRemoteStreamFromReceivers).
// Não trava em `connectionState === 'connected'`: confirmado num teste real
// que esse aviso também pode nunca disparar pro lado que ofereceu a conexão,
// mesmo com ela genuinamente funcionando (dado real fluindo) — a própria
// função já é barata de chamar à toa (sai cedo se não achar receiver com
// track, ou se já estiver tudo certo).
setInterval(() => {
  roomPeers.forEach((peer) => {
    if (peer.pc) syncRemoteStreamFromReceivers(peer);
  });
}, 3000);

// Diagnóstico de bitrate/fps por conexão (visível só no console/DevTools,
// que fica desligado nos executáveis empacotados) — mesma finalidade do
// diagnóstico que já existia no fluxo 1:1, generalizada pra cada peer da
// malha em vez de cada espectador.
setInterval(async () => {
  if (!mySharing) return;
  for (const peer of roomPeers.values()) {
    if (!peer.videoSender || !peer.pc || peer.pc.connectionState !== 'connected') continue;
    const stats = await peer.pc.getStats();
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
    const stats = await peer.pc.getStats();
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
