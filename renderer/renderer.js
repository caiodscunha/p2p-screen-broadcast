const ICE_SERVERS = [{ urls: 'stun:stun.l.google.com:19302' }];

// ---------- utilidades ----------

// O código de oferta/resposta carrega seus candidatos ICE (IP público, às
// vezes IP local) em texto plano — base64 só torna isso seguro de colar, não
// esconde nada. Com uma senha combinada por outro canal (voz, presencial),
// o payload vira AES-GCM de verdade; sem senha, cai no formato antigo
// (prefixo "P1."), só codificado. "E1." identifica um código criptografado
// para que o lado que decodifica saiba se precisa pedir a senha.
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

  // formato legado (sem prefixo), gerado por versões anteriores do app
  return JSON.parse(decodeURIComponent(escape(atob(trimmed))));
}

// Espera o ICE gathering terminar, mas com um teto de tempo: se o STUN
// demorar (rede lenta, firewall bloqueando UDP, VPN etc.) seguimos com os
// candidatos já coletados até ali (o candidato "host" costuma estar pronto
// quase instantaneamente e já basta para mesma rede/mesma máquina).
// Como a troca de SDP é manual (sem trickle ICE), qualquer candidato que não
// chegue dentro desse prazo fica de fora do código gerado — por isso o teto
// é generoso: 2s era curto demais e podia cortar o candidato STUN (srflx)
// antes de ele voltar, deixando só candidatos "host" (inúteis entre redes
// diferentes) no código trocado.
function waitIceGatheringComplete(pc, timeoutMs = 8000) {
  if (pc.iceGatheringState === 'complete') return Promise.resolve();
  return new Promise((resolve) => {
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      pc.removeEventListener('icegatheringstatechange', check);
      resolve();
    };
    function check() {
      if (pc.iceGatheringState === 'complete') finish();
    }
    pc.addEventListener('icegatheringstatechange', check);
    setTimeout(finish, timeoutMs);
  });
}

// ---------- abas ----------

const tabTransmitir = document.getElementById('tab-transmitir');
const tabAssistir = document.getElementById('tab-assistir');
const viewTransmitir = document.getElementById('view-transmitir');
const viewAssistir = document.getElementById('view-assistir');

tabTransmitir.addEventListener('click', () => switchTab('transmitir'));
tabAssistir.addEventListener('click', () => switchTab('assistir'));

const audioSourceSelect = document.getElementById('audio-source-select');
const btnRefreshAudioSources = document.getElementById('btn-refresh-audio-sources');

// Valor especial reservado para "usar o loopback automático do sistema" (todo
// o áudio que está tocando). Qualquer outro valor não-vazio é um deviceId
// real de um dispositivo de entrada específico.
const LOOPBACK_VALUE = '__loopback__';
// Fonte de áudio "captura por processo" (só Windows) — incluir ou excluir um
// app específico via WASAPI Process Loopback, em vez de um dispositivo
// inteiro. Ver native/audio-loopback.
const PROCESS_VALUE = '__process__';
let supportsLoopback = false;
let supportsProcessAudio = false;

window.api.supportsSystemAudio().then((supported) => {
  supportsLoopback = supported;
  if (!supported) document.getElementById('audio-hint').hidden = false;
  refreshAudioSources();
});

window.api.supportsProcessAudio().then((supported) => {
  supportsProcessAudio = supported;
  refreshAudioSources();
});

// Além do loopback automático (quando suportado), deixa escolher um
// dispositivo de entrada específico como fonte de áudio — útil para excluir
// algo do que é compartilhado (ex: a chamada de voz do Discord), desde que
// esse app/chamada esteja tocando num dispositivo de saída separado (ou um
// cabo de áudio virtual) que não seja o padrão do sistema. No Linux, isso
// também é o que expõe o "monitor" do PulseAudio/PipeWire como entrada. Os
// labels dos dispositivos só ficam visíveis depois de uma permissão de áudio
// concedida, por isso o getUserMedia "descartável" abaixo.
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

  // Na primeira chamada, o valor do <select> é só o placeholder estático do
  // HTML, não uma escolha real do usuário — ignora ele pra não confundir
  // "ainda não escolheu nada" com "escolheu Nenhum áudio" e cair sempre em
  // silêncio por padrão mesmo quando o loopback está disponível.
  const previousValue = audioSourceInitialized ? audioSourceSelect.value : undefined;
  audioSourceInitialized = true;
  audioSourceSelect.innerHTML = '';

  if (supportsLoopback) {
    const loopbackOption = document.createElement('option');
    loopbackOption.value = LOOPBACK_VALUE;
    loopbackOption.textContent = 'Áudio do sistema (tudo, padrão)';
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
}

btnRefreshAudioSources.addEventListener('click', refreshAudioSources);

const processAudioBlock = document.getElementById('process-audio-block');
const processAudioSelect = document.getElementById('process-audio-select');
const processAudioMode = document.getElementById('process-audio-mode');
const btnRefreshAudioProcesses = document.getElementById('btn-refresh-audio-processes');

audioSourceSelect.addEventListener('change', () => {
  const isProcessMode = audioSourceSelect.value === PROCESS_VALUE;
  processAudioBlock.hidden = !isProcessMode;
  if (isProcessMode) refreshAudioProcesses();
  switchAudioSource();
});

// Se já está transmitindo e o usuário troca de app/modo dentro de "Processo
// específico", aplica a troca imediatamente, sem esperar um novo clique.
processAudioMode.addEventListener('change', () => switchAudioSource());
processAudioSelect.addEventListener('change', () => switchAudioSource());

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

function switchTab(which) {
  const isTransmitir = which === 'transmitir';
  tabTransmitir.classList.toggle('active', isTransmitir);
  tabAssistir.classList.toggle('active', !isTransmitir);
  viewTransmitir.classList.toggle('active', isTransmitir);
  viewAssistir.classList.toggle('active', !isTransmitir);
}

// ===================================================================
// TRANSMITIR
// ===================================================================

let localStream = null;
let viewers = []; // { id, pc }
let viewerCounter = 0;

const preview = document.getElementById('preview');
const btnStartCapture = document.getElementById('btn-start-capture');
const btnPauseCapture = document.getElementById('btn-pause-capture');
const btnStopCapture = document.getElementById('btn-stop-capture');
const btnNewViewer = document.getElementById('btn-new-viewer');
const offerBlock = document.getElementById('offer-block');
const offerCodeEl = document.getElementById('offer-code');
const copyOfferBtn = document.getElementById('copy-offer');
const answerInputBlock = document.getElementById('answer-input-block');
const answerCodeInput = document.getElementById('answer-code-input');
const pasteAnswerBtn = document.getElementById('paste-answer');
const connectAnswerBtn = document.getElementById('connect-answer');
const viewerListEl = document.getElementById('viewer-list');
const broadcastPassphraseInput = document.getElementById('broadcast-passphrase');
const liveBadge = document.getElementById('live-badge');
const liveBadgeText = document.getElementById('live-badge-text');
const monitorSelect = document.getElementById('monitor-select');
const btnRefreshMonitors = document.getElementById('btn-refresh-monitors');
const monitorThumbnail = document.getElementById('monitor-thumbnail');

// Lista as telas via desktopCapturer (com miniatura) em vez de depender do
// seletor nativo do SO — assim dá pra trocar de monitor com a transmissão
// já em andamento (replaceTrack, sem reconectar ninguém), e funciona igual
// em Windows/macOS/Linux.
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
refreshMonitors();

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

// Troca de monitor com a transmissão já rolando, sem recapturar áudio nem
// reconectar espectadores — mesma técnica do switchAudioSource, mas pro
// sender de vídeo. Não usada pela primeira captura (que ainda passa pelo
// seletor nativo do SO quando disponível); só entra em ação numa troca
// depois de já estar transmitindo.
async function switchMonitor() {
  updateMonitorThumbnail();
  if (!localStream) return;

  const sourceId = monitorSelect.value;
  if (!sourceId) return;

  let newTrack;
  try {
    newTrack = await acquireVideoTrackForScreen(sourceId);
  } catch (err) {
    alert('Não foi possível trocar de monitor: ' + err.message);
    return;
  }

  // Mantém o mesmo teto de bitrate/framerate usado ao conectar cada
  // espectador (ver btnNewViewer), já que replaceTrack não herda isso.
  newTrack.contentHint = 'detail';

  const oldTrack = localStream.getVideoTracks()[0];
  if (oldTrack) {
    localStream.removeTrack(oldTrack);
    oldTrack.stop();
  }
  localStream.addTrack(newTrack);

  viewers.forEach((v) => {
    if (!v.videoSender) return;
    v.videoSender.replaceTrack(newTrack).catch(() => {});
    const params = v.videoSender.getParameters();
    params.encodings = [{ maxBitrate: 8_000_000, maxFramerate: 60 }];
    v.videoSender.setParameters(params).catch(() => {});
  });

  localStream.getVideoTracks()[0].addEventListener('ended', stopCapture);
}

monitorSelect.addEventListener('change', () => switchMonitor());

// Estado da captura de áudio por processo em andamento (null quando não
// está em uso). Precisa ser desmontado em stopCapture() além de qualquer
// track normal, já que envolve um AudioContext + sessão nativa próprios.
let processAudioState = null;

// Guardadas à parte pra trocar de fonte de áudio em pleno andamento (ver
// switchAudioSource) sem precisar recapturar nada:
// - loopbackAudioTrack: só existe se "Áudio do sistema" foi a escolha ao dar
//   play — vem embutida na mesma chamada de getDisplayMedia que pegou o
//   vídeo, então não tem como buscar uma nova sem reabrir o seletor de tela.
//   Por isso ela é preservada (nunca stopada) enquanto durar a transmissão,
//   pra poder ser reaproveitada se o usuário voltar pra essa opção depois.
// - silentAudioTrack: track de áudio silenciosa (Web Audio), criada sob
//   demanda, usada quando a escolha é "Nenhum áudio" — garante que sempre
//   exista uma track de áudio no localStream (mesmo que muda) desde o
//   início, então trocar de fonte depois sempre pode usar
//   RTCRtpSender.replaceTrack() em vez de precisar renegociar a conexão.
let loopbackAudioTrack = null;
let silentAudioTrack = null;

function getOrCreateSilentAudioTrack() {
  if (silentAudioTrack && silentAudioTrack.readyState === 'live') return silentAudioTrack;
  const ctx = new AudioContext();
  const destination = ctx.createMediaStreamDestination();
  silentAudioTrack = destination.stream.getAudioTracks()[0];
  return silentAudioTrack;
}

// Resolve a track de áudio correspondente ao que está selecionado agora na
// UI. Usada tanto ao iniciar quanto ao trocar de fonte em andamento.
async function acquireAudioTrack() {
  const selected = audioSourceSelect.value;

  if (selected === LOOPBACK_VALUE) {
    if (!loopbackAudioTrack) {
      throw new Error(
        '"Áudio do sistema" só pode ser escolhido ao iniciar a captura (exigiria reabrir o seletor de tela).'
      );
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

// Troca a fonte de áudio com a transmissão já rolando: pega a nova track e
// substitui via RTCRtpSender.replaceTrack() em cada espectador já conectado
// — isso funciona sem precisar renegociar a conexão (nem gerar um novo
// código), já que todo espectador já tem um sender de áudio desde a
// primeira oferta (mesmo que inicialmente silencioso).
async function switchAudioSource() {
  if (!localStream) return; // nada rodando ainda; o botão "Iniciar" cuida disso

  const previousProcessState = processAudioState;
  processAudioState = null; // é recriado abaixo se a nova fonte for "processo"

  let newTrack;
  try {
    newTrack = await acquireAudioTrack();
  } catch (err) {
    alert('Não foi possível trocar a fonte de áudio: ' + err.message);
    processAudioState = previousProcessState; // mantém a sessão antiga rodando
    return;
  }

  const previousTrack = localStream.getAudioTracks()[0];
  if (previousTrack && previousTrack !== newTrack) {
    localStream.removeTrack(previousTrack);
    // loopback e silêncio ficam guardados pra reaproveitar depois; qualquer
    // outra track (dispositivo ou processo) pode ser parada de vez.
    if (previousTrack !== loopbackAudioTrack && previousTrack !== silentAudioTrack) {
      previousTrack.stop();
    }
  }
  if (!localStream.getAudioTracks().includes(newTrack)) {
    localStream.addTrack(newTrack);
  }

  viewers.forEach((v) => {
    if (v.audioSender) v.audioSender.replaceTrack(newTrack).catch(() => {});
  });

  if (previousProcessState) previousProcessState.cleanup();
}

async function startProcessAudioTrack(pid, exclude) {
  const audioCtx = new AudioContext({ sampleRate: 48000 });
  await audioCtx.audioWorklet.addModule('pcm-injector-worklet.js');

  const workletNode = new AudioWorkletNode(audioCtx, 'pcm-injector', {
    outputChannelCount: [2],
  });
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

btnStartCapture.addEventListener('click', async () => {
  const selectedAudio = audioSourceSelect.value;
  const useLoopback = selectedAudio === LOOPBACK_VALUE;

  try {
    localStream = await navigator.mediaDevices.getDisplayMedia({
      video: {
        width: { ideal: 1920, max: 1920 },
        height: { ideal: 1080, max: 1080 },
        frameRate: { ideal: 60, max: 60 },
      },
      // Só pede o loopback quando é isso que o usuário escolheu; caso
      // contrário o handler do main process (capture.js) nem tenta anexar
      // áudio automático, evitando misturar loopback com outra fonte de
      // áudio escolhida abaixo.
      audio: useLoopback,
    });

    if (useLoopback) {
      // Guardada pra poder ser reaproveitada se o usuário trocar de fonte e
      // depois voltar pra "Áudio do sistema" (ver switchAudioSource).
      loopbackAudioTrack = localStream.getAudioTracks()[0] || null;
      // Se o usuário desmarcou "compartilhar áudio do sistema" no seletor
      // nativo, nenhuma track de áudio volta — cai pra silenciosa, mantendo
      // a garantia de que sempre existe uma track de áudio no localStream.
      if (!loopbackAudioTrack) {
        localStream.addTrack(getOrCreateSilentAudioTrack());
      }
    } else {
      // Sempre garante uma track de áudio desde o início (real ou
      // silenciosa) — assim todo espectador já nasce com um sender de
      // áudio, e trocar de fonte depois nunca precisa renegociar.
      const track = await acquireAudioTrack();
      localStream.addTrack(track);
    }
  } catch (err) {
    alert('Não foi possível capturar a tela: ' + err.message);
    return;
  }

  preview.srcObject = localStream;
  btnStartCapture.disabled = true;
  btnPauseCapture.disabled = false;
  btnStopCapture.disabled = false;
  btnNewViewer.disabled = false;
  monitorSelect.disabled = false;
  liveBadge.hidden = false;
  setPaused(false);

  // se o usuário parar o compartilhamento pelos controles do próprio SO
  localStream.getVideoTracks()[0].addEventListener('ended', stopCapture);
});

let isPaused = false;

// Pausar só desativa a track de vídeo (track.enabled = false), sem parar
// nenhuma RTCPeerConnection nem renegociar nada. Como todos os espectadores
// recebem essa mesma instância de track (via pc.addTrack(track, ...) em
// btnNewViewer), desativá-la aqui já congela a imagem para todo mundo ao
// mesmo tempo, sem cair a conexão de ninguém. O áudio do sistema continua
// tocando normalmente durante a pausa.
btnPauseCapture.addEventListener('click', () => {
  if (!localStream) return;
  setPaused(!isPaused);
});

function setPaused(paused) {
  isPaused = paused;
  if (localStream) {
    localStream.getVideoTracks().forEach((track) => {
      track.enabled = !paused;
    });
  }
  btnPauseCapture.textContent = paused ? 'Retomar compartilhamento' : 'Pausar compartilhamento';
  liveBadge.classList.toggle('is-paused', paused);
  liveBadgeText.textContent = paused ? 'PAUSADO' : 'AO VIVO';
}

btnStopCapture.addEventListener('click', stopCapture);

function stopCapture() {
  if (localStream) {
    localStream.getTracks().forEach((t) => t.stop());
    localStream = null;
  }
  if (processAudioState) {
    processAudioState.cleanup();
    processAudioState = null;
  }
  // loopbackAudioTrack/silentAudioTrack podem ter sido trocadas pra fora do
  // localStream (mas mantidas vivas de propósito pra reaproveitar depois —
  // ver switchAudioSource); aqui a transmissão acabou de vez, então param.
  if (loopbackAudioTrack) {
    loopbackAudioTrack.stop();
    loopbackAudioTrack = null;
  }
  if (silentAudioTrack) {
    silentAudioTrack.stop();
    silentAudioTrack = null;
  }
  preview.srcObject = null;
  viewers.forEach((v) => v.pc.close());
  viewers = [];
  renderViewerList();
  btnStartCapture.disabled = false;
  btnPauseCapture.disabled = true;
  btnStopCapture.disabled = true;
  btnNewViewer.disabled = true;
  monitorSelect.disabled = true;
  offerBlock.hidden = true;
  answerInputBlock.hidden = true;
  liveBadge.hidden = true;
  setPaused(false);
}

let pendingViewerId = null;

btnNewViewer.addEventListener('click', async () => {
  if (!localStream) return;

  viewerCounter += 1;
  const id = viewerCounter;
  const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
  const viewer = { id, pc, status: 'connecting', name: null, videoSender: null, audioSender: null };

  localStream.getTracks().forEach((track) => {
    const sender = pc.addTrack(track, localStream);
    if (track.kind === 'video') {
      viewer.videoSender = sender;
      // Teto de 8 Mbps por espectador. É um máximo, não um valor fixo: o
      // WebRTC ainda estima a banda real disponível e usa menos se precisar
      // — isso só evita que ele tente mandar mais do que 8 Mbps para cada
      // pessoa conectada.
      const params = sender.getParameters();
      params.encodings = [{ maxBitrate: 8_000_000, maxFramerate: 60 }];
      sender.setParameters(params).catch(() => {});
    } else if (track.kind === 'audio') {
      // Guardado pra permitir trocar a fonte de áudio em pleno andamento
      // (ver switchAudioSource) via replaceTrack(), sem renegociar.
      viewer.audioSender = sender;
    }
  });

  viewers.push(viewer);
  renderViewerList();

  pc.addEventListener('connectionstatechange', () => {
    viewer.status = pc.connectionState;
    renderViewerList();
  });

  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  await waitIceGatheringComplete(pc);

  pendingViewerId = id;
  offerCodeEl.value = await encode(pc.localDescription.toJSON(), broadcastPassphraseInput.value.trim());
  offerBlock.hidden = false;
  answerInputBlock.hidden = false;
  answerCodeInput.value = '';
});

copyOfferBtn.addEventListener('click', () => {
  window.api.copyToClipboard(offerCodeEl.value);
});

pasteAnswerBtn.addEventListener('click', () => {
  answerCodeInput.value = window.api.readClipboard();
});

connectAnswerBtn.addEventListener('click', async () => {
  const viewer = viewers.find((v) => v.id === pendingViewerId);
  if (!viewer) {
    alert('Gere um código de espectador primeiro.');
    return;
  }
  try {
    const decoded = await decode(answerCodeInput.value, broadcastPassphraseInput.value.trim());
    // O nome do espectador vem embutido no código de resposta (não há canal
    // de sinalização contínuo para mandar isso separado). Formato antigo
    // (só a descrição, sem "sdp"/"name") continua funcionando como fallback.
    const answer = decoded && decoded.sdp ? decoded.sdp : decoded;
    const name = decoded && decoded.name ? String(decoded.name).trim().slice(0, 60) : '';
    if (name) viewer.name = name;
    await viewer.pc.setRemoteDescription(answer);
  } catch (err) {
    alert('Código de resposta inválido: ' + err.message);
    return;
  }
  offerBlock.hidden = true;
  answerInputBlock.hidden = true;
  pendingViewerId = null;
  renderViewerList();
});

function renderViewerList() {
  viewerListEl.innerHTML = '';
  if (viewers.length === 0) {
    const li = document.createElement('li');
    li.textContent = 'Nenhum espectador ainda.';
    viewerListEl.appendChild(li);
    return;
  }

  const statusLabel = {
    new: 'aguardando',
    connecting: 'conectando',
    connected: 'conectado',
    disconnected: 'desconectado',
    failed: 'falhou',
    closed: 'fechado',
  };

  viewers.forEach((v) => {
    const li = document.createElement('li');
    const displayName = v.name || `Espectador #${v.id}`;
    const statusClass =
      v.status === 'connected'
        ? 'status-connected'
        : v.status === 'failed' || v.status === 'disconnected'
        ? 'status-failed'
        : 'status-connecting';

    const avatar = document.createElement('span');
    avatar.className = 'viewer-avatar';
    avatar.textContent = displayName.trim().charAt(0).toUpperCase() || '?';

    const name = document.createElement('span');
    name.className = 'viewer-name';
    name.textContent = displayName;

    const pill = document.createElement('span');
    pill.className = 'status-pill ' + statusClass;
    pill.textContent = statusLabel[v.status] || v.status;

    const meta = document.createElement('span');
    meta.className = 'viewer-meta';
    meta.appendChild(name);
    meta.appendChild(pill);

    const left = document.createElement('span');
    left.className = 'viewer-row-left';
    left.appendChild(avatar);
    left.appendChild(meta);

    const removeBtn = document.createElement('button');
    removeBtn.className = 'btn btn-danger-ghost';
    removeBtn.textContent = 'Remover';
    removeBtn.addEventListener('click', () => {
      v.pc.close();
      viewers = viewers.filter((x) => x.id !== v.id);
      renderViewerList();
    });

    li.appendChild(left);
    li.appendChild(removeBtn);
    viewerListEl.appendChild(li);
  });
}

renderViewerList();

// ===================================================================
// ASSISTIR
// ===================================================================

let viewerPc = null;

const offerCodeInput = document.getElementById('offer-code-input');
const pasteOfferBtn = document.getElementById('paste-offer');
const btnGenerateAnswer = document.getElementById('btn-generate-answer');
const answerBlock = document.getElementById('answer-block');
const answerCodeEl = document.getElementById('answer-code');
const copyAnswerBtn = document.getElementById('copy-answer');
const watchStatus = document.getElementById('watch-status');
const remoteVideo = document.getElementById('remote-video');
const btnDisconnect = document.getElementById('btn-disconnect');
const watchPassphraseInput = document.getElementById('watch-passphrase');
const viewerNameInput = document.getElementById('viewer-name-input');

pasteOfferBtn.addEventListener('click', () => {
  offerCodeInput.value = window.api.readClipboard();
});

btnGenerateAnswer.addEventListener('click', async () => {
  let offer;
  try {
    offer = await decode(offerCodeInput.value, watchPassphraseInput.value.trim());
  } catch (err) {
    alert('Código do transmissor inválido: ' + err.message);
    return;
  }

  if (viewerPc) {
    viewerPc.close();
  }

  viewerPc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
  btnDisconnect.disabled = false;

  viewerPc.addEventListener('track', (event) => {
    remoteVideo.srcObject = event.streams[0];
  });

  viewerPc.addEventListener('connectionstatechange', () => {
    watchStatus.textContent = 'Status: ' + viewerPc.connectionState;
  });

  await viewerPc.setRemoteDescription(offer);
  const answer = await viewerPc.createAnswer();
  await viewerPc.setLocalDescription(answer);
  await waitIceGatheringComplete(viewerPc);

  const payload = {
    sdp: viewerPc.localDescription.toJSON(),
    name: viewerNameInput.value.trim().slice(0, 60),
  };
  answerCodeEl.value = await encode(payload, watchPassphraseInput.value.trim());
  answerBlock.hidden = false;
  watchStatus.textContent = 'Envie o código de resposta ao transmissor...';
});

copyAnswerBtn.addEventListener('click', () => {
  window.api.copyToClipboard(answerCodeEl.value);
});

btnDisconnect.addEventListener('click', () => {
  if (viewerPc) {
    viewerPc.close();
    viewerPc = null;
  }
  remoteVideo.srcObject = null;
  btnDisconnect.disabled = true;
  answerBlock.hidden = true;
  watchStatus.textContent = 'Desconectado.';
});
