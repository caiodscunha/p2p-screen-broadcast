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
const linuxAudioBlock = document.getElementById('linux-audio-block');
const btnRefreshAudioSources = document.getElementById('btn-refresh-audio-sources');

window.api.supportsSystemAudio().then((supported) => {
  if (supported) return;
  document.getElementById('audio-hint').hidden = false;
  linuxAudioBlock.hidden = false;
  refreshAudioSources();
});

// No Linux não existe loopback de áudio nativo: o usuário precisa expor o
// "monitor" da sua placa de som (PulseAudio/PipeWire) como um dispositivo de
// entrada e escolhê-lo aqui. Os labels dos dispositivos só ficam visíveis
// depois de uma permissão de áudio concedida, por isso o getUserMedia
// "descartável" abaixo.
async function refreshAudioSources() {
  try {
    const tmp = await navigator.mediaDevices.getUserMedia({ audio: true });
    tmp.getTracks().forEach((t) => t.stop());
  } catch (err) {
    // segue sem permissão; a lista pode vir sem labels
  }

  const devices = await navigator.mediaDevices.enumerateDevices();
  const audioInputs = devices.filter((d) => d.kind === 'audioinput');

  const previousValue = audioSourceSelect.value;
  audioSourceSelect.innerHTML = '';

  const noneOption = document.createElement('option');
  noneOption.value = '';
  noneOption.textContent = 'Sem áudio do sistema';
  audioSourceSelect.appendChild(noneOption);

  audioInputs.forEach((d) => {
    const opt = document.createElement('option');
    opt.value = d.deviceId;
    opt.textContent = d.label || `Dispositivo de áudio (${d.deviceId.slice(0, 8)})`;
    audioSourceSelect.appendChild(opt);
  });

  const stillExists = audioInputs.some((d) => d.deviceId === previousValue);
  if (stillExists) {
    audioSourceSelect.value = previousValue;
  } else {
    const monitor = audioInputs.find((d) => /monitor/i.test(d.label));
    if (monitor) audioSourceSelect.value = monitor.deviceId;
  }
}

btnRefreshAudioSources.addEventListener('click', refreshAudioSources);

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

btnStartCapture.addEventListener('click', async () => {
  try {
    localStream = await navigator.mediaDevices.getDisplayMedia({
      video: {
        width: { ideal: 1920, max: 1920 },
        height: { ideal: 1080, max: 1080 },
        frameRate: { ideal: 60, max: 60 },
      },
      audio: true,
    });

    // Fallback para Linux: sem loopback nativo, o áudio do sistema (se
    // escolhido) vem de um dispositivo de entrada separado (o "monitor" do
    // PulseAudio/PipeWire) e é anexado manualmente ao stream capturado.
    const linuxAudioDeviceId = audioSourceSelect.value;
    if (linuxAudioDeviceId) {
      const audioStream = await navigator.mediaDevices.getUserMedia({
        audio: { deviceId: { exact: linuxAudioDeviceId } },
      });
      audioStream.getAudioTracks().forEach((track) => localStream.addTrack(track));
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
  setPaused(false);
  window.api.notifyCaptureStarted();

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
}

btnStopCapture.addEventListener('click', stopCapture);

function stopCapture() {
  if (localStream) {
    localStream.getTracks().forEach((t) => t.stop());
    localStream = null;
  }
  preview.srcObject = null;
  viewers.forEach((v) => v.pc.close());
  viewers = [];
  renderViewerList();
  btnStartCapture.disabled = false;
  btnPauseCapture.disabled = true;
  btnStopCapture.disabled = true;
  btnNewViewer.disabled = true;
  offerBlock.hidden = true;
  answerInputBlock.hidden = true;
  setPaused(false);
}

let pendingViewerId = null;

btnNewViewer.addEventListener('click', async () => {
  if (!localStream) return;

  viewerCounter += 1;
  const id = viewerCounter;
  const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });

  localStream.getTracks().forEach((track) => {
    const sender = pc.addTrack(track, localStream);
    if (track.kind === 'video') {
      // Teto de 8 Mbps por espectador. É um máximo, não um valor fixo: o
      // WebRTC ainda estima a banda real disponível e usa menos se precisar
      // — isso só evita que ele tente mandar mais do que 8 Mbps para cada
      // pessoa conectada.
      const params = sender.getParameters();
      params.encodings = [{ maxBitrate: 8_000_000, maxFramerate: 60 }];
      sender.setParameters(params).catch(() => {});
    }
  });

  const viewer = { id, pc, status: 'connecting' };
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
    const answer = await decode(answerCodeInput.value, broadcastPassphraseInput.value.trim());
    await viewer.pc.setRemoteDescription(answer);
  } catch (err) {
    alert('Código de resposta inválido: ' + err.message);
    return;
  }
  offerBlock.hidden = true;
  answerInputBlock.hidden = true;
  pendingViewerId = null;
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
    const dot = document.createElement('span');
    dot.className =
      'status-dot ' +
      (v.status === 'connected'
        ? 'status-connected'
        : v.status === 'failed' || v.status === 'disconnected'
        ? 'status-failed'
        : 'status-connecting');
    const label = document.createElement('span');
    label.textContent = `Espectador #${v.id} — ${statusLabel[v.status] || v.status}`;

    const left = document.createElement('span');
    left.appendChild(dot);
    left.appendChild(label);

    const removeBtn = document.createElement('button');
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

// Diagnóstico: loga a cada 3s as estatísticas de envio de vídeo pra cada
// espectador. Serve pra descobrir, quando a transmissão "trava", se quem
// para de produzir/enviar frames é o lado de quem transmite (aqui) ou se os
// frames continuam sendo enviados normalmente e o travamento é só na
// recepção/decodificação de quem assiste. Acompanhe pelo DevTools
// (Ctrl+Shift+I) durante o teste de minimizar/cobrir a janela.
setInterval(async () => {
  for (const v of viewers) {
    if (v.pc.connectionState !== 'connected') continue;
    const stats = await v.pc.getStats();
    stats.forEach((report) => {
      if (report.type === 'outbound-rtp' && report.kind === 'video') {
        console.log(
          `[transmitir] espectador #${v.id} vídeo — fps=${report.framesPerSecond ?? '?'} ` +
            `framesSent=${report.framesSent} bytesSent=${report.bytesSent} ` +
            `qualityLimitation=${report.qualityLimitationReason ?? '?'}`
        );
      }
    });
  }
}, 3000);

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

  answerCodeEl.value = await encode(viewerPc.localDescription.toJSON(), watchPassphraseInput.value.trim());
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

// Contraparte do log de diagnóstico do lado de quem transmite: se
// framesDecoded/bytesReceived continuam subindo normalmente aqui enquanto o
// vídeo aparenta estar congelado na tela, o problema é na decodificação/
// renderização desta janela, não no envio. Se pararem de subir junto com o
// congelamento, o problema é do lado de quem transmite (ele parou de mandar
// frames). Acompanhe pelo DevTools (Ctrl+Shift+I).
setInterval(async () => {
  if (!viewerPc || viewerPc.connectionState !== 'connected') return;
  const stats = await viewerPc.getStats();
  stats.forEach((report) => {
    if (report.type === 'inbound-rtp' && report.kind === 'video') {
      console.log(
        `[assistir] vídeo — fps=${report.framesPerSecond ?? '?'} ` +
          `framesDecoded=${report.framesDecoded} bytesReceived=${report.bytesReceived} ` +
          `jitterBufferDelay=${report.jitterBufferDelay ?? '?'}`
      );
    }
  });
}, 3000);
