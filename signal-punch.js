// Handshake automático de resposta, sem servidor próprio, em duas camadas:
//
// 1) UDP direto (STUN + IP local + UPnP): o código de oferta carrega embutido
//    (dentro do mesmo payload criptografado, se houver senha) um "ponto de
//    encontro" — id de sessão + candidatos IP:porta. Quem cola o código
//    tenta mandar a resposta direto pra esses endereços por UDP. Funciona
//    quando o roteador/NAT permite um pacote de entrada não solicitado — mas
//    alguns roteadores/operadoras não permitem isso de jeito nenhum, mesmo
//    com regra de firewall liberada no PC (visto na prática: rede "pública"
//    no Windows já resolvida, e mesmo assim UDP direto não chega entre dois
//    PCs de verdade — provavelmente o próprio modem/operadora barrando).
//
// 2) Retransmissor HTTPS (ntfy.sh) como reforço, tentado em paralelo: os dois
//    lados só fazem requisições HTTPS de SAÍDA (publicar/consultar mensagens
//    num "tópico" público e efêmero identificado pelo id de sessão) — nenhum
//    dos dois precisa aceitar conexão nenhuma, então funciona atrás de
//    qualquer NAT/firewall que bloqueie a via 1. É uma exceção real ao "sem
//    servidor" deste projeto, do mesmo jeito que o STUN do Google já é: um
//    serviço público, gratuito, neutro e de código aberto, usado só pra essa
//    sinalização — o vídeo/áudio continua 100% direto entre os dois lados,
//    nunca passa por aqui. Só é tentado se o código couber no limite de
//    tamanho de mensagem do serviço.
//
// Se nenhuma das duas vias funcionar, cai pro fluxo manual de colar o código
// de resposta — mesmo caso em que a própria conexão WebRTC (que só usa STUN,
// sem TURN) também poderia falhar.
const dgram = require('dgram');
const crypto = require('crypto');
const os = require('os');

const NTFY_BASE = 'https://ntfy.sh';
// O código de resposta (com vários candidatos ICE, senha, etc.) costuma
// passar de 8KB — bem mais do que qualquer serviço de mensagens aguenta
// numa mensagem só. Em vez de adivinhar um limite e desistir se não couber,
// divide em pedaços pequenos (bem abaixo de qualquer limite razoável) e
// remonta do outro lado — funciona não importa o tamanho real do limite.
const NTFY_CHUNK_SIZE = 2000;

// Vai juntando os pedaços de uma resposta dividida (ver sendAnswerViaHttpRelay)
// conforme chegam, em qualquer ordem — cada instância corresponde a uma
// única sessão/resposta. Retorna o código completo assim que tiver todos os
// pedaços, ou null enquanto ainda faltar algum. Mensagens no formato antigo
// (sem chunking, "answer" com "code" direto) continuam funcionando.
function createChunkAssembler() {
  let parts = null;
  return (data) => {
    if (data.t === 'answer' && typeof data.code === 'string') return data.code;
    if (data.t !== 'answer-chunk' || typeof data.c !== 'string' || !Number.isInteger(data.i) || !Number.isInteger(data.n)) {
      return null;
    }
    if (!parts) parts = new Array(data.n).fill(null);
    parts[data.i] = data.c;
    return parts.every((p) => p !== null) ? parts.join('') : null;
  };
}

async function postNtfyMessage(topic, obj) {
  try {
    const res = await fetch(`${NTFY_BASE}/${encodeURIComponent(topic)}`, {
      method: 'POST',
      body: JSON.stringify(obj),
    });
    if (!res.ok) console.error('[signal-punch] ntfy: publicar falhou, status', res.status);
    return res.ok;
  } catch (err) {
    console.error('[signal-punch] ntfy: publicar deu erro de rede:', err.message);
    return false;
  }
}

// Mantém UMA conexão HTTP aberta (streaming, sem "poll=1") num tópico da
// ntfy, chamando onMessage pra cada mensagem publicada nele, até `signal`
// abortar. Existe por causa de um bug real: a versão anterior consultava em
// loop (poll) a cada 1,5s, e isso estourou o limite de taxa da instância
// pública (HTTP 429) sempre que o ponto de encontro ficava aberto por mais
// que uns poucos segundos — depois de estourado, TODA consulta seguinte
// falhava, inclusive a que acharia a resposta de verdade. Uma conexão só,
// mantida aberta, evita bater nesse limite.
// Abre a conexão em streaming e devolve a Response assim que o cabeçalho
// chega (conexão de fato estabelecida) — separado de ler o corpo (ver
// readNtfyStream) porque quem chama precisa SABER que já está conectado
// antes de mandar quem quer que seja publicar algo. Testado na prática:
// "since=all" não resgata mensagens publicadas antes desta conexão abrir
// (só funciona assim no modo "poll=1", não no streaming) — ou seja, se a
// resposta for publicada antes do transmissor estar de fato conectado aqui,
// ela se perde pra sempre. Por isso a ordem importa: abrir e confirmar a
// conexão sempre vem antes de publicar, nunca em paralelo/depois.
async function openNtfyStream(topic, signal) {
  try {
    const res = await fetch(`${NTFY_BASE}/${encodeURIComponent(topic)}/json`, { signal });
    if (!res.ok || !res.body) {
      console.error('[signal-punch] ntfy: abrir stream falhou, status', res.status);
      return null;
    }
    return res;
  } catch (err) {
    if (err.name !== 'AbortError') console.error('[signal-punch] ntfy: abrir stream deu erro de rede:', err.message);
    return null;
  }
}

// Lê o corpo de uma conexão já aberta (ver openNtfyStream), chamando
// onMessage pra cada mensagem publicada nesse tópico enquanto a conexão
// durar. Retorna quando a conexão fechar (sozinha ou abortada).
async function readNtfyStream(res, onMessage) {
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let idx;
      while ((idx = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, idx).trim();
        buffer = buffer.slice(idx + 1);
        if (!line) continue; // linha de "keepalive"/"open" da ntfy — ignora
        try {
          const envelope = JSON.parse(line);
          if (typeof envelope.message === 'string') onMessage(JSON.parse(envelope.message));
        } catch {
          // não era uma mensagem nossa — ignora
        }
      }
    }
  } catch (err) {
    if (err.name !== 'AbortError') console.error('[signal-punch] ntfy: stream caiu:', err.message);
  }
}

const STUN_SERVER = { host: 'stun.l.google.com', port: 19302 };
const STUN_MAGIC_COOKIE = 0x2112a442;
const XOR_MAPPED_ADDRESS = 0x0020;
const XOR_MAPPED_ADDRESS_LEGACY = 0x8020; // usado por alguns servidores antigos
const MAPPED_ADDRESS = 0x0001;

function buildStunBindingRequest(transactionId) {
  const msg = Buffer.alloc(20);
  msg.writeUInt16BE(0x0001, 0); // Binding Request
  msg.writeUInt16BE(0, 2); // length: sem atributos
  msg.writeUInt32BE(STUN_MAGIC_COOKIE, 4);
  transactionId.copy(msg, 8);
  return msg;
}

function parseStunBindingResponse(buf, transactionId) {
  if (buf.length < 20) return null;
  if (buf.readUInt16BE(0) !== 0x0101) return null; // Binding Success Response
  if (buf.readUInt32BE(4) !== STUN_MAGIC_COOKIE) return null;
  if (!buf.subarray(8, 20).equals(transactionId)) return null;

  const length = buf.readUInt16BE(2);
  let offset = 20;
  const end = Math.min(20 + length, buf.length);

  while (offset + 4 <= end) {
    const type = buf.readUInt16BE(offset);
    const attrLen = buf.readUInt16BE(offset + 2);
    const attrStart = offset + 4;
    if (attrStart + attrLen > buf.length) break;

    if ((type === XOR_MAPPED_ADDRESS || type === XOR_MAPPED_ADDRESS_LEGACY) && attrLen >= 8) {
      const family = buf.readUInt8(attrStart + 1);
      if (family === 0x01) {
        const port = buf.readUInt16BE(attrStart + 2) ^ (STUN_MAGIC_COOKIE >>> 16);
        const addr = buf.readUInt32BE(attrStart + 4) ^ STUN_MAGIC_COOKIE;
        return { ip: ipv4ToString(addr >>> 0), port };
      }
    } else if (type === MAPPED_ADDRESS && attrLen >= 8) {
      const family = buf.readUInt8(attrStart + 1);
      if (family === 0x01) {
        const port = buf.readUInt16BE(attrStart + 2);
        const addr = buf.readUInt32BE(attrStart + 4);
        return { ip: ipv4ToString(addr >>> 0), port };
      }
    }

    const padding = attrLen % 4 === 0 ? 0 : 4 - (attrLen % 4);
    offset = attrStart + attrLen + padding;
  }
  return null;
}

function ipv4ToString(uint32) {
  return [(uint32 >>> 24) & 0xff, (uint32 >>> 16) & 0xff, (uint32 >>> 8) & 0xff, uint32 & 0xff].join('.');
}

function getLocalIPv4Addresses() {
  const interfaces = os.networkInterfaces();
  const addresses = [];
  for (const ifaceList of Object.values(interfaces)) {
    for (const iface of ifaceList) {
      if (iface.family === 'IPv4' && !iface.internal) addresses.push(iface.address);
    }
  }
  return addresses;
}

// Pede pro SEU PRÓPRIO roteador (UPnP é local à rede, não fala com nada de
// fora) pra encaminhar a porta UDP local pra fora. Diferente do STUN (que só
// descobre um endereço, sem garantir que o roteador deixa passar), isso
// configura o roteador ativamente pra aceitar aquele tráfego — funciona
// mesmo quando o NAT sozinho não aceitaria um pacote não solicitado, desde
// que o roteador tenha UPnP habilitado (vem assim de fábrica na maioria).
// O mapeamento é removido (gateway.stop()) assim que a escuta termina — não
// fica pra sempre, e só pede a porta específica que está em uso agora.
async function mapPublicPort(localPort, timeoutMs = 3000) {
  let upnpNat;
  try {
    ({ upnpNat } = await import('@achingbrain/nat-port-mapper'));
  } catch {
    return null; // biblioteca não carregou (ex: build empacotado sem o módulo) — segue sem UPnP
  }

  const client = upnpNat();

  // Só olha o primeiro roteador que responder — em rede doméstica normal só
  // existe um mesmo, e simplifica não ter que decidir entre vários.
  let gateway;
  try {
    const iterator = client.findGateways({ signal: AbortSignal.timeout(timeoutMs) })[Symbol.asyncIterator]();
    const { value, done } = await iterator.next();
    if (done || !value) return null; // nenhum roteador UPnP respondeu a tempo
    gateway = value;
  } catch {
    return null; // busca por roteador falhou (UPnP desabilitado na rede, timeout etc.)
  }

  try {
    const candidates = [];
    for await (const mapping of gateway.mapAll(localPort, {
      protocol: 'udp',
      // Sem autoRefresh: se o cleanup no stop() falhar por algum motivo (app
      // fechado à força no meio do processo, por exemplo), o próprio
      // roteador derruba o mapeamento sozinho logo em seguida, em vez de
      // ficar exposto por mais tempo.
      ttl: 30_000,
      autoRefresh: false,
      signal: AbortSignal.timeout(timeoutMs),
    })) {
      candidates.push({ ip: mapping.externalHost, port: mapping.externalPort });
    }
    if (candidates.length === 0) return null;
    return { candidates, cleanup: () => gateway.stop().catch(() => {}) };
  } catch {
    return null; // o roteador recusou o mapeamento (UPnP desabilitado nas configs dele, por exemplo)
  }
}

// Descobre o IP:porta pública de um socket UDP já aberto e vinculado. O
// mesmo socket segue aberto depois (não é fechado aqui) para ser reusado
// como canal de sinalização, já que a maioria dos NATs mantém o mapeamento
// enquanto a porta local ficar em uso.
function discoverPublicAddress(socket, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const transactionId = crypto.randomBytes(12);
    const request = buildStunBindingRequest(transactionId);
    let done = false;

    const finish = (result) => {
      if (done) return;
      done = true;
      clearInterval(retryTimer);
      clearTimeout(giveUpTimer);
      socket.removeListener('message', onMessage);
      resolve(result);
    };

    function onMessage(msg) {
      const result = parseStunBindingResponse(msg, transactionId);
      if (result) finish(result);
      // mensagens que não são a resposta STUN esperada (ex: JSON de
      // sinalização chegando antes) são ignoradas aqui de propósito.
    }

    socket.on('message', onMessage);

    let attempts = 0;
    const send = () => {
      attempts += 1;
      socket.send(request, STUN_SERVER.port, STUN_SERVER.host, () => {});
    };
    send();
    const retryTimer = setInterval(() => {
      if (attempts >= 3) return;
      send();
    }, 900);
    const giveUpTimer = setTimeout(() => finish(null), timeoutMs);
  });
}

// Inicia o "ponto de encontro" do transmissor: escuta pela resposta do
// espectador, aplica via onAnswer e confirma com um ack.
async function startHostListener({ onAnswer }) {
  const socket = dgram.createSocket('udp4');
  await new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.bind(0, () => {
      socket.removeListener('error', reject);
      resolve();
    });
  }).catch(() => null);

  const localPort = socket.address().port;
  // "source" não afeta a lógica (a busca tenta todos igual) — é só pra dar
  // pra mostrar na UI de onde veio cada candidato, quando algo não conectar
  // e for preciso entender o que foi tentado em vez de adivinhar.
  const candidates = getLocalIPv4Addresses().map((ip) => ({ ip, port: localPort, source: 'local' }));

  // sessionId não depende de STUN/UPnP — gerado já aqui pra poder abrir a
  // conexão do retransmissor HTTPS em paralelo com a descoberta de rede, e
  // ESPERAR ela conectar de verdade antes desta função devolver o controle
  // (ver openNtfyStream: se o espectador publicar a resposta antes disso,
  // ela se perde).
  const sessionId = crypto.randomBytes(8).toString('base64url');
  const ntfyAbort = new AbortController();

  // STUN só descobre um endereço (sem garantir que o roteador deixa passar
  // um pacote não solicitado); UPnP configura o roteador ativamente pra
  // aceitar. Tenta os dois em paralelo com a conexão do retransmissor — o
  // que funcionar, funcionou.
  const [publicAddr, upnpResult, initialNtfyStream] = await Promise.all([
    discoverPublicAddress(socket),
    mapPublicPort(localPort),
    openNtfyStream(sessionId, ntfyAbort.signal),
  ]);

  if (publicAddr && !candidates.some((c) => c.ip === publicAddr.ip && c.port === publicAddr.port)) {
    candidates.push({ ...publicAddr, source: 'stun' });
  }
  if (upnpResult) {
    upnpResult.candidates.forEach((c) => {
      if (!candidates.some((existing) => existing.ip === c.ip && existing.port === c.port)) {
        candidates.push({ ...c, source: 'upnp' });
      }
    });
  }

  if (candidates.length === 0) {
    socket.close();
    ntfyAbort.abort();
    return null;
  }

  // A resposta pode chegar por dois canais em paralelo (UDP direto ou
  // retransmissor HTTPS, ver topo do arquivo) — e cada um reenvia/reconsulta
  // várias vezes até confirmar, então mais de uma cópia idêntica pode
  // aparecer. Aplica só a primeira; as demais só recebem a confirmação de
  // novo, pra fazer quem mandou parar de tentar.
  let answered = false;
  let stopped = false;

  socket.on('message', (msg, rinfo) => {
    let data;
    try {
      data = JSON.parse(msg.toString('utf8'));
    } catch {
      return; // não é JSON válido (ex: ruído/scan) — ignora
    }
    if (!data || data.v !== 1 || data.sid !== sessionId || data.t !== 'answer' || typeof data.code !== 'string') return;

    if (!answered) {
      answered = true;
      onAnswer(data.code);
    }
    const ack = Buffer.from(JSON.stringify({ v: 1, sid: sessionId, t: 'ack' }));
    socket.send(ack, rinfo.port, rinfo.address, () => {});
  });

  // Reforço via retransmissor HTTPS: a primeira conexão já foi aberta e
  // confirmada acima (initialNtfyStream), em paralelo com STUN/UPnP — por
  // isso o código do convite só sai depois de garantir que já dá pra
  // escutar. Lê essa conexão, e só reconecta (nova chamada a openNtfyStream)
  // se ela cair sozinha antes da escuta terminar.
  const assembleAnswer = createChunkAssembler();
  const handleNtfyMessage = (data) => {
    if (!data || data.v !== 1) return;
    const fullCode = assembleAnswer(data);
    if (!fullCode) return; // ainda faltam pedaços, ou não é uma mensagem de resposta
    if (!answered) {
      console.log('[signal-punch] ntfy: resposta recebida via retransmissor HTTPS');
      answered = true;
      onAnswer(fullCode);
    }
    postNtfyMessage(`${sessionId}-ack`, { v: 1, t: 'ack' }).catch(() => {});
  };

  (async () => {
    let stream = initialNtfyStream;
    while (!stopped) {
      if (stream) {
        await readNtfyStream(stream, handleNtfyMessage);
        stream = null;
        if (stopped) break;
      }
      await new Promise((r) => setTimeout(r, 1000)); // pequena pausa antes de reconectar
      if (stopped) break;
      stream = await openNtfyStream(sessionId, ntfyAbort.signal);
    }
  })().catch(() => {});

  return {
    sessionId,
    candidates,
    stop: () => {
      stopped = true;
      ntfyAbort.abort();
      socket.close();
      if (upnpResult) upnpResult.cleanup();
    },
  };
}

// Manda a resposta pra TODOS os candidatos UDP ao mesmo tempo (não sabemos de
// antemão qual vai funcionar — local, LAN ou público — então corre todos em
// paralelo), com retentativas, até o transmissor confirmar com um ack ou
// estourar o tempo limite. Retorna qual candidato exatamente respondeu (se
// algum) — não é só "conectou/não conectou", é "conectou via tal endereço
// (local/stun/upnp)" — pra dar pra diagnosticar de verdade quando não
// conectar, em vez de ficar só adivinhando.
function sendAnswerViaUdp({ candidates, sessionId, code }, { retries = 9, intervalMs = 500, timeoutMs = 5000 } = {}) {
  const payload = Buffer.from(JSON.stringify({ v: 1, sid: sessionId, t: 'answer', code }));

  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    let done = false;

    const finish = (result) => {
      if (done) return;
      done = true;
      clearInterval(retryTimer);
      clearTimeout(giveUpTimer);
      socket.close();
      resolve(result);
    };

    socket.on('message', (msg, rinfo) => {
      let data;
      try {
        data = JSON.parse(msg.toString('utf8'));
      } catch {
        return;
      }
      if (!(data && data.v === 1 && data.sid === sessionId && data.t === 'ack')) return;
      // O ack chega do endereço que o transmissor "enxerga" como origem —
      // deve bater com um dos candidatos que mandamos (local direto, ou o
      // IP:porta público se veio via STUN/UPnP).
      const via = candidates.find((c) => c.ip === rinfo.address && c.port === rinfo.port) || null;
      finish({ ok: true, via });
    });
    socket.on('error', () => finish({ ok: false, via: null }));

    let attempts = 0;
    const sendToAll = () => {
      attempts += 1;
      candidates.forEach((c) => socket.send(payload, c.port, c.ip, () => {}));
    };
    sendToAll();
    const retryTimer = setInterval(() => {
      if (attempts >= retries) return;
      sendToAll();
    }, intervalMs);
    const giveUpTimer = setTimeout(() => finish({ ok: false, via: null }), timeoutMs);
  });
}

// Reforço via retransmissor HTTPS (ver comentário no topo do arquivo e nota
// grande em openNtfyStream): abre e CONFIRMA a conexão no tópico de
// confirmação antes de publicar qualquer coisa — testado na prática que
// publicar primeiro e conectar depois perde a mensagem sempre que o outro
// lado responde rápido. Só então divide a resposta em pedaços (ver
// NTFY_CHUNK_SIZE/createChunkAssembler) e publica todos no "tópico" da
// sessão.
async function sendAnswerViaHttpRelay({ sessionId, code, timeoutMs }) {
  const controller = new AbortController();
  const ackStream = await openNtfyStream(`${sessionId}-ack`, controller.signal);
  if (!ackStream) return { ok: false, via: null };

  return new Promise((resolve) => {
    let done = false;

    const finish = (result) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      controller.abort();
      resolve(result);
    };

    const timer = setTimeout(() => {
      console.error('[signal-punch] ntfy: publicado mas nenhuma confirmação chegou a tempo');
      finish({ ok: false, via: null });
    }, timeoutMs);

    readNtfyStream(ackStream, (data) => {
      if (!(data && data.v === 1 && data.t === 'ack')) return;
      console.log('[signal-punch] ntfy: confirmação recebida');
      finish({ ok: true, via: { source: 'http-relay' } });
    }).catch(() => {});

    (async () => {
      const chunks = [];
      for (let i = 0; i < code.length; i += NTFY_CHUNK_SIZE) chunks.push(code.slice(i, i + NTFY_CHUNK_SIZE));

      const posted = await Promise.all(
        chunks.map((c, i) => postNtfyMessage(sessionId, { v: 1, sid: sessionId, t: 'answer-chunk', i, n: chunks.length, c }))
      );
      if (posted.some((ok) => !ok)) {
        console.error('[signal-punch] ntfy: falha ao publicar um ou mais pedaços da resposta');
        finish({ ok: false, via: null });
        return;
      }
      console.log(`[signal-punch] ntfy: resposta publicada em ${chunks.length} pedaço(s), aguardando confirmação...`);
    })();
  });
}

// Corre as duas vias em paralelo — o que responder primeiro com sucesso,
// ganha. Só devolve falha se as duas falharem.
async function sendAnswer({ candidates, sessionId, code }, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 5000;

  return new Promise((resolve) => {
    let pending = 2;
    const onSettled = (result) => {
      if (result.ok) {
        resolve(result);
        return;
      }
      pending -= 1;
      if (pending === 0) resolve(result);
    };

    sendAnswerViaUdp({ candidates, sessionId, code }, opts).then(onSettled);
    sendAnswerViaHttpRelay({ sessionId, code, timeoutMs }).then(onSettled);
  });
}

module.exports = { startHostListener, sendAnswer };
