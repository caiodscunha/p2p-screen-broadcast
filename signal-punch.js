// Canal de sinalização sem servidor próprio, em duas camadas:
//
// 1) UDP direto (STUN + IP local + UPnP): cada participante abre um "ponto de
//    encontro" (id de sessão + candidatos IP:porta) e quem quer falar com ele
//    manda mensagens JSON direto pra esses endereços por UDP. Funciona quando
//    o roteador/NAT permite um pacote de entrada não solicitado — mas alguns
//    roteadores/operadoras não permitem isso de jeito nenhum, mesmo com regra
//    de firewall liberada no PC (visto na prática: rede "pública" no Windows
//    já resolvida, e mesmo assim UDP direto não chega entre dois PCs de
//    verdade — provavelmente o próprio modem/operadora barrando).
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
//    tamanho de mensagem do serviço (com chunking pra mensagens grandes).
//
// Usado tanto pro pareamento 1:1 original quanto pro protocolo de salas (ver
// renderer.js): toda mensagem trocada é um objeto JSON pequeno e genérico
// ({t: 'join'|'welcome'|'offer'|'answer'|'sharing'|... , ...}), este arquivo
// não conhece o significado de nenhum campo além do envelope de roteamento
// (v, sid, t). Cada participante mantém seu próprio `startListener()` aberto
// durante toda a sessão (sala inteira, não só o primeiro round-trip) e pode
// mandar mensagens pra qualquer outro participante cujos candidatos conheça,
// via `sendMessage()` — inclusive par-a-par, sem passar por quem criou a sala.
//
// Se nenhuma das duas vias funcionar entre um par específico, aquele par
// simplesmente não conecta (mesmo caso em que a própria conexão WebRTC — que
// só usa STUN, sem TURN — também poderia falhar); os outros pares da sala não
// são afetados.
const dgram = require('dgram');
const crypto = require('crypto');
const os = require('os');

const NTFY_BASE = 'https://ntfy.sh';
// Uma oferta/resposta SDP (com vários candidatos ICE) costuma passar de
// alguns KB — bem mais do que um datagrama UDP ou uma mensagem de ntfy
// aguentam de forma confiável numa vez só. Em vez de adivinhar um limite e
// desistir se não couber, TODA mensagem (grande ou pequena) é dividida em
// pedaços pequenos e remontada do outro lado — funciona não importa o
// tamanho real da mensagem nem o limite exato do transporte.
const MESSAGE_CHUNK_SIZE = 2000;

function splitIntoChunks(text, size) {
  if (text.length === 0) return [''];
  const chunks = [];
  for (let i = 0; i < text.length; i += size) chunks.push(text.slice(i, i + size));
  return chunks;
}

// Junta os pedaços de mensagens conforme chegam, em qualquer ordem — uma
// única instância cuida de TODAS as mensagens de uma sessão ao longo da
// vida dela (uma sala fica trocando várias mensagens, não só uma). Retorna
// a mensagem original (já com JSON.parse aplicado) assim que um "mid"
// tiver todos os pedaços, ou null enquanto faltar algum ou se o envelope
// não for reconhecido. Deduplica: uma vez entregue, o mesmo "mid" nunca é
// entregue de novo (importa porque a mesma mensagem pode chegar mais de
// uma vez — reenvios da via UDP, ou UDP e ntfy chegando os dois).
function createMessageAssembler() {
  const partial = new Map(); // mid -> pedaços (array com buracos)
  const delivered = new Set(); // mid's já entregues — não deixa crescer sem limite
  const MAX_DELIVERED = 500;
  // Mensagens cujo último pedaço nunca chega (perdido nas duas vias — UDP e
  // ntfy — ao mesmo tempo) ficavam presas aqui pra sempre: era o único mapa
  // deste arquivo sem limite nenhum, um vazamento de memória real e sem
  // relação com nenhum modo de áudio, só com o tempo de uma sessão de sala
  // (quanto mais renegociações/candidatos ICE trocados, mais mensagens
  // fragmentadas passam por aqui). Mesma técnica de `delivered` abaixo:
  // `Map` preserva ordem de inserção, então descarta a mais antiga.
  const MAX_PARTIAL = 200;

  return (envelope) => {
    if (
      !envelope ||
      typeof envelope.mid !== 'string' ||
      !Number.isInteger(envelope.i) ||
      !Number.isInteger(envelope.n) ||
      envelope.n < 1 ||
      envelope.i < 0 ||
      envelope.i >= envelope.n ||
      typeof envelope.c !== 'string'
    ) {
      return null;
    }
    if (delivered.has(envelope.mid)) return null;

    let parts = partial.get(envelope.mid);
    if (!parts) {
      parts = new Array(envelope.n).fill(null);
      partial.set(envelope.mid, parts);
      if (partial.size > MAX_PARTIAL) {
        partial.delete(partial.keys().next().value);
      }
    }
    parts[envelope.i] = envelope.c;
    if (!parts.every((p) => p !== null)) return null;

    partial.delete(envelope.mid);
    delivered.add(envelope.mid);
    if (delivered.size > MAX_DELIVERED) {
      delivered.delete(delivered.values().next().value);
    }

    try {
      return JSON.parse(parts.join(''));
    } catch {
      return null;
    }
  };
}

// Devolve um resultado rico (não só sucesso/falha) pra quem chama poder
// distinguir POR QUE falhou — usado por `send()` pra montar um diagnóstico
// que chega até a UI (ver `ntfyOutcome`/mensagens de erro em renderer.js).
// `networkError: true` é a categoria "fetch failed" de verdade (relé
// inalcançável — DNS, conexão recusada, bloqueio de IP etc.), diferente de
// uma resposta HTTP com erro (relé alcançável, mas recusou o pedido — ex:
// 429 de limite de taxa).
async function postNtfyMessage(topic, obj) {
  try {
    const res = await fetch(`${NTFY_BASE}/${encodeURIComponent(topic)}`, {
      method: 'POST',
      body: JSON.stringify(obj),
    });
    if (!res.ok) console.error('[signal-punch] ntfy: publicar falhou, status', res.status);
    return { ok: res.ok, networkError: false, status: res.status };
  } catch (err) {
    console.error('[signal-punch] ntfy: publicar deu erro de rede:', err.message);
    return { ok: false, networkError: true, status: null };
  }
}

// Reduz a lista de resultados de `postNtfyMessage` (um por pedaço da
// mensagem) numa única categoria pra UI mostrar. 'unreachable' (só erros de
// rede — o caso confirmado na prática em 2026-09-19: `fetch failed` puro,
// nem chega a trocar HTTP com o servidor) e 'rate-limited' (HTTP 429) são as
// duas categorias que já se repetiram de verdade neste projeto. 'ok' quer
// dizer que o ntfy funcionou normalmente mas mesmo assim ninguém confirmou
// receber — ou seja, o problema não é o relé, é o código/sessão de destino
// (expirado, digitado errado, a pessoa já não está mais lá).
function summarizeNtfyOutcome(results) {
  if (results.length === 0) return 'unknown'; // nenhum pedaço chegou a ser tentado ainda
  if (results.every((r) => r.ok)) return 'ok';
  if (results.every((r) => r.networkError)) return 'unreachable';
  if (results.some((r) => r.status === 429)) return 'rate-limited';
  return 'error';
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

// Abre o "ponto de encontro" de UM participante: um socket UDP + um stream
// ntfy, mantidos abertos por toda a vida da sessão (sala inteira, não só um
// round-trip) — usados tanto pra RECEBER mensagens de qualquer outro
// participante (via `onMessage`) quanto pra MANDAR mensagens pra qualquer
// outro participante cujo ponto de encontro se conheça (via `send`,
// devolvido junto). Este arquivo não sabe o que cada mensagem significa —
// isso é responsabilidade de quem chama (ver protocolo de sala em
// renderer.js: 'join', 'welcome', 'offer', 'answer', 'sharing' etc.).
async function startListener({ onMessage }) {
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
  // (ver openNtfyStream: se alguém publicar uma mensagem antes disso, ela
  // se perde).
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

  let stopped = false;
  const assembler = createMessageAssembler();
  // Callbacks "finish" de todo send() ainda em andamento — usado só pra
  // conseguir encerrar todos de uma vez, como falha, se stop() for chamado
  // no meio (o socket morre e eles nunca mais receberiam ack nenhum).
  const pendingSends = new Set();
  // mid -> callback do send() em andamento esperando o ack; chamado assim
  // que o ack chegar por QUALQUER via (UDP ou ntfy — a primeira que chegar
  // resolve, o resto é ignorado porque o mid já sai do mapa).
  const pendingAcks = new Map();

  // Ponto único por onde toda mensagem recebida passa, venha de UDP
  // (rinfo preenchido) ou do stream ntfy (rinfo null) — responde no MESMO
  // canal em que a mensagem chegou.
  function handleIncoming(envelope, rinfo) {
    if (!envelope || envelope.v !== 1 || envelope.sid !== sessionId) return;

    if (envelope.t === 'ack') {
      const onAck = pendingAcks.get(envelope.mid);
      if (onAck) onAck(rinfo ? { source: 'udp', address: `${rinfo.address}:${rinfo.port}` } : { source: 'http-relay' });
      return;
    }

    const from = typeof envelope.from === 'string' ? envelope.from : null;
    const complete = assembler(envelope);
    if (!complete) return; // ainda faltam pedaços, ou envelope não reconhecido

    if (from) {
      const ack = { v: 1, sid: from, t: 'ack', mid: envelope.mid };
      if (rinfo) {
        socket.send(Buffer.from(JSON.stringify(ack)), rinfo.port, rinfo.address, () => {});
      } else {
        postNtfyMessage(from, ack).catch(() => {});
      }
    }

    onMessage(complete, { from });
  }

  socket.on('message', (msg, rinfo) => {
    let envelope;
    try {
      envelope = JSON.parse(msg.toString('utf8'));
    } catch {
      return; // não é JSON válido (ex: ruído/scan) — ignora
    }
    handleIncoming(envelope, rinfo);
  });

  // A primeira conexão ntfy já foi aberta e confirmada acima
  // (initialNtfyStream), em paralelo com STUN/UPnP. Lê essa conexão, e só
  // reconecta (nova chamada a openNtfyStream) se ela cair sozinha antes da
  // sessão terminar.
  (async () => {
    let stream = initialNtfyStream;
    while (!stopped) {
      if (stream) {
        await readNtfyStream(stream, (data) => handleIncoming(data, null));
        stream = null;
        if (stopped) break;
      }
      await new Promise((r) => setTimeout(r, 1000)); // pequena pausa antes de reconectar
      if (stopped) break;
      stream = await openNtfyStream(sessionId, ntfyAbort.signal);
    }
  })().catch(() => {});

  // Manda `message` pro participante identificado por (targetSessionId,
  // targetCandidates) — divide em pedaços (ver MESSAGE_CHUNK_SIZE) e corre
  // as duas vias: publica cada pedaço no ntfy UMA vez só (HTTP já garante
  // entrega se o POST voltar sucesso — repetir isso à toa foi o que
  // estourou o limite de taxa do ntfy.sh numa versão anterior deste
  // arquivo), e reenvia por UDP periodicamente (que não tem confirmação
  // embutida) até o destinatário confirmar com um ack — por qualquer via —
  // ou estourar o tempo limite.
  function send(targetCandidates, targetSessionId, message, opts = {}) {
    const timeoutMs = opts.timeoutMs ?? 6000;
    const udpRetryIntervalMs = opts.udpRetryIntervalMs ?? 600;

    const mid = crypto.randomBytes(6).toString('base64url');
    const chunkStrings = splitIntoChunks(JSON.stringify(message), MESSAGE_CHUNK_SIZE);
    const envelopes = chunkStrings.map((c, i) => ({
      v: 1,
      sid: targetSessionId,
      from: sessionId,
      mid,
      i,
      n: chunkStrings.length,
      c,
    }));

    return new Promise((resolve) => {
      let done = false;
      const finish = (result) => {
        if (done) return;
        done = true;
        clearInterval(udpRetryTimer);
        clearTimeout(giveUpTimer);
        pendingAcks.delete(mid);
        pendingSends.delete(finish);
        resolve(result);
      };
      pendingSends.add(finish);

      pendingAcks.set(mid, (via) => finish({ ok: true, via }));

      // Agrega o resultado de cada pedaço publicado no ntfy num diagnóstico
      // só (ver `summarizeNtfyOutcome`) — é o que deixa a UI (renderer.js)
      // mostrar uma mensagem específica ("relé inalcançável" vs "limite de
      // taxa" vs "código não existe mais") em vez de um erro genérico só,
      // se o ack nunca chegar por nenhuma via.
      const ntfyResults = [];
      Promise.all(
        envelopes.map((env) => postNtfyMessage(targetSessionId, env).then((r) => ntfyResults.push(r)))
      ).catch(() => {});

      // socket.send() LANÇA de verdade (não é uma Promise rejeitada) se o
      // socket já tiver sido fechado — pode acontecer se o app fechar ou a
      // pessoa sair da sala bem no meio de um envio ainda tentando
      // confirmar (ex: o aviso de "saí da sala" mandado pros outros ao
      // fechar). Sem o try/catch aqui, isso derrubava o processo inteiro:
      // uma exceção dentro de um callback de setInterval não tem Promise
      // nenhuma pra capturá-la, então virava um "Uncaught Exception" fatal
      // no processo principal.
      const sendUdpOnce = () => {
        envelopes.forEach((env) => {
          const payload = Buffer.from(JSON.stringify(env));
          (targetCandidates || []).forEach((c) => {
            try {
              socket.send(payload, c.port, c.ip, () => {});
            } catch {
              // socket já fechado — essa via não serve mais, mas não é
              // motivo pra derrubar o app; só segue (stop() abaixo já
              // encerra qualquer send() pendente como falha de qualquer jeito).
            }
          });
        });
      };
      sendUdpOnce();
      const udpRetryTimer = setInterval(sendUdpOnce, udpRetryIntervalMs);
      const giveUpTimer = setTimeout(
        () => finish({ ok: false, via: null, ntfy: summarizeNtfyOutcome(ntfyResults) }),
        timeoutMs
      );
    });
  }

  return {
    sessionId,
    candidates,
    send,
    stop: () => {
      stopped = true;
      ntfyAbort.abort();
      socket.close();
      if (upnpResult) upnpResult.cleanup();
      // Nenhum send() ainda em andamento vai conseguir confirmar depois
      // disso (o socket morreu) — encerra todos como falha na hora, em vez
      // de deixar cada um esperando pelo próprio timeout individual.
      pendingSends.forEach((finish) => finish({ ok: false, via: null }));
    },
  };
}

module.exports = { startListener };
