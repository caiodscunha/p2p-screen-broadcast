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
// 2) Retransmissor HTTPS (ntfy.sh) como reforço, tentado se o UDP não
//    confirmar a entrega em pouco mais de 1s (ou direto, com quem o UDP já
//    se mostrou não chegar — ver NTFY_FALLBACK_DELAY_MS): os dois
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
// 3) Broker MQTT público (EMQX) como reserva do reserva: só usado pra MANDAR
//    quando o ntfy.sh recusa por limite (cota diária de 250 mensagens por IP
//    ou limite de pedidos por minuto — ver ntfyLimitedUntil). A conexão de
//    escuta fica sempre aberta, porque é ela que deixa alguém cujo ntfy
//    estourou alcançar você.
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
//
// Cada via tem o seu tamanho de pedaço:
// - UDP: abaixo de um pacote IP (~1472 bytes úteis). Os 2000 de antes viravam
//   datagramas fragmentados em 2 pacotes IP, e muito NAT/CGNAT descarta
//   fragmento — justamente entre redes diferentes, onde o UDP direto mais
//   falhava.
// - ntfy: o maior que cabe numa mensagem (limite de 4096 bytes, mesmo depois
//   do JSON escapar aspas/barras), porque CADA pedaço publicado conta na
//   cota diária do ntfy.sh — 250 mensagens por dia por IP no plano anônimo
//   (conferido em https://ntfy.sh/v1/account), dividida por todo mundo atrás
//   do mesmo IP (CGNAT).
const UDP_CHUNK_SIZE = 1000;
const NTFY_CHUNK_SIZE = 3000;
// O ntfy só entra se o UDP não confirmar a entrega nesse tempo (ver send()).
// Entre quem se alcança por UDP isso zera o uso da cota; pra quem depende do
// ntfy, a espera some depois da primeira mensagem (lastAckVia).
const NTFY_FALLBACK_DELAY_MS = 1200;
// O ntfy manda uma linha de "keepalive" a cada 45s em toda conexão de
// streaming aberta. Passar disso sem receber NADA quer dizer que a conexão
// morreu sem avisar (ex: a internet caiu e voltou — o TCP antigo fica
// pendurado pra sempre, sem erro nenhum), e as mensagens que chegarem pelo
// ntfy nunca mais seriam lidas.
const NTFY_STALL_MS = 70000;

// Reserva pro ntfy.sh quando ele recusa por limite. Escolhido em 2026-10-10
// testando de verdade cada candidato: o broker público da EMQX (da EMQ
// Technologies, a empresa por trás do EMQX, broker MQTT de código aberto;
// cluster distribuído em várias regiões) respondeu com TLS válido
// (certificado da DigiCert, verificado) e ida e volta de ~0,4s. O público da
// HiveMQ recusou conexão em todas as portas no mesmo dia, o sandbox da
// Eclipse não respondeu, e o test.mosquitto.org o próprio site descreve
// como "best-effort" (com histórico de quedas e bloqueio anti-DDoS) — todos
// de fora. Como o ntfy, é um serviço gratuito sem garantia de
// disponibilidade, por isso é reserva e não a via principal. O broker só vê
// o envelope de roteamento (ids de sessão) e o conteúdo já cifrado com a
// chave da sala (ver sealSignal em renderer.js).
const MQTT_BROKERS = ['mqtts://broker.emqx.io:8883'];
const MQTT_TOPIC_PREFIX = 'sinal-p2p/v2/';
const MQTT_CHUNK_SIZE = 12000; // sem cota por mensagem: pedaços maiores, normalmente 1 só
const MQTT_PUBLISH_TIMEOUT_MS = 5000;
// Depois de um 429, por quanto tempo nem tentar o ntfy: a cota diária
// (código 42908, "daily message quota reached") não volta tão cedo, então
// só testa de novo a cada hora; o limite de pedidos por minuto (42901)
// volta rápido.
const NTFY_DAILY_QUOTA_BACKOFF_MS = 60 * 60 * 1000;
const NTFY_RATE_LIMIT_BACKOFF_MS = 60 * 1000;
// Vale pro app inteiro (a cota é por IP, não por sala/sessão).
let ntfyLimitedUntil = 0;

function ntfyLimited() {
  return Date.now() < ntfyLimitedUntil;
}

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
// Devolvido pelo montador quando chega um pedaço de uma mensagem que JÁ foi
// entregue (ver handleIncoming).
const ALREADY_DELIVERED = Symbol('already-delivered');

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
  // Tetos pro que chega da rede: sem eles, um único pacote com "n" enorme
  // (ex: 1e9) fazia `new Array(n).fill(null)` alocar gigabytes e derrubava o
  // processo principal por falta de memória — bastava saber o id da sessão,
  // que viaja aberto nos próprios pacotes UDP. Mensagem legítima nenhuma
  // chega perto disso (uma oferta SDP inteira são poucos pedaços).
  const MAX_CHUNKS = 64;
  const MAX_CHUNK_LENGTH = 16384; // cabe o pedaço do MQTT (MQTT_CHUNK_SIZE) já escapado
  const MAX_MID_LENGTH = 64;

  return (envelope) => {
    if (
      !envelope ||
      typeof envelope.mid !== 'string' ||
      envelope.mid.length > MAX_MID_LENGTH ||
      !Number.isInteger(envelope.i) ||
      !Number.isInteger(envelope.n) ||
      envelope.n < 1 ||
      envelope.n > MAX_CHUNKS ||
      envelope.i < 0 ||
      envelope.i >= envelope.n ||
      typeof envelope.c !== 'string' ||
      envelope.c.length > MAX_CHUNK_LENGTH
    ) {
      return null;
    }
    if (delivered.has(envelope.mid)) return ALREADY_DELIVERED;

    // UDP e ntfy picam a MESMA mensagem em tamanhos diferentes (ver
    // UDP_CHUNK_SIZE/NTFY_CHUNK_SIZE), então os pedaços de cada via são
    // montados separados (`n` diferente) — misturar daria lixo. A entrega
    // continua sendo uma só por "mid": a via que completar primeiro ganha.
    const key = `${envelope.mid}/${envelope.n}`;
    let parts = partial.get(key);
    if (!parts) {
      parts = new Array(envelope.n).fill(null);
      partial.set(key, parts);
      if (partial.size > MAX_PARTIAL) {
        partial.delete(partial.keys().next().value);
      }
    }
    parts[envelope.i] = envelope.c;
    if (!parts.every((p) => p !== null)) return null;

    partial.delete(key);
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
      // Sem isso o ntfy.sh guarda cada mensagem por 12h, e qualquer um que
      // saiba o id do tópico lê o histórico inteiro com um GET (testado);
      // e "Firebase: no" não deixa ele repassar pro Firebase do Google (que
      // ele usa pros apps de celular). O app só lê mensagens ao vivo, pela
      // conexão de streaming — nunca precisou do histórico.
      headers: { Cache: 'no', Firebase: 'no' },
      body: JSON.stringify(obj),
    });
    if (res.status === 429) {
      let code = null;
      try {
        code = (await res.json()).code;
      } catch {
        // corpo fora do formato esperado — trata como limite de pedidos
      }
      const daily = code === 42908;
      const wasLimited = ntfyLimited();
      ntfyLimitedUntil = Date.now() + (daily ? NTFY_DAILY_QUOTA_BACKOFF_MS : NTFY_RATE_LIMIT_BACKOFF_MS);
      if (!wasLimited) {
        console.warn(
          '[signal-punch] ntfy: limite atingido (' + (daily ? 'cota diária' : 'pedidos por minuto') + ') — usando o broker MQTT reserva'
        );
      }
      return { ok: false, networkError: false, status: 429, limit: daily ? 'daily' : 'rate' };
    }
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
// durar. Retorna quando a conexão fechar (sozinha ou abortada). `onActivity`
// é chamado a cada pedaço de dado recebido, keepalive inclusive — é o sinal
// de vida que o watchdog do startListener usa (ver NTFY_STALL_MS).
async function readNtfyStream(res, onMessage, onActivity) {
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      onActivity();
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

// Dois servidores do mesmo serviço público do Google (hosts diferentes):
// a pergunta vai pros dois e vale a primeira resposta — se um não
// responder, o endereço público ainda é descoberto.
const STUN_SERVERS = [
  { host: 'stun.l.google.com', port: 19302 },
  { host: 'stun1.l.google.com', port: 19302 },
];
// Conexões com os brokers MQTT de reserva (ver MQTT_BROKERS) pra UMA sessão:
// assina o tópico dela (pra receber de quem estiver usando a reserva) e
// publica quando o ntfy está no limite. A biblioteca (MQTT.js) cuida de
// reconectar e de reassinar sozinha se a conexão cair.
function openMqttRelay(sessionId, onEnvelope) {
  let mqtt;
  try {
    mqtt = require('mqtt');
  } catch {
    return null; // biblioteca ausente — segue sem a reserva
  }
  const clients = MQTT_BROKERS.map((url) => {
    const client = mqtt.connect(url, {
      clientId: 'sinal-' + crypto.randomBytes(8).toString('hex'),
      clean: true,
      keepalive: 60,
      connectTimeout: 10_000,
      reconnectPeriod: 10_000,
      protocolVersion: 4,
    });
    client.subscribe(MQTT_TOPIC_PREFIX + sessionId, { qos: 1 });
    client.on('message', (_topic, payload) => {
      let envelope;
      try {
        envelope = JSON.parse(payload.toString('utf8'));
      } catch {
        return;
      }
      onEnvelope(envelope);
    });
    let lastError = null;
    client.on('error', (err) => {
      if (err.message === lastError) return; // não repete o mesmo erro a cada tentativa de reconexão
      lastError = err.message;
      console.error('[signal-punch] mqtt (' + url + '):', err.message);
    });
    client.on('connect', () => {
      lastError = null;
    });
    return client;
  });

  // true quando o broker confirma que recebeu (QoS 1).
  const publishOne = (client, targetSessionId, obj) =>
    new Promise((resolve) => {
      const timer = setTimeout(() => resolve(false), MQTT_PUBLISH_TIMEOUT_MS);
      client.publish(MQTT_TOPIC_PREFIX + targetSessionId, JSON.stringify(obj), { qos: 1 }, (err) => {
        clearTimeout(timer);
        resolve(!err);
      });
    });

  return {
    publish: async (targetSessionId, obj) =>
      (await Promise.all(clients.map((client) => publishOne(client, targetSessionId, obj)))).some(Boolean),
    reconnectIfDown: () =>
      clients.forEach((client) => {
        if (!client.connected && !client.reconnecting) client.reconnect();
      }),
    close: () => clients.forEach((client) => client.end(true)),
  };
}

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
      // A biblioteca nunca pede menos de 1 hora ao roteador (arredonda pra
      // cima qualquer ttl menor — o 30s que estava aqui virava 1h), então
      // sem renovação o mapeamento simplesmente sumia depois de 1 hora de
      // sala, e quem entrasse depois perdia esse caminho. Renovando, dura
      // enquanto a sala durar; o stop() remove na saída. Se o app for
      // fechado à força, o roteador derruba sozinho em no máximo 1 hora.
      ttl: 3_600_000,
      autoRefresh: true,
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
      STUN_SERVERS.forEach((server) => {
        try {
          socket.send(request, server.port, server.host, () => {});
        } catch {
          // socket fechado no meio — o giveUpTimer encerra
        }
      });
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
  const bound = await new Promise((resolve) => {
    socket.once('error', () => resolve(false));
    socket.bind(0, () => resolve(true));
  });
  if (!bound) {
    // Sem porta UDP nenhuma (antes isso estourava logo abaixo, em
    // socket.address(), e a sala simplesmente não abria sem explicação):
    // devolve null, que a UI já trata como "conexão automática indisponível".
    try {
      socket.close();
    } catch {
      // já fechado
    }
    return null;
  }
  // Depois de vinculado, um erro do socket (ex: ICMP "porta inalcançável"
  // em algumas plataformas) não pode derrubar o processo principal.
  socket.on('error', (err) => console.error('[signal-punch] erro no socket UDP:', err.message));

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
  // Um AbortController por conexão de streaming, além do geral (ntfyAbort,
  // que encerra tudo no stop()): deixa derrubar SÓ a conexão atual pra
  // reabrir uma nova — ver o watchdog e kick() abaixo.
  let streamAbort = new AbortController();
  const streamSignal = () => AbortSignal.any([ntfyAbort.signal, streamAbort.signal]);

  // STUN só descobre um endereço (sem garantir que o roteador deixa passar
  // um pacote não solicitado); UPnP configura o roteador ativamente pra
  // aceitar. Tenta os dois em paralelo com a conexão do retransmissor — o
  // que funcionar, funcionou.
  const [publicAddr, upnpResult, initialNtfyStream] = await Promise.all([
    discoverPublicAddress(socket),
    mapPublicPort(localPort),
    openNtfyStream(sessionId, streamSignal()),
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

  // Publica algo pequeno (uma confirmação) por um retransmissor: o ntfy, ou
  // o broker MQTT reserva se o ntfy estiver no limite.
  async function relayPublish(targetSessionId, obj) {
    if (!ntfyLimited()) {
      const result = await postNtfyMessage(targetSessionId, obj);
      if (result.ok || result.status !== 429) return;
    }
    if (mqttRelay) await mqttRelay.publish(targetSessionId, obj);
  }

  // Ponto único por onde toda mensagem recebida passa, venha de UDP
  // (rinfo preenchido), do stream ntfy ou do broker MQTT (`via`) — responde
  // no MESMO canal em que a mensagem chegou.
  function handleIncoming(envelope, rinfo, via) {
    if (!envelope || envelope.v !== 1 || envelope.sid !== sessionId) return;

    if (envelope.t === 'ack') {
      const onAck = pendingAcks.get(envelope.mid);
      if (onAck) {
        onAck(
          rinfo
            ? { source: 'udp', address: `${rinfo.address}:${rinfo.port}` }
            : { source: via === 'mqtt' ? 'mqtt' : 'http-relay' }
        );
      }
      return;
    }

    const from = typeof envelope.from === 'string' ? envelope.from : null;
    const complete = assembler(envelope);
    if (complete === ALREADY_DELIVERED) {
      // Quem mandou continua reenviando por UDP porque a confirmação dele
      // ainda não chegou — ela se perdeu, ou foi pelo ntfy e o ntfy recusou
      // (limite diário). Antes a repetição era descartada calada e a
      // confirmação NUNCA chegava: quem mandou achava que a mensagem tinha
      // se perdido (com o "join", a pessoa era tirada da sala do nada ~10s
      // depois de entrar, mesmo funcionando). Confirma de novo pelo próprio
      // UDP — de graça, sem gastar cota do ntfy. Uma vez por rodada de
      // reenvio (pedaço 0), não uma por pedaço.
      if (rinfo && envelope.i === 0 && typeof envelope.from === 'string') {
        const ack = { v: 1, sid: envelope.from, t: 'ack', mid: envelope.mid };
        try {
          socket.send(Buffer.from(JSON.stringify(ack)), rinfo.port, rinfo.address, () => {});
        } catch {
          // socket fechado — nada a fazer
        }
      }
      return;
    }
    if (!complete) return; // ainda faltam pedaços, ou envelope não reconhecido

    if (from) {
      const ack = { v: 1, sid: from, t: 'ack', mid: envelope.mid };
      if (rinfo) {
        socket.send(Buffer.from(JSON.stringify(ack)), rinfo.port, rinfo.address, () => {});
      } else if (via === 'mqtt') {
        if (mqttRelay) mqttRelay.publish(from, ack).catch(() => {});
      } else {
        relayPublish(from, ack).catch(() => {});
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
    handleIncoming(envelope, rinfo, 'udp');
  });

  const mqttRelay = openMqttRelay(sessionId, (envelope) => handleIncoming(envelope, null, 'mqtt'));

  // A primeira conexão ntfy já foi aberta e confirmada acima
  // (initialNtfyStream), em paralelo com STUN/UPnP. Lê essa conexão, e só
  // reconecta (nova chamada a openNtfyStream) se ela cair — sozinha, pelo
  // watchdog (sem sinal de vida há NTFY_STALL_MS) ou por kick().
  let lastNtfyActivity = Date.now();
  let ntfyStreamOpen = false;
  (async () => {
    let stream = initialNtfyStream;
    while (!stopped) {
      if (stream) {
        lastNtfyActivity = Date.now();
        ntfyStreamOpen = true;
        await readNtfyStream(stream, (data) => handleIncoming(data, null, 'ntfy'), () => {
          lastNtfyActivity = Date.now();
        });
        ntfyStreamOpen = false;
        stream = null;
        if (stopped) break;
      }
      await new Promise((r) => setTimeout(r, 1000)); // pequena pausa antes de reconectar
      if (stopped) break;
      streamAbort = new AbortController();
      stream = await openNtfyStream(sessionId, streamSignal());
    }
  })().catch(() => {});

  const ntfyWatchdog = setInterval(() => {
    if (ntfyStreamOpen && Date.now() - lastNtfyActivity > NTFY_STALL_MS) {
      console.warn('[signal-punch] ntfy: stream sem sinal de vida há', Math.round((Date.now() - lastNtfyActivity) / 1000), 's — reabrindo');
      streamAbort.abort();
    }
  }, 10000);

  // Última via que confirmou entrega pra cada destino — decide se o ntfy
  // espera o UDP tentar primeiro (ver NTFY_FALLBACK_DELAY_MS) ou já vai
  // direto, porque com esse destino o UDP não chega.
  const lastAckVia = new Map(); // targetSessionId -> 'udp' | 'http-relay' | 'mqtt'

  // Manda `message` pro participante identificado por (targetSessionId,
  // targetCandidates) — divide em pedaços (ver UDP_CHUNK_SIZE/
  // NTFY_CHUNK_SIZE) e corre as duas vias: reenvia por UDP periodicamente
  // (que não tem confirmação embutida) até o destinatário confirmar com um
  // ack — por qualquer via — ou estourar o tempo limite; e, se o UDP não
  // confirmar logo, publica cada pedaço no ntfy UMA vez só (HTTP já garante
  // entrega se o POST voltar sucesso — repetir isso à toa foi o que estourou
  // o limite de taxa do ntfy.sh numa versão anterior deste arquivo).
  function send(targetCandidates, targetSessionId, message, opts = {}) {
    const timeoutMs = opts.timeoutMs ?? 6000;
    const udpRetryIntervalMs = opts.udpRetryIntervalMs ?? 600;
    // `urgent`: não dá pra esperar o UDP tentar primeiro (ex: aviso de saída,
    // mandado logo antes do canal fechar).
    const lastVia = lastAckVia.get(targetSessionId);
    const ntfyDelayMs = opts.urgent || (lastVia && lastVia !== 'udp') ? 0 : NTFY_FALLBACK_DELAY_MS;

    const mid = crypto.randomBytes(6).toString('base64url');
    const json = JSON.stringify(message);
    const toEnvelopes = (chunkStrings) =>
      chunkStrings.map((c, i) => ({
        v: 1,
        sid: targetSessionId,
        from: sessionId,
        mid,
        i,
        n: chunkStrings.length,
        c,
      }));
    const udpEnvelopes = toEnvelopes(splitIntoChunks(json, UDP_CHUNK_SIZE));
    const ntfyEnvelopes = toEnvelopes(splitIntoChunks(json, NTFY_CHUNK_SIZE));
    const mqttEnvelopes = toEnvelopes(splitIntoChunks(json, MQTT_CHUNK_SIZE));

    return new Promise((resolve) => {
      let done = false;
      let ntfyTimer = null;
      const finish = (result) => {
        if (done) return;
        done = true;
        clearInterval(udpRetryTimer);
        clearTimeout(giveUpTimer);
        clearTimeout(ntfyTimer);
        pendingAcks.delete(mid);
        pendingSends.delete(finish);
        resolve(result);
      };
      pendingSends.add(finish);

      pendingAcks.set(mid, (via) => {
        lastAckVia.set(targetSessionId, via.source);
        finish({ ok: true, via });
      });

      // Agrega o resultado de cada pedaço publicado no ntfy num diagnóstico
      // só (ver `summarizeNtfyOutcome`) — é o que deixa a UI (renderer.js)
      // mostrar uma mensagem específica ("relé inalcançável" vs "limite de
      // taxa" vs "código não existe mais") em vez de um erro genérico só,
      // se o ack nunca chegar por nenhuma via.
      const ntfyResults = [];
      // 'unused' | 'ok' | 'failed' | 'unavailable' — usado só no diagnóstico
      let mqttOutcome = 'unused';
      ntfyTimer = setTimeout(async () => {
        ntfyTimer = null;
        if (!ntfyLimited()) {
          await Promise.all(
            ntfyEnvelopes.map((env) => postNtfyMessage(targetSessionId, env).then((r) => ntfyResults.push(r)))
          ).catch(() => {});
          if (done || !ntfyLimited()) return; // o ntfy aceitou (ou falhou por outro motivo que não limite)
        }
        // O ntfy está no limite: manda pela reserva.
        if (!mqttRelay) {
          mqttOutcome = 'unavailable';
          return;
        }
        const oks = await Promise.all(mqttEnvelopes.map((env) => mqttRelay.publish(targetSessionId, env)));
        mqttOutcome = oks.every(Boolean) ? 'ok' : 'failed';
      }, ntfyDelayMs);

      // socket.send() LANÇA de verdade (não é uma Promise rejeitada) se o
      // socket já tiver sido fechado — pode acontecer se o app fechar ou a
      // pessoa sair da sala bem no meio de um envio ainda tentando
      // confirmar (ex: o aviso de "saí da sala" mandado pros outros ao
      // fechar). Sem o try/catch aqui, isso derrubava o processo inteiro:
      // uma exceção dentro de um callback de setInterval não tem Promise
      // nenhuma pra capturá-la, então virava um "Uncaught Exception" fatal
      // no processo principal.
      const sendUdpOnce = () => {
        udpEnvelopes.forEach((env) => {
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
        () =>
          finish({
            ok: false,
            via: null,
            ntfy: ntfyResults.length === 0 && ntfyLimited() ? 'rate-limited' : summarizeNtfyOutcome(ntfyResults),
            mqtt: mqttOutcome,
          }),
        timeoutMs
      );
    });
  }

  return {
    sessionId,
    candidates,
    send,
    // A rede acabou de voltar (ver 'online' no renderer): a conexão de
    // streaming do ntfy aberta antes da queda quase certamente está morta sem
    // saber — reabre agora em vez de esperar o watchdog perceber.
    kick: () => {
      if (ntfyStreamOpen) streamAbort.abort();
      if (mqttRelay) mqttRelay.reconnectIfDown();
    },
    stop: () => {
      stopped = true;
      clearInterval(ntfyWatchdog);
      ntfyAbort.abort();
      socket.close();
      if (upnpResult) upnpResult.cleanup();
      if (mqttRelay) mqttRelay.close();
      // Nenhum send() ainda em andamento vai conseguir confirmar depois
      // disso (o socket morreu) — encerra todos como falha na hora, em vez
      // de deixar cada um esperando pelo próprio timeout individual.
      pendingSends.forEach((finish) => finish({ ok: false, via: null }));
    },
  };
}

module.exports = { startListener };
