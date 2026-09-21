'use strict';

// Captura de áudio por processo no Linux via PipeWire puro (pw-loopback +
// pw-link + pw-record) — não depende do compat de PulseAudio (pactl/parec
// podem nem estar instalados num sistema PipeWire sem pulseaudio-utils).
//
// A ideia, testada manualmente num Ubuntu 26.04/PipeWire antes de escrever
// isto:
//
//   1. `pw-loopback` sobe um par de nós virtuais: um "sink" (onde a gente
//      pluga manualmente as portas de saída dos apps-alvo) e um "source"
//      pareado com ele (de onde o pw-record lê o que chegou no sink).
//   2. `pw-link`, usando os IDs numéricos das portas (nunca nome — dois
//      processos podem ter o mesmo nome de app, ex: duas janelas do
//      Chrome), conecta as portas de saída do(s) app(s)-alvo às portas de
//      entrada desse sink, SEM remover os links que já existiam pros
//      alto-falantes de verdade — o app continua tocando normal ao mesmo
//      tempo que também é capturado, igual ao WASAPI process loopback do
//      Windows (ver process_loopback.cpp).
//   3. `pw-record` lê o lado "source" do par como PCM cru (float32, 48kHz,
//      estéreo) e a gente repassa pro JS em chunks, no mesmo formato que o
//      addon nativo do Windows entrega.
//
// Reconecta periodicamente (syncLinks) porque um app pode abrir um novo
// stream de áudio depois que a captura já começou (ex: nova aba tocando som).

const { spawn, execFileSync } = require('child_process');
const fs = require('fs');

const REQUIRED_BINARIES = ['pw-dump', 'pw-loopback', 'pw-link', 'pw-record'];

function binaryAvailable(bin) {
  try {
    execFileSync(bin, ['--version'], { stdio: 'ignore' });
    return true;
  } catch (err) {
    // ENOENT = binário não existe; qualquer outro erro (ex: --version não
    // reconhecido) ainda indica que o binário está lá.
    return err.code !== 'ENOENT';
  }
}

const supported = REQUIRED_BINARIES.every(binaryAvailable);

// ---------- árvore de processos deste próprio app ----------
//
// Precisa saber quais PIDs são "a gente" pra nunca capturar nosso próprio
// áudio (a voz de quem está na sala, tocando pelos nossos alto-falantes) —
// sem isso ela voltaria retransmitida e ecoaria pros outros participantes.

function ownProcessTree() {
  const tree = new Set([process.pid]);
  const childrenByPpid = new Map();

  for (const entry of fs.readdirSync('/proc')) {
    if (!/^\d+$/.test(entry)) continue;
    let stat;
    try {
      stat = fs.readFileSync(`/proc/${entry}/stat`, 'utf8');
    } catch {
      continue;
    }
    // Formato: "pid (comm) state ppid ...". Usa o ÚLTIMO ")" porque o nome
    // do processo (comm) pode conter parênteses/espaços.
    const closeParen = stat.lastIndexOf(')');
    if (closeParen === -1) continue;
    const fields = stat.slice(closeParen + 2).split(' ');
    const ppid = Number(fields[1]);
    const pid = Number(entry);
    if (!Number.isFinite(ppid) || !Number.isFinite(pid)) continue;
    if (!childrenByPpid.has(ppid)) childrenByPpid.set(ppid, []);
    childrenByPpid.get(ppid).push(pid);
  }

  const queue = [process.pid];
  while (queue.length) {
    const pid = queue.shift();
    for (const child of childrenByPpid.get(pid) || []) {
      if (!tree.has(child)) {
        tree.add(child);
        queue.push(child);
      }
    }
  }
  return tree;
}

// ---------- grafo do PipeWire ----------

function dumpGraph() {
  const raw = execFileSync('pw-dump', [], { maxBuffer: 32 * 1024 * 1024, encoding: 'utf8' });
  const objects = JSON.parse(raw);
  const nodes = [];
  const ports = [];
  for (const obj of objects) {
    if (obj.type === 'PipeWire:Interface:Node') {
      nodes.push({ id: obj.id, props: (obj.info && obj.info.props) || {} });
    } else if (obj.type === 'PipeWire:Interface:Port') {
      const props = (obj.info && obj.info.props) || {};
      ports.push({
        id: obj.id,
        nodeId: props['node.id'],
        direction: props['port.direction'],
      });
    }
  }
  return { nodes, ports };
}

// Nós de saída de áudio de apps (o equivalente a "sink-input" do PulseAudio).
function listStreamNodes(graph) {
  const result = [];
  for (const node of graph.nodes) {
    if (node.props['media.class'] !== 'Stream/Output/Audio') continue;
    const pid = Number(node.props['application.process.id']);
    if (!pid) continue;
    result.push({
      nodeId: node.id,
      pid,
      title:
        node.props['application.name'] ||
        node.props['node.description'] ||
        node.props['node.name'] ||
        `pid ${pid}`,
    });
  }
  return result;
}

function findNodeIdByName(graph, nodeName) {
  const node = graph.nodes.find((n) => n.props['node.name'] === nodeName);
  return node ? node.id : null;
}

function portIds(graph, nodeId, direction) {
  return graph.ports.filter((p) => p.nodeId === nodeId && p.direction === direction).map((p) => p.id);
}

// ---------- API pública ----------

function listProcesses() {
  if (!supported) return [];
  const own = ownProcessTree();
  const graph = dumpGraph();
  const byPid = new Map();
  for (const node of listStreamNodes(graph)) {
    if (own.has(node.pid)) continue;
    if (!byPid.has(node.pid)) byPid.set(node.pid, node.title);
  }
  return Array.from(byPid, ([pid, title]) => ({ pid, title }));
}

let nextHandle = 1;
const sessions = new Map();

function emitError(session, callback, message) {
  if (session.stopped) return;
  try {
    callback(message, null, null, null);
  } catch {
    // o lado JS já pode ter desregistrado o callback, ignora
  }
}

async function waitUntil(predicate, timeoutMs, intervalMs = 100) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  return false;
}

async function startCapture(pid, exclude, callback) {
  if (!supported) {
    throw new Error(
      'Captura de áudio por processo não está disponível nesta máquina ' +
        '(faltam pw-loopback/pw-link/pw-record/pw-dump do PipeWire).'
    );
  }

  const handle = nextHandle++;
  const name = `sinalp2p_cap_${handle}`;
  const own = ownProcessTree();
  const targetPid = pid || null; // pid 0/undefined é o sentinela "sem alvo específico"

  const session = {
    stopped: false,
    linkedNodeIds: new Set(),
    pollTimer: null,
    loopbackProc: null,
    recordProc: null,
  };
  sessions.set(handle, session);

  session.loopbackProc = spawn(
    'pw-loopback',
    ['-n', name, '--capture-props', 'media.class=Audio/Sink', '--playback-props', 'media.class=Audio/Source'],
    { stdio: 'ignore' }
  );
  session.loopbackProc.on('exit', (code) => {
    if (!session.stopped) emitError(session, callback, `pw-loopback encerrou inesperadamente (code=${code})`);
  });

  const sinkReady = await waitUntil(() => {
    try {
      return findNodeIdByName(dumpGraph(), `input.${name}`) !== null;
    } catch {
      return false;
    }
  }, 3000);

  if (!sinkReady) {
    stopCapture(handle);
    throw new Error('O roteamento de áudio (pw-loopback) não respondeu a tempo.');
  }

  function matchesFilter(node) {
    if (own.has(node.pid)) return false; // nunca captura este próprio app (eco)
    if (targetPid) return exclude ? node.pid !== targetPid : node.pid === targetPid;
    return exclude; // pid=0: "sistema inteiro, exceto este app" (ver renderer.js)
  }

  function syncLinks() {
    if (session.stopped) return;
    let graph;
    try {
      graph = dumpGraph();
    } catch {
      return;
    }
    const sinkNodeId = findNodeIdByName(graph, `input.${name}`);
    if (sinkNodeId === null) return;
    const sinkInputs = portIds(graph, sinkNodeId, 'in');

    for (const node of listStreamNodes(graph)) {
      if (session.linkedNodeIds.has(node.nodeId)) continue;
      if (!matchesFilter(node)) continue;
      const outputs = portIds(graph, node.nodeId, 'out');
      const n = Math.min(outputs.length, sinkInputs.length);
      for (let i = 0; i < n; i++) {
        try {
          execFileSync('pw-link', [String(outputs[i]), String(sinkInputs[i])], { stdio: 'ignore' });
        } catch {
          // já ligado, ou a porta sumiu numa corrida — segue o jogo
        }
      }
      session.linkedNodeIds.add(node.nodeId);
    }
  }

  syncLinks();
  session.pollTimer = setInterval(syncLinks, 800);

  session.recordProc = spawn(
    'pw-record',
    ['--target', `output.${name}`, '--rate', '48000', '--channels', '2', '--format', 'f32', '-a', '-'],
    { stdio: ['ignore', 'pipe', 'pipe'] }
  );

  const FRAME_BYTES = 4 * 2; // float32 * 2 canais
  let leftover = Buffer.alloc(0);
  session.recordProc.stdout.on('data', (chunk) => {
    const buf = leftover.length ? Buffer.concat([leftover, chunk]) : chunk;
    const usable = buf.length - (buf.length % FRAME_BYTES);
    leftover = Buffer.from(buf.subarray(usable));
    if (usable === 0) return;

    // Cópia num buffer dedicado (não fatiado do pool interno do Node) pra
    // garantir o alinhamento de 4 bytes que o Float32Array exige.
    const owned = Buffer.allocUnsafeSlow(usable);
    buf.copy(owned, 0, 0, usable);
    const samples = new Float32Array(owned.buffer, owned.byteOffset, usable / 4);
    callback(null, samples, 48000, 2);
  });

  session.recordProc.on('exit', (code) => {
    if (!session.stopped && code !== 0) {
      emitError(session, callback, `pw-record encerrou inesperadamente (code=${code})`);
    }
  });

  return handle;
}

function stopCapture(handle) {
  const session = sessions.get(handle);
  if (!session) return;
  session.stopped = true;
  sessions.delete(handle);
  if (session.pollTimer) clearInterval(session.pollTimer);
  if (session.recordProc) session.recordProc.kill('SIGTERM');
  // Mata o pw-loopback por último: derruba os dois nós virtuais, o que já
  // desfaz sozinho os pw-link manuais feitos em cima deles.
  if (session.loopbackProc) session.loopbackProc.kill('SIGTERM');
}

module.exports = { supported, listProcesses, startCapture, stopCapture };
