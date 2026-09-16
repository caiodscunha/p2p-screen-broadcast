const addon = require('./build/Release/audio_loopback.node');

const processes = addon.listProcesses();
console.log(`Encontrados ${processes.length} processos com janela visível:`);
processes.slice(0, 15).forEach((p) => console.log(`  pid=${p.pid}  "${p.title}"`));

if (processes.length === 0) {
  console.log('Nenhum processo encontrado — algo está errado na enumeração de janelas.');
  process.exit(1);
}

// Testa capturar áudio de um processo específico (passado via argv) ou do
// primeiro da lista, por 3 segundos.
const filter = process.argv[2];
const target = filter
  ? processes.find((p) => p.title.toLowerCase().includes(filter.toLowerCase()))
  : processes[0];

if (!target) {
  console.log(`Nenhum processo encontrado com título contendo "${filter}".`);
  process.exit(1);
}
console.log(`\nTestando captura (INCLUDE) do pid=${target.pid} ("${target.title}") por 3s...`);

let chunkCount = 0;
let totalSamples = 0;
let maxAbs = 0;
let lastError = null;

const handle = addon.startCapture(target.pid, false, (error, samples, sampleRate, channels) => {
  if (error) {
    lastError = error;
    console.log(`  ERRO reportado pelo addon: ${error}`);
    return;
  }
  chunkCount++;
  totalSamples += samples.length;
  for (let i = 0; i < samples.length; i++) {
    const abs = Math.abs(samples[i]);
    if (abs > maxAbs) maxAbs = abs;
  }
  if (chunkCount === 1) {
    console.log(`  primeiro chunk: ${samples.length} amostras, sampleRate=${sampleRate}, channels=${channels}`);
  }
});

setTimeout(() => {
  addon.stopCapture(handle);
  console.log(`\nResultado: ${chunkCount} chunks recebidos, ${totalSamples} amostras totais, pico=${maxAbs.toFixed(4)}`);
  console.log(chunkCount > 0 ? 'SUCESSO: callback de áudio está sendo chamado.' : 'FALHOU: nenhum chunk recebido.');
  process.exit(chunkCount > 0 ? 0 : 1);
}, 3000);
