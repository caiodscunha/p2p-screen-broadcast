// Recebe chunks PCM intercalados (Float32Array) vindos do processo nativo de
// captura por processo (via postMessage) e os reproduz continuamente na
// saída do AudioWorklet — essa saída vira um MediaStreamTrack de verdade
// através de um MediaStreamAudioDestinationNode, algo que não existe jeito
// de criar diretamente a partir de dados PCM crus sem passar pela Web Audio.
//
// A fila é um pequeno buffer contra o "jitter" do caminho captura → processo
// principal → IPC → aqui: os chunks (~10ms cada no Windows) não chegam em
// ritmo perfeito — basta o processo principal engasgar um instante pra
// vários chegarem de uma vez. O problema é que, depois de uma rajada, a
// produção e o consumo voltam a andar no mesmo ritmo e a fila NUNCA mais
// esvazia sozinha: cada engasgo virava atraso permanente no áudio
// transmitido, até o teto antigo de 0,5s — e quem assistia ouvia o som
// atrasado em relação ao vídeo (a sincronia do WebRTC não tem como corrigir
// isso: pra ele, o áudio foi "capturado" na hora em que sai daqui). Agora
// a fila se ajusta pros dois lados:
// - a cada WINDOW, olha o MENOR nível que a fila teve nesse período — o
//   quanto de folga sobrou até no pior momento. Se nem no pior momento
//   precisou de tudo (sobrou mais que MARGIN), aquele excesso é atraso à
//   toa: corta. Um engasgo isolado e grande deixa de virar atraso pra
//   sempre; um jitter que se repete continua coberto (a folga que ele usa
//   não sobra, então não é cortada). Testado numa simulação com engasgos
//   aleatórios: a versão anterior ficava em ~200ms de atraso; um alvo fixo
//   baixo derrubava o atraso mas inseria ~10x mais silêncio (picotava).
// - acima de MAX descarta o mais antigo na hora (rajada enorme, ou o
//   contexto ficou parado sem chamar process() — sem teto a fila crescia
//   sem limite: 48kHz estéreo float32 são ~1,4GB por hora);
// - quando a fila esvazia, espera juntar PRIME antes de voltar a tocar, em
//   vez de tocar cada chunk que chega e esvaziar de novo logo em seguida.
const WINDOW_SECONDS = 5;
const MARGIN_SECONDS = 0.02;
const PRIME_SECONDS = 0.02;
const MAX_QUEUED_SECONDS = 0.4;

class PcmInjectorProcessor extends AudioWorkletProcessor {
  constructor() {
    super();
    this.queue = [];
    this.readFrame = 0;
    this.queuedFrames = 0;
    this.primed = false;
    this.windowFrames = Math.round(sampleRate * WINDOW_SECONDS);
    this.marginFrames = Math.round(sampleRate * MARGIN_SECONDS);
    this.primeFrames = Math.round(sampleRate * PRIME_SECONDS);
    this.maxQueuedFrames = Math.round(sampleRate * MAX_QUEUED_SECONDS);
    this.windowElapsed = 0;
    this.windowMin = Infinity;
    this.port.onmessage = (event) => {
      const { interleaved, channels } = event.data;
      const totalFrames = interleaved.length / channels;
      this.queue.push({ interleaved, channels, totalFrames });
      this.queuedFrames += totalFrames;
      if (this.queuedFrames > this.maxQueuedFrames) this.dropOldest(this.queuedFrames - this.maxQueuedFrames);
    };
  }

  // Descarta `frames` quadros do começo da fila (o áudio mais antigo).
  dropOldest(frames) {
    while (frames > 0 && this.queue.length) {
      const current = this.queue[0];
      const available = current.totalFrames - this.readFrame;
      if (frames >= available) {
        this.queue.shift();
        this.readFrame = 0;
        this.queuedFrames -= available;
        frames -= available;
      } else {
        this.readFrame += frames;
        this.queuedFrames -= frames;
        frames = 0;
      }
    }
  }

  process(_inputs, outputs) {
    const output = outputs[0];
    const numFrames = output[0].length;
    const numChannels = output.length;

    if (!this.primed && this.queuedFrames >= this.primeFrames) this.primed = true;

    for (let frame = 0; frame < numFrames; frame++) {
      const current = this.primed ? this.queue[0] : null;
      if (!current) {
        for (let ch = 0; ch < numChannels; ch++) output[ch][frame] = 0;
        continue;
      }

      for (let ch = 0; ch < numChannels; ch++) {
        const srcCh = Math.min(ch, current.channels - 1);
        output[ch][frame] = current.interleaved[this.readFrame * current.channels + srcCh] || 0;
      }

      this.readFrame++;
      this.queuedFrames--;
      if (this.readFrame >= current.totalFrames) {
        this.queue.shift();
        this.readFrame = 0;
      }
    }

    if (this.queuedFrames <= 0) this.primed = false;

    this.windowMin = Math.min(this.windowMin, this.queuedFrames);
    this.windowElapsed += numFrames;
    if (this.windowElapsed >= this.windowFrames) {
      if (this.primed && this.windowMin > this.marginFrames) this.dropOldest(this.windowMin - this.marginFrames);
      this.windowElapsed = 0;
      this.windowMin = Infinity;
    }

    return true;
  }
}

registerProcessor('pcm-injector', PcmInjectorProcessor);
