// Recebe chunks PCM intercalados (Float32Array) vindos do processo nativo de
// captura por processo (via postMessage) e os reproduz continuamente na
// saída do AudioWorklet — essa saída vira um MediaStreamTrack de verdade
// através de um MediaStreamAudioDestinationNode, algo que não existe jeito
// de criar diretamente a partir de dados PCM crus sem passar pela Web Audio.
//
// A fila tem teto: a captura (relógio do PipeWire/WASAPI) e este
// AudioContext (relógio da placa de som) andam em relógios independentes,
// e se este aqui consome mais devagar — deriva de clock, ou pior, o
// contexto parado/suspenso sem chamar process() — a fila crescia pra
// sempre: 48kHz estéreo float32 são ~1,4GB por hora. Passou do teto,
// descarta o áudio mais antigo (um "pulo" curto, inaudível na prática, em
// vez de atraso crescente e memória sem fim).
const MAX_QUEUED_SECONDS = 0.5;

class PcmInjectorProcessor extends AudioWorkletProcessor {
  constructor() {
    super();
    this.queue = [];
    this.readFrame = 0;
    this.queuedFrames = 0;
    this.maxQueuedFrames = Math.round(sampleRate * MAX_QUEUED_SECONDS);
    this.port.onmessage = (event) => {
      const { interleaved, channels } = event.data;
      const totalFrames = interleaved.length / channels;
      this.queue.push({ interleaved, channels, totalFrames });
      this.queuedFrames += totalFrames;
      while (this.queue.length > 1 && this.queuedFrames > this.maxQueuedFrames) {
        const dropped = this.queue.shift();
        this.queuedFrames -= dropped.totalFrames - this.readFrame;
        this.readFrame = 0;
      }
    };
  }

  process(_inputs, outputs) {
    const output = outputs[0];
    const numFrames = output[0].length;
    const numChannels = output.length;

    for (let frame = 0; frame < numFrames; frame++) {
      const current = this.queue[0];
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

    return true;
  }
}

registerProcessor('pcm-injector', PcmInjectorProcessor);
