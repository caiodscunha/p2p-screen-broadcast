// Recebe chunks PCM intercalados (Float32Array) vindos do processo nativo de
// captura por processo (via postMessage) e os reproduz continuamente na
// saída do AudioWorklet — essa saída vira um MediaStreamTrack de verdade
// através de um MediaStreamAudioDestinationNode, algo que não existe jeito
// de criar diretamente a partir de dados PCM crus sem passar pela Web Audio.
class PcmInjectorProcessor extends AudioWorkletProcessor {
  constructor() {
    super();
    this.queue = [];
    this.readFrame = 0;
    this.port.onmessage = (event) => {
      const { interleaved, channels } = event.data;
      this.queue.push({ interleaved, channels, totalFrames: interleaved.length / channels });
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
      if (this.readFrame >= current.totalFrames) {
        this.queue.shift();
        this.readFrame = 0;
      }
    }

    return true;
  }
}

registerProcessor('pcm-injector', PcmInjectorProcessor);
