'use strict';

const { desktopCapturer } = require('electron');

// O seletor nativo (useSystemPicker) e a captura de áudio do sistema via
// loopback ('audio: "loopback"') só têm suporte no Chromium/Electron para
// Windows e macOS. No Linux não existe um equivalente único: cada
// distro/servidor de áudio (PulseAudio, PipeWire, ALSA puro) expõe isso de um
// jeito diferente e o Electron não abstrai isso via getDisplayMedia, então lá
// a captura cai para vídeo apenas, sem áudio do sistema.
const platform = process.platform;
const supportsSystemPicker = platform === 'win32' || platform === 'darwin';
const supportsSystemAudioLoopback = platform === 'win32' || platform === 'darwin';

function registerDisplayMediaHandler(targetSession) {
  targetSession.setDisplayMediaRequestHandler(
    (request, callback) => {
      desktopCapturer.getSources({ types: ['screen'] }).then((sources) => {
        callback({
          video: sources[0],
          audio: supportsSystemAudioLoopback ? 'loopback' : undefined,
        });
      });
    },
    { useSystemPicker: supportsSystemPicker }
  );
}

module.exports = {
  registerDisplayMediaHandler,
  supportsSystemAudioLoopback,
};
