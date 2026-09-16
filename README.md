# P2P Screen & Audio Broadcast

A serverless, peer-to-peer screen and system-audio broadcasting app for
Windows, macOS and Linux, built with Electron and native WebRTC.

It was created as a **free alternative to Discord's screen sharing**, after
Discord's streaming/voice features were blocked for users in Brazil. No
signaling server, no accounts, no infrastructure to maintain, just two
people exchanging a text code to establish a direct peer-to-peer connection.

## Features

- 🖥️ Screen + system audio capture (native picker and system-audio
  loopback on Windows and macOS; manual PulseAudio/PipeWire monitor-source
  selection on Linux)
- 🎚️ Per-app audio capture on Windows: include only one app's audio, or
  exclude one app (e.g. share your game/music but not your Discord call),
  via WASAPI Process Loopback — no manual audio device routing required
- 🔗 Fully peer-to-peer via WebRTC, no relay server ever touches your
  video/audio
- 🚫 Zero infrastructure, no signaling server, no backend, no account,
  no database
- 📋 Manual signaling via copy/paste, one offer/answer code exchange per
  viewer, sendable over WhatsApp, chat, email, anything
- 👥 One broadcaster, multiple simultaneous viewers
- 🎯 Minimal by design, just screen/audio broadcasting, no chat, no room
  list, no extra features

## Why this exists

Discord's screen streaming stopped working reliably for users in Brazil.
This project replaces that specific use case, one person streaming their
screen (with audio) to friends, without depending on any third-party
service or server. Every participant just runs the same app locally.

## How it works

There is **no signaling server**, not even a free public one. Instead, the
SDP handshake required by WebRTC is done manually:

1. The broadcaster starts screen capture and generates a base64-encoded
   **offer code** (ICE gathering is awaited to completion, so it's a single
   one-shot code, no trickle ICE needed).
2. The broadcaster sends that code to a viewer through any side channel
   (WhatsApp, Discord text chat, email, etc).
3. The viewer pastes the code into the app and generates an **answer
   code**, which they send back to the broadcaster.
4. The broadcaster pastes the answer code in, the direct P2P connection
   is established and the stream starts playing for the viewer.
5. Steps 1–4 are repeated once per additional viewer.

The only external service involved is a public Google STUN server
(`stun.l.google.com:19302`), used only to help discover each participant's
public IP/port for NAT traversal. No STUN/TURN server ever sees your
video, audio, or any application data.

### Code encryption (optional)

The offer/answer code is base64, not encryption — anyone who gets a copy of
it (not just the intended recipient) can attempt to use it, since it embeds
your ICE candidates (IP/port) in plain text. Both the broadcast and watch
screens have an optional passphrase field: if set, the code is encrypted
with AES-GCM (key derived via PBKDF2, Web Crypto API, no dependencies)
before being base64-encoded, and the same passphrase is required to decode
it on the other end. This only adds real protection if the passphrase is
agreed through a different channel than the one used to send the code
(e.g. code over chat, passphrase said out loud on a call) — if both travel
together over the same compromised channel, encryption doesn't help.
Leaving the passphrase blank keeps the previous plain behavior.

### Per-app audio capture (Windows only)

The "Audio source" dropdown on the Broadcast tab has a "Specific process"
option that lets you include only one running app's audio, or exclude one
app from an otherwise full system-audio share — e.g. share your game or
music but keep a Discord voice call out of the stream, without routing
anything to a separate audio device manually.

This uses WASAPI's Process Loopback Capture (`AUDIOCLIENT_ACTIVATION_TYPE_
PROCESS_LOOPBACK`, Windows 10 2004+), the same API OBS Studio uses for its
"Application Audio Capture" source. It isn't exposed by Chromium/Electron's
JS APIs, so it's implemented as a small native addon
(`native/audio-loopback/`, C++/N-API) that captures raw PCM for a target
process (and its child processes) and streams it to the renderer, where a
Web Audio `AudioWorklet` turns it into a real `MediaStreamTrack` that gets
added to the broadcast alongside the video. Windows-only — on macOS and
Linux this option simply doesn't appear.

## Tech stack

- **Electron**: desktop shell, native screen/window picker, system-audio
  loopback capture
- **WebRTC** (native, via Chromium): peer-to-peer media transport
- **Vanilla JS/HTML/CSS**: renderer UI, no frameworks

Electron was chosen over alternatives (.NET/SIPSorcery, Python) specifically
for its support of `getDisplayMedia` with system-audio loopback and the
native source picker on Windows and macOS.

Platform-specific capture logic lives in `capture.js`, isolated from the
rest of the app so Windows, macOS and Linux run from the same codebase
without diverging branches.

## Download

Prebuilt executables for Windows and Linux are published on the
[Releases page](https://github.com/caiodscunha/p2p-screen-broadcast/releases).
Both the broadcaster and every viewer need to download and run the app on
their own machine (there's nothing to install on a server).

- **Windows**: `Sinal-P2P-<version>-win.exe` (portable, no install needed —
  just run it)
- **Linux**: `Sinal-P2P-<version>-linux-x64.tar.gz` (extract and run the
  `Sinal P2P` binary inside)

A macOS build isn't published yet — `electron-builder` refuses to build for
macOS from any non-macOS host, even for an unsigned `.zip`, so it needs to
be built on an actual Mac (see `npm run dist:mac` below).

## Getting started (from source)

Both the broadcaster and every viewer need Node.js installed and must run
the app on their own machine.

```bash
npm install
npm start
```

To build the executables yourself:

```bash
npm run dist:win     # Windows portable .exe
npm run dist:mac     # macOS .zip — must be run on an actual Mac, electron-builder refuses this target on other hosts
npm run dist:linux   # Linux .tar.gz
npm run dist         # all three
```

Rebuilding the Windows build from source also rebuilds the native
per-process audio module (see below), which requires the C++ workload of
Visual Studio Build Tools (`Desktop development with C++`) to be installed.
Without it, `npm install`/`npm run dist:win` still work, but per-process
audio capture is silently unavailable (falls back to not offering that
option in the UI).

## Usage

### Broadcasting

1. Go to the **Broadcast** tab. On Windows/macOS, click **Start screen
   capture** and check "also share system audio" in the native picker. On
   Linux, first pick your sound card's monitor source (usually named
   "Monitor of ...") from the audio dropdown that appears, then click
   **Start screen capture**.
2. Click **Generate code for new viewer** and copy the generated code.
3. Send that code to the viewer through any channel (WhatsApp, chat, etc).
4. Ask the viewer for their response code, paste it into the "Paste
   response code here" field, and click **Connect viewer**.
5. Repeat steps 2–4 for each additional person who wants to watch.

At any point after step 1, click **Pause sharing** to freeze the video for
every connected viewer without dropping their connections (system audio
keeps playing); click it again to resume.

### Watching

1. Go to the **Watch** tab and paste the code received from the broadcaster.
2. Click **Generate response code** and copy the generated code.
3. Send that response code back to the broadcaster.
4. Once the broadcaster connects, video and audio start playing
   automatically.

## Limitations

- **No TURN server**: if both participants are behind restrictive/symmetric
  NATs (e.g. some corporate networks), the direct connection may fail.
  Works reliably on normal home networks.
- **Manual signaling only**: every new viewer requires one manual
  offer/answer code exchange, there's no room/lobby system by design.
- **No native system-audio loopback on Linux**: `getDisplayMedia` loopback
  audio is only supported by Chromium/Electron on Windows and macOS. On
  Linux the app instead lets you manually pick a PulseAudio/PipeWire
  monitor source as a regular input device; if your distro doesn't expose
  one, only video is captured.
- Intentionally minimal: no chat, no recording, no room list, no accounts,
  just screen + audio broadcast.

## License

Licensed under the [GNU General Public License v3.0](LICENSE).
