# P2P Screen & Audio Broadcast

A serverless, peer-to-peer screen and system-audio broadcasting app for
Windows, macOS and Linux, built with Electron and native WebRTC.

It was created as a **free alternative to Discord's screen sharing**, after
Discord's streaming/voice features were blocked for users in Brazil. No
signaling server of our own, no accounts, no infrastructure to maintain: the
broadcaster generates a code, sends it to a viewer over any chat app, and
the connection is established directly between the two — automatically
whenever the network allows it, falling back to pasting one response code
back manually otherwise.

## Features

- 🖥️ Screen + system audio capture (native picker and system-audio
  loopback on Windows and macOS; manual PulseAudio/PipeWire monitor-source
  selection on Linux)
- 🎚️ Per-app audio capture on Windows: include only one app's audio, or
  exclude one app (e.g. share your game/music but not your Discord call),
  via WASAPI Process Loopback — no manual audio device routing required
- 🔗 Fully peer-to-peer via WebRTC, no relay server ever touches your
  video/audio
- ⚡ Automatic connection when possible: tries a direct UDP path first
  (local network, UPnP router port mapping, STUN-discovered public
  address), then a free public relay as a second attempt — no manual
  copy/paste needed when either one works
- 📋 Manual signaling as a guaranteed fallback: one offer/answer code
  exchange per viewer, sendable over WhatsApp, chat, email, anything,
  whenever the automatic path can't get through
- 🚫 No infrastructure of our own: no backend, no database, no accounts —
  see [How it works](#how-it-works) for the two free, public, neutral
  services involved in establishing the connection (never in the actual
  video/audio)
- 👥 One broadcaster, multiple simultaneous viewers
- 🎯 Minimal by design, just screen/audio broadcasting, no chat, no room
  list, no extra features

## Why this exists

Discord's screen streaming stopped working reliably for users in Brazil.
This project replaces that specific use case, one person streaming their
screen (with audio) to friends, without depending on any third-party
service or server. Every participant just runs the same app locally.

## How it works

The SDP handshake required by WebRTC still boils down to one **offer code**
and one **answer code**, exchanged like before — but delivering the answer
back to the broadcaster is now automated whenever possible, instead of
always requiring a manual copy/paste in both directions:

1. The broadcaster starts screen capture and generates a base64-encoded
   **offer code** (ICE gathering is awaited to completion, so it's a single
   one-shot code, no trickle ICE needed). This code also embeds a small,
   passphrase-protected "rendezvous" section (a random session id plus a
   handful of network addresses) used only for the automatic delivery
   described below.
2. The broadcaster sends that code to a viewer through any side channel
   (WhatsApp, Discord text chat, email, etc).
3. The viewer pastes the code into the app and clicks **Enter**. The app
   generates the answer, then tries to deliver it back automatically:
   - First, direct UDP to one of the addresses embedded in the offer (the
     broadcaster's local network address, a port UPnP mapped on their
     router, or their public address discovered via STUN).
   - In parallel, as a second attempt, a free public relay
     ([ntfy.sh](https://ntfy.sh)) — used only to shuttle the small
     signaling payload over plain HTTPS, so it works even when direct UDP
     is blocked by a NAT/firewall/ISP that doesn't allow it (which happens
     in practice on some networks).
   - Whichever path succeeds first wins, and the broadcaster's app applies
     the answer automatically — no code ever needs to be copied back.
4. If neither automatic path works (e.g. very restrictive network on both
   ends), the app falls back to showing the same **answer code** as before,
   for the viewer to send back manually; the broadcaster pastes it in to
   complete the connection.
5. Steps 1–4 are repeated once per additional viewer.

Two free, public, neutral third-party services are involved in setting up
the connection — never in the actual video/audio, which always flows
directly between the two peers over WebRTC:

- **Google's public STUN server** (`stun.l.google.com:19302`), used to help
  each participant discover their own public IP/port for NAT traversal.
- **[ntfy.sh](https://ntfy.sh)**, a free and open-source pub/sub-over-HTTP
  service (self-hostable, same code you could run yourself), used only as
  a best-effort relay for the tiny signaling payload described in step 3.
  If you'd rather this app never talk to it at all, it's only ever used as
  a fallback alongside direct UDP — either one failing just means falling
  back further, down to the fully manual flow.

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
4. If the network allows it, the viewer's connection completes
   automatically — nothing else to do. If their app shows "Couldn't connect
   automatically", ask for the response code it gives them, paste it into
   the "Paste response code here" field, and click **Connect viewer**.
5. Repeat steps 2–4 for each additional person who wants to watch.

At any point after step 1, click **Pause sharing** to freeze the video for
every connected viewer without dropping their connections (system audio
keeps playing); click it again to resume.

### Watching

1. Go to the **Watch** tab and paste the code received from the broadcaster.
2. Click **Enter** — the app tries to connect automatically.
3. If it can't (the status will say so), click **"Couldn't connect?
   Generate response code"**, copy the code it shows, and send it back to
   the broadcaster.
4. Once connected — automatically or after the broadcaster pastes your
   response code — video and audio start playing.

## Limitations

- **No TURN server**: this only affects the actual video/audio stream, not
  the signaling relay above — if both participants are behind
  restrictive/symmetric NATs (e.g. some corporate networks), the direct
  WebRTC connection itself may fail regardless of how the offer/answer
  codes were exchanged. Works reliably on normal home networks.
- **Automatic connection is best-effort**: it depends on things outside the
  app's control (router UPnP support, ISP/NAT behavior, ntfy.sh being
  reachable) and can simply not work on some networks. The manual
  offer/answer code exchange always remains available as a fallback and
  never stops working.
- **No room/lobby system**: every new viewer is added one at a time by
  design, there's no shared "room code" or viewer list to join from.
- **No native system-audio loopback on Linux**: `getDisplayMedia` loopback
  audio is only supported by Chromium/Electron on Windows and macOS. On
  Linux the app instead lets you manually pick a PulseAudio/PipeWire
  monitor source as a regular input device; if your distro doesn't expose
  one, only video is captured.
- Intentionally minimal: no chat, no recording, no room list, no accounts,
  just screen + audio broadcast.

## License

Licensed under the [GNU General Public License v3.0](LICENSE).
