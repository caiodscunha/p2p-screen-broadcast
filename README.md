# Sinal P2P

A serverless, peer-to-peer screen and system-audio broadcasting app for
Windows, macOS and Linux, built with Electron and native WebRTC, with a
Discord-style **room**: create or join a room with a single code, and
everyone in it can watch everyone else's screen and broadcast their own,
at the same time, in a grid you can click into focus.

It was created as a **free alternative to Discord's screen sharing**, after
Discord's streaming/voice features were blocked for users in Brazil. No
signaling server of our own, no accounts, no infrastructure to maintain: one
person creates a room and shares a small code with everyone else, and every
connection in the room is established directly, peer-to-peer, between
whichever two people need to talk to each other.

## Features

- 🧑‍🤝‍🧑 **Rooms, not one-off pairings**: create or join with one code;
  anyone in the room can start sharing their screen at any time, and
  everyone else sees it appear in the grid automatically
- 🟦 **Discord-style grid & focus**: all active screen shares laid out in a
  grid; hover a tile and click the pin icon that appears to focus it
  full-size, with the rest as a thumbnail strip below; hover the focused
  tile for the "unpin" icon to go back, exactly like Discord's pin/unpin
  behavior (the hover overlay fades out after a couple of seconds of no
  mouse movement, but clicking still always works)
- 🔊 **Per-peer volume control**: hover any tile you're watching for a
  volume slider, click the icon to mute/unmute instantly, drag the slider
  to reactivate if it was muted
- ▶️ **One-click share bar**: a floating, rounded dock at the bottom
  (room code / share / leave, with a separate participants button) with a
  share button that opens a picker (monitor + audio source) the first
  time, turns into a red "stop sharing" button while live, with an arrow
  beside it to change monitor/audio source mid-stream
- 🚪 **Stopping your share doesn't drop you from the room**: your connection
  to everyone stays up, your tile just disappears from the grid until you
  share again
- 🖥️ Screen + system audio capture (native picker and system-audio
  loopback on Windows and macOS; manual PulseAudio/PipeWire monitor-source
  selection on Linux)
- 🎚️ Per-app audio capture on Windows and Linux (PipeWire): include only one
  app's audio, or exclude one app (e.g. share your game/music but not your
  Discord call); picking this mode auto-selects "exclude" and auto-picks any
  app whose window title (or app name, on Linux) ends in "Discord", since
  that's the overwhelmingly common case. Uses WASAPI Process Loopback on
  Windows and a `pw-loopback`/`pw-link`/`pw-record` PipeWire pipeline on
  Linux, and switching audio source works live, mid-share, without
  interrupting anything
- 🔇 **No self-echo**: whichever audio mode you pick (including plain
  "system audio"), Sinal P2P's own output is automatically excluded from
  what you broadcast on Windows and Linux, so a room-mate's voice playing on
  your speakers never loops back into your own stream
- 🔗 Fully peer-to-peer via WebRTC mesh, no relay server ever touches your
  video/audio: every pair of participants in a room talks directly to
  each other
- ⚡ Automatic connection when possible: tries a direct UDP path first
  (local network, UPnP router port mapping, STUN-discovered public
  address), then a free public relay as a second attempt. No manual
  copy/paste needed when either one works
- 🚫 No infrastructure of our own: no backend, no database, no accounts.
  See [How it works](#how-it-works) for the two free, public, neutral
  services involved in establishing connections (never in the actual
  video/audio)
- 🎯 Minimal by design: rooms, screen/audio sharing, grid/focus, no chat,
  no accounts, no recording

## Why this exists

Discord's screen streaming stopped working reliably for users in Brazil.
This project replaces that use case: a group of people watching each
other's screens, like a Discord voice channel with video, without
depending on any third-party service or server. Every participant just
runs the same app locally.

## How it works

Joining a room used to mean pasting a full WebRTC offer (containing an
entire SDP) for every single pairing. Rooms work differently: the code only
carries the **rendezvous point** of whoever generated it (a random session
id plus a handful of network addresses), no SDP at all, so it's short and
generated instantly, no ICE gathering wait.

1. Someone clicks **Criar sala**: their app opens a listening "rendezvous"
   (local network addresses, a UPnP-mapped router port, and their
   STUN-discovered public address) and encodes it into a small, optionally
   passphrase-protected **room code**.
2. That code is shared with anyone who should join, through any side
   channel (WhatsApp, chat, email, etc).
3. Each person who pastes the code and clicks **Entrar** sends a small
   `join` message to that rendezvous, delivered automatically whenever the
   network allows (direct UDP first, and a free public relay,
   [ntfy.sh](https://ntfy.sh), only if UDP doesn't confirm delivery within
   about a second).
4. Whoever receives that `join` replies with the room's current roster and
   introduces the newcomer to everyone else already there. From that point
   on, **every pair of participants talks directly to each other**: the
   person who answered `join` was only ever a matchmaker for that one
   moment, never a relay for the mesh that forms afterward. Any current
   member of the room can hand out their own current room code to invite
   more people, not just whoever created it first.
5. Starting to share your screen (the bottom bar's share button) sends your
   video/audio directly to every other connection in the mesh, with no new
   code to generate or exchange, and no code re-entry needed for people
   already in the room. When a connection's bandwidth drops, the stream
   temporarily lowers its resolution to keep the frame rate (and latency)
   steady, and goes back up once the network recovers. Audio goes out as
   stereo Opus at up to 128 kbps (WebRTC's default would be mono at
   32 kbps, fine for voice but noticeably worse for music and games).
6. Once two participants are connected, everything else between them
   (who is sharing, how each one is viewing the other's screen,
   renegotiations, introducing newcomers, leaving) goes over a data channel
   inside their own WebRTC connection, encrypted by it like the media. The
   external signaling path (UDP, then the relays below) is only needed to
   enter a room and to reconnect after a drop.
7. If a connection drops, the app reconnects on its own: first it looks for
   a new network path on the same connection, then rebuilds the connection
   from scratch. Meanwhile that person's tile shows "Reconectando...", their
   status in the participants list says so, and a notice pops up in the
   corner (same for people joining, leaving, and coming back). After a
   minute without any connection they're removed from your room with a
   notice. If you're the one who lost everyone (your own internet dropped),
   a banner says so and the app keeps trying to rejoin the room by itself
   for a few minutes, no new code needed.

Free, public, neutral third-party services are involved in setting up
connections, never in the actual video/audio, which always flows directly
between peers over WebRTC:

- **Google's public STUN server** (`stun.l.google.com:19302`), used to help
  each participant discover their own public IP/port for NAT traversal.
- **[ntfy.sh](https://ntfy.sh)**, a free and open-source pub/sub-over-HTTP
  service (self-hostable, same code you could run yourself), used only as
  a best-effort relay for the small signaling messages described above
  (room join, and the per-pair WebRTC offer/answer/ICE candidates). Those
  messages are end-to-end encrypted (see below), so the relay only ever
  sees ciphertext, and they're published with caching off, so ntfy.sh
  doesn't keep them. It's only used when direct UDP doesn't confirm
  delivery; either one failing just means the room can't form that
  particular connection, everything else keeps working.
- **EMQX's public MQTT broker** (`broker.emqx.io`, run by EMQ Technologies,
  the company behind the open-source EMQX broker), as a backup for ntfy.sh:
  messages are only sent through it when ntfy.sh refuses them because of
  its limits (the daily quota or the per-minute request limit). The app
  keeps a listening connection to it open (over TLS) so that someone whose
  ntfy.sh quota ran out can still reach you. Like ntfy.sh, it only sees
  routing ids and already-encrypted messages. It was picked after testing
  the well-known public brokers: HiveMQ's refused connections and
  Eclipse's sandbox didn't answer at the time, and test.mosquitto.org
  describes itself as best-effort. It's a free service with no uptime
  guarantee, which is why it's a backup and not the main path.

### Encryption

Video and audio are always encrypted by WebRTC itself (DTLS-SRTP). That
protection relies on the signaling messages (which carry each side's DTLS
fingerprint) not being tampered with, so the signaling is encrypted too:

- **Signaling (always on)**: every room has a random 256-bit room key,
  carried inside the room code. Every message between participants (offers
  and answers with everyone's IP addresses and DTLS fingerprints, the
  roster, names) is compressed and then encrypted and authenticated with it
  (AES-GCM, Web Crypto API, no dependencies), bound to the sender's session.
  Without the code, someone watching the network or the relay can't read
  these messages, forge one, or replay a captured one: anything that doesn't
  decrypt is dropped before it's processed. Codes from older versions
  (without a room key) are refused with a message asking for a new code, so
  everyone in a room needs the current version.
- **The room code itself (optional passphrase)**: the code is plain base64
  by default, so anyone who gets a copy can join (it's the invitation).
  Both "Criar sala" and "Entrar em sala" have an optional passphrase field:
  if set, the code is encrypted with AES-GCM (key derived via PBKDF2) before
  being base64-encoded, and the same passphrase is required to decode it.
  This only adds real protection if the passphrase is agreed through a
  different channel than the one used to send the code (e.g. code over
  chat, passphrase said out loud on a call).

### Per-app audio capture (Windows and Linux)

The audio source picker in the share popover has a "Specific process"
option that lets you include only one running app's audio, or exclude one
app from an otherwise full system-audio share, e.g. share your game or
music but keep a Discord voice call out of the stream, without routing
anything to a separate audio device manually. Picking this option
automatically switches to "exclude" mode and auto-selects any running app
whose window title (Windows) or app name (Linux) ends in "Discord" (falling
back to just the first app in the list if none matches); you can always
change it manually afterward.

On **Windows**, this uses WASAPI's Process Loopback Capture
(`AUDIOCLIENT_ACTIVATION_TYPE_PROCESS_LOOPBACK`, Windows 10 2004+), the same
API OBS Studio uses for its "Application Audio Capture" source. It isn't
exposed by Chromium/Electron's JS APIs, so it's implemented as a small
native addon (`native/audio-loopback/`, C++/N-API) that captures raw PCM
for a target process (and its child processes) and streams it to the
renderer, where a Web Audio `AudioWorklet` turns it into a real
`MediaStreamTrack` that gets added to the share alongside the video.

On **Linux**, there's no equivalent single API, so this shells out to
PipeWire's own CLI tools instead of a native addon
(`native/audio-loopback/linux-pipewire.js`): `pw-loopback` creates a pair of
virtual sink/source nodes, `pw-link` connects the target app's output ports
into that virtual sink by numeric port ID (never by name, since two
processes can share the same app name) without removing the app's existing
link to your real speakers — so it keeps playing normally while also being
captured — and `pw-record` reads the virtual source as raw PCM. Requires an
actual PipeWire session (not plain PulseAudio) with `pw-loopback`,
`pw-link`, `pw-record` and `pw-dump` available, which is the default on
current mainstream distros (Ubuntu, Fedora, etc.); if any of those binaries
are missing, this option simply doesn't appear, same as on macOS.

Plain "system audio" also uses this same per-process mechanism on Windows
and Linux (targeting this app's own process in exclude mode) instead of
Electron's built-in loopback, so it can be switched to/from at any point
during a share, not just chosen once at the very start, and so it never
includes Sinal P2P's own output (preventing the echo a room-mate's voice
would otherwise cause). Since the audio no longer needs to ride along with
the screen picker, the monitor dropdown also stays usable with "system
audio" selected. On macOS (no native addon and no PipeWire path), "system
audio" keeps the older behavior: tied to `getDisplayMedia`'s one-time OS
picker grant, not switchable mid-share, and not self-excluding.

## Tech stack

- **Electron**: desktop shell, native screen/window picker, system-audio
  loopback capture
- **WebRTC** (native, via Chromium): peer-to-peer mesh media transport
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
Everyone who wants to be in a room needs to download and run the app on
their own machine (there's nothing to install on a server).

- **Windows**: `Sinal-P2P-<version>-win.exe` (portable, no install needed,
  just run it)
- **Linux**: `Sinal-P2P-<version>-linux-x64.tar.gz` (extract and run the
  `Sinal P2P` binary inside)

A macOS build isn't published yet: `electron-builder` refuses to build for
macOS from any non-macOS host, even for an unsigned `.zip`, so it needs to
be built on an actual Mac (see `npm run dist:mac` below).

## Getting started (from source)

Everyone who wants to be in a room needs Node.js installed and must run the
app on their own machine.

```bash
npm install
npm start
```

To build the executables yourself:

```bash
npm run dist:win     # Windows portable .exe
npm run dist:mac     # macOS .zip, must be run on an actual Mac, electron-builder refuses this target on other hosts
npm run dist:linux   # Linux .tar.gz
npm run dist         # all three
```

Rebuilding the Windows build from source also rebuilds the native
per-process audio module (see below), which requires the C++ workload of
Visual Studio Build Tools (`Desktop development with C++`) to be installed.
Without it, `npm install`/`npm run dist:win` still work, but per-process
audio capture is silently unavailable (falls back to not offering that
option in the UI). Linux needs no build step for this feature — it shells
out to PipeWire's CLI tools at runtime instead of a compiled addon (see
above), so it works as long as those tools are present on whoever's running
the app, on any machine that built or downloaded the Linux release.

## Usage

> **Windows**: your network must be set to **Private** (Settings → Network
> & Internet → your network → Network profile type). On a **Public**
> profile, Windows Firewall blocks the inbound connections Sinal P2P needs
> for direct peer-to-peer networking, and rooms can fail to connect.

### Creating a room

1. On the home screen, fill in your name and (optionally) a passphrase
   under **Criar sala**, then click it.
2. In the room, click **Copiar código da sala** and send that code to
   whoever you want to invite, through any channel (WhatsApp, chat, etc).
   Anyone can join with it for as long as your app stays open, and once
   they're in, they can generate and share their own current invite code
   too, so the room doesn't depend on you staying online forever.
3. Click the monitor icon in the bottom bar to open the share popover, pick
   a monitor and an audio source, and click **Começar a compartilhar**.
   Your tile appears in the grid for everyone in the room.
4. While live, the same button turns into a red "stop sharing" button
   (click to stop instantly); the small arrow beside it reopens the same
   popover to switch monitor or audio source without interrupting the
   stream.

### Joining a room

1. On the home screen, paste the code you received under **Entrar em
   sala**, fill in your name and the passphrase if one was set, and click
   **Entrar**. If it doesn't connect (expired code, the room's creator
   already closed their app, or a temporary signaling hiccup; see
   [Known issues](#known-issues)), a message explains that and you're
   returned to the home screen automatically after a few seconds.
2. You'll see the grid of whoever's currently sharing (or an empty state if
   nobody is yet) and a participants list of everyone in the room (toggle it
   with the people icon on the right of the bottom dock). Hover a tile and
   click the pin icon to focus it full-size; hover the focused tile and
   click "unpin" to go back to the grid.
3. Share your own screen the same way described above whenever you want to.

## Limitations

- **No TURN server**: this only affects the actual video/audio stream, not
  the signaling relay above. If two participants are both behind
  restrictive/symmetric NATs (e.g. some corporate networks), the direct
  WebRTC connection between just that pair may fail regardless of how the
  room code was exchanged. Works reliably on normal home networks.
- **Automatic connection is best-effort**: it depends on things outside the
  app's control (router UPnP support, ISP/NAT behavior, ntfy.sh being
  reachable) and can simply not work on some networks. There's currently
  no manual fallback for room signaling (unlike the old one-off offer/
  answer flow), since a room's mesh isn't a single pairing that a human can
  paste codes for.
- **No SFU / bandwidth budgeting**: since every pair of participants talks
  directly (mesh), a room with several people sharing their screens at the
  same time means each of them is uploading directly to every other
  participant; there's a per-connection bitrate cap, but nothing that
  budgets total bandwidth across a room with many simultaneous
  broadcasters. The same goes for encoding: every viewer gets their own
  encode of your screen. To keep that cheap, the app prefers H.264 on the
  GPU's hardware encoder (NVENC, Quick Sync, AMF, VideoToolbox), which also
  lets viewers decode it on their GPU, and only sends each viewer what they
  actually see: a viewer who has your stream as a small thumbnail (focused
  on someone else) gets it at 180p and 15 fps, and a viewer who can't see
  it at all (thumbnails hidden, or the app minimized) gets no video from
  you until that changes, which stops your encoder for them (audio keeps
  going). A PC without a usable hardware encoder falls back to VP8 in
  software, which gets CPU-heavy at 1080p and above with several viewers.
- **No native `getDisplayMedia` system-audio loopback on Linux**: that
  specific API is only supported by Chromium/Electron on Windows and macOS.
  Linux instead gets its own audio path: on a PipeWire session, per-app
  capture (see above) covers both "specific app" and "whole system audio"
  the same way it does on Windows; without PipeWire's CLI tools, the app
  falls back to letting you manually pick a PulseAudio/PipeWire monitor
  source as a regular input device, and if your distro doesn't expose one,
  only video is captured.
- Intentionally minimal: no chat, no recording, no accounts, just rooms +
  screen/audio sharing.

## Known issues

Unlike [Limitations](#limitations) above (things that are inherent to the
architecture), these are real bugs/rough edges that just haven't been fixed
yet:

- **ntfy.sh rate limiting**: the free public relay used for automatic room
  signaling (see [How it works](#how-it-works)) limits by IP address, not
  by app: anonymous use gets 250 messages per day per IP (as reported by
  `https://ntfy.sh/v1/account`), plus a short-term request rate limit. Every
  piece of a signaling message counts, and the quota is shared by everyone
  behind the same public IP (CGNAT). To make it last, the app only uses the
  relay when direct UDP doesn't confirm delivery, sends everything after
  the first connection over the WebRTC data channel instead, and keeps
  reconnection attempts frugal. When the quota runs out anyway, ntfy.sh
  answers HTTP 429 and the app switches to the EMQX backup broker (see
  [How it works](#how-it-works)) until ntfy.sh accepts messages again; a
  failed join says which of them was the problem.
- **Screen/audio capture is still rough on Linux**: unlike Windows/macOS,
  there's no single API Electron can rely on across distros: behavior
  varies by desktop environment and audio server. Per-app capture (see
  above) was built and manually tested against one PipeWire session
  (Ubuntu), not across distros/desktop environments yet — on a system
  running plain PulseAudio (no PipeWire), it falls back to the older manual
  monitor-source selection, same as before this existed. Screen picking is
  also more likely to need manual fiddling or simply not work on some
  setups. Since the move to Electron 44, the app runs as a native Wayland
  app on Wayland sessions (Electron's default since version 38) instead of
  through XWayland, which changes how screen capture works there; this
  hasn't been tested on Linux yet.
- **Minimizing while sharing could freeze the whole computer (fixed, but not
  a driver fix: the trigger is avoided instead)**: on some machines, mainly
  laptops with hybrid graphics (an Intel integrated GPU alongside a
  discrete one, e.g. NVIDIA Optimus), minimizing the window while actively
  sharing your screen could freeze the entire PC, not just the app. This
  matches a known, driver-level bug class (documented by Intel and reported
  by others independently of this app): minimizing is a window-resize event
  at the OS level, and resizing a GPU-accelerated window while its GPU is
  under heavy concurrent load (screen capture + hardware video encoding, in
  this case) is a known trigger for hybrid-graphics driver hangs. We can't
  fix the driver from here, so instead the app **disables the minimize
  button/shortcut for as long as you're sharing your screen** (a one-time
  dialog explains this the first time it happens), removing the trigger
  instead of reacting to it. This doesn't cover every way Windows can
  minimize a window (Win+D "Show desktop" still minimizes everything
  regardless); switching to another app normally (Alt+Tab, clicking another
  window) works fine and doesn't trigger this. Separately, and unrelated to
  the freeze above: if another window fully covers the broadcaster's
  (without minimizing), the video can still visibly stall for viewers until
  it's uncovered again (confirmed via WebRTC stats that frames keep
  arriving but stop being decoded while occluded); not yet root-caused or
  fixed.

## License

Licensed under the [GNU General Public License v3.0](LICENSE).
