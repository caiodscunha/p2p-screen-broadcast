# Sinal P2P

A serverless, peer-to-peer screen and system-audio broadcasting app for
Windows, macOS and Linux, built with Electron and native WebRTC — with a
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
  full-size, with the rest as a thumbnail strip below — hover the focused
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
- 🎚️ Per-app audio capture on Windows: include only one app's audio, or
  exclude one app (e.g. share your game/music but not your Discord call) —
  picking this mode auto-selects "exclude" and auto-picks any app whose
  window title ends in "Discord", since that's the overwhelmingly common
  case. Uses WASAPI Process Loopback, and switching audio source works
  live, mid-share, without interrupting anything
- 🔇 **No self-echo**: whichever audio mode you pick (including plain
  "system audio"), Sinal P2P's own output is automatically excluded from
  what you broadcast on Windows — so a room-mate's voice playing on your
  speakers never loops back into your own stream
- 🔗 Fully peer-to-peer via WebRTC mesh, no relay server ever touches your
  video/audio — every pair of participants in a room talks directly to
  each other
- ⚡ Automatic connection when possible: tries a direct UDP path first
  (local network, UPnP router port mapping, STUN-discovered public
  address), then a free public relay as a second attempt — no manual
  copy/paste needed when either one works
- 🚫 No infrastructure of our own: no backend, no database, no accounts —
  see [How it works](#how-it-works) for the two free, public, neutral
  services involved in establishing connections (never in the actual
  video/audio)
- 🎯 Minimal by design: rooms, screen/audio sharing, grid/focus — no chat,
  no accounts, no recording

## Why this exists

Discord's screen streaming stopped working reliably for users in Brazil.
This project replaces that use case — a group of people watching each
other's screens, like a Discord voice channel with video — without
depending on any third-party service or server. Every participant just
runs the same app locally.

## How it works

Joining a room used to mean pasting a full WebRTC offer (containing an
entire SDP) for every single pairing. Rooms work differently: the code only
carries the **rendezvous point** of whoever generated it (a random session
id plus a handful of network addresses) — no SDP at all, so it's short and
generated instantly, no ICE gathering wait.

1. Someone clicks **Criar sala** — their app opens a listening "rendezvous"
   (local network addresses, a UPnP-mapped router port, and their
   STUN-discovered public address) and encodes it into a small, optionally
   passphrase-protected **room code**.
2. That code is shared with anyone who should join, through any side
   channel (WhatsApp, chat, email, etc).
3. Each person who pastes the code and clicks **Entrar** sends a small
   `join` message to that rendezvous — delivered automatically whenever the
   network allows (direct UDP first, a free public relay,
   [ntfy.sh](https://ntfy.sh), as a fallback in parallel).
4. Whoever receives that `join` replies with the room's current roster and
   introduces the newcomer to everyone else already there. From that point
   on, **every pair of participants talks directly to each other** — the
   person who answered `join` was only ever a matchmaker for that one
   moment, never a relay for the mesh that forms afterward. Any current
   member of the room can hand out their own current room code to invite
   more people, not just whoever created it first.
5. Starting to share your screen (the bottom bar's share button) sends your
   video/audio directly to every other connection in the mesh — no new code
   to generate or exchange, and no code re-entry needed for people already
   in the room.

Two free, public, neutral third-party services are involved in setting up
connections — never in the actual video/audio, which always flows directly
between peers over WebRTC:

- **Google's public STUN server** (`stun.l.google.com:19302`), used to help
  each participant discover their own public IP/port for NAT traversal.
- **[ntfy.sh](https://ntfy.sh)**, a free and open-source pub/sub-over-HTTP
  service (self-hostable, same code you could run yourself), used only as
  a best-effort relay for the small signaling messages described above
  (room join, and the per-pair WebRTC offer/answer/ICE candidates). If
  you'd rather this app never talk to it at all, it's only ever used
  alongside direct UDP — either one failing just means the room can't form
  that particular connection, everything else keeps working.

### Code encryption (optional)

The room code is base64, not encryption by default — anyone who gets a copy
of it can attempt to join, since it embeds your rendezvous IP/port in plain
text. Both "Criar sala" and "Entrar em sala" have an optional passphrase
field: if set, the code is encrypted with AES-GCM (key derived via PBKDF2,
Web Crypto API, no dependencies) before being base64-encoded, and the same
passphrase is required to decode it on the other end. This only adds real
protection if the passphrase is agreed through a different channel than the
one used to send the code (e.g. code over chat, passphrase said out loud on
a call). Leaving the passphrase blank keeps the previous plain behavior.

### Per-app audio capture (Windows only)

The audio source picker in the share popover has a "Specific process"
option that lets you include only one running app's audio, or exclude one
app from an otherwise full system-audio share — e.g. share your game or
music but keep a Discord voice call out of the stream, without routing
anything to a separate audio device manually. Picking this option
automatically switches to "exclude" mode and auto-selects any running app
whose window title ends in "Discord" (falling back to just the first app in
the list if none matches) — you can always change it manually afterward.

This uses WASAPI's Process Loopback Capture (`AUDIOCLIENT_ACTIVATION_TYPE_
PROCESS_LOOPBACK`, Windows 10 2004+), the same API OBS Studio uses for its
"Application Audio Capture" source. It isn't exposed by Chromium/Electron's
JS APIs, so it's implemented as a small native addon
(`native/audio-loopback/`, C++/N-API) that captures raw PCM for a target
process (and its child processes) and streams it to the renderer, where a
Web Audio `AudioWorklet` turns it into a real `MediaStreamTrack` that gets
added to the share alongside the video. Windows-only — on macOS and Linux
this option simply doesn't appear.

Plain "system audio" also uses this same native addon on Windows (targeting
this app's own process in exclude mode) instead of Electron's built-in
loopback, so it can be switched to/from at any point during a share — not
just chosen once at the very start — and so it never includes Sinal P2P's
own output (preventing the echo a room-mate's voice would otherwise cause).
Since the audio no longer needs to ride along with the screen picker, the
monitor dropdown also stays usable with "system audio" selected on Windows.
On macOS/Linux (no native addon), "system audio" keeps the older behavior:
tied to `getDisplayMedia`'s one-time OS picker grant, not switchable
mid-share, and not self-excluding.

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

- **Windows**: `Sinal-P2P-<version>-win.exe` (portable, no install needed —
  just run it)
- **Linux**: `Sinal-P2P-<version>-linux-x64.tar.gz` (extract and run the
  `Sinal P2P` binary inside)

A macOS build isn't published yet — `electron-builder` refuses to build for
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

### Creating a room

1. On the home screen, fill in your name and (optionally) a passphrase
   under **Criar sala**, then click it.
2. In the room, click **Copiar código da sala** and send that code to
   whoever you want to invite, through any channel (WhatsApp, chat, etc).
   Anyone can join with it for as long as your app stays open — and once
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
   **Entrar**.
2. You'll see the grid of whoever's currently sharing (or an empty state if
   nobody is yet) and a participants list of everyone in the room (toggle it
   with the people icon on the right of the bottom dock). Hover a tile and
   click the pin icon to focus it full-size; hover the focused tile and
   click "unpin" to go back to the grid.
3. Share your own screen the same way described above whenever you want to.

## Limitations

- **No TURN server**: this only affects the actual video/audio stream, not
  the signaling relay above — if two participants are both behind
  restrictive/symmetric NATs (e.g. some corporate networks), the direct
  WebRTC connection between just that pair may fail regardless of how the
  room code was exchanged. Works reliably on normal home networks.
- **Automatic connection is best-effort**: it depends on things outside the
  app's control (router UPnP support, ISP/NAT behavior, ntfy.sh being
  reachable) and can simply not work on some networks — there's currently
  no manual fallback for room signaling (unlike the old one-off offer/
  answer flow), since a room's mesh isn't a single pairing that a human can
  paste codes for.
- **No SFU / bandwidth budgeting**: since every pair of participants talks
  directly (mesh), a room with several people sharing their screens at the
  same time means each of them is uploading directly to every other
  participant — there's a per-connection bitrate cap, but nothing that
  budgets total bandwidth across a room with many simultaneous
  broadcasters.
- **No native system-audio loopback on Linux**: `getDisplayMedia` loopback
  audio is only supported by Chromium/Electron on Windows and macOS. On
  Linux the app instead lets you manually pick a PulseAudio/PipeWire
  monitor source as a regular input device; if your distro doesn't expose
  one, only video is captured.
- Intentionally minimal: no chat, no recording, no accounts, just rooms +
  screen/audio sharing.

## Known issues

Unlike [Limitations](#limitations) above (things that are inherent to the
architecture), these are real bugs/rough edges that just haven't been fixed
yet:

- **ntfy.sh rate limiting**: the free public relay used for automatic room
  signaling (see [How it works](#how-it-works)) rate-limits by IP address,
  not by app — if a lot of signaling traffic comes from the same public IP
  in a short window (e.g. repeated join attempts while debugging a
  connection issue), it can start rejecting requests with HTTP 429 for a
  while. This is rare in normal one-off usage, but can show up during heavy
  testing, and can also affect multiple unrelated people sharing the same
  IP behind CGNAT. When it happens, automatic signaling degrades to just the
  direct UDP path (still often enough on its own); there's no in-app
  indicator of this yet.
- **Screen/audio capture is still rough on Linux**: unlike Windows/macOS,
  there's no single API Electron can rely on across distros — behavior
  varies by desktop environment and audio server (PulseAudio/PipeWire vs.
  something else), and both screen picking and audio-source selection are
  more likely to need manual fiddling or simply not work on some setups.
  Not yet systematically tested across distros.
- **Minimizing the window can freeze the share, and sometimes the OS/Chrome
  itself**: when the broadcaster minimizes the app (or another window fully
  covers it), the video reliably freezes for viewers until the window is
  restored — confirmed via WebRTC stats that frames keep arriving but stop
  being decoded while minimized. On top of that, minimizing has also been
  observed to freeze the whole app, or possibly Windows/Chrome itself, in
  ways not yet root-caused. Several fixes were already tried (disabling
  Chromium's window-occlusion throttling, disabling hardware acceleration,
  forcing process priority) — none of them helped, so the actual cause is
  still unidentified. Avoid minimizing the window while sharing for now;
  covering it with another window instead of minimizing may also trigger
  the video-freeze part of this.

## License

Licensed under the [GNU General Public License v3.0](LICENSE).
