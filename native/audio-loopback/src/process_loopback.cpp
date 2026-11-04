// Captura de áudio por processo no Windows via WASAPI "Process Loopback"
// (AUDIOCLIENT_ACTIVATION_TYPE_PROCESS_LOOPBACK, Windows 10 2004+/build 20348).
// É a mesma API que ferramentas como o OBS usam na fonte "Application Audio
// Capture": em vez de ligar/desligar dispositivos inteiros, ela deixa
// incluir (ou excluir) só o áudio de uma árvore de processos específica.
//
// Não existe equivalente disso em JS/Web Audio/Electron — por isso este
// módulo nativo. Referência: amostra "ApplicationLoopback" da Microsoft
// (Windows-classic-samples/Samples/ApplicationLoopback).

#include <napi.h>
#include <windows.h>
#include <objbase.h>
#include <objidl.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <audioclientactivationparams.h>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

// ---------- listagem de janelas/processos ----------

struct ProcessEntry {
  DWORD pid;
  std::wstring title;
};

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
  if (!IsWindowVisible(hwnd)) return TRUE;
  if (GetWindow(hwnd, GW_OWNER) != nullptr) return TRUE;  // ignora janelas "filhas"/popups

  int length = GetWindowTextLengthW(hwnd);
  if (length == 0) return TRUE;

  std::vector<wchar_t> buffer(static_cast<size_t>(length) + 1);
  GetWindowTextW(hwnd, buffer.data(), length + 1);

  DWORD pid = 0;
  GetWindowThreadProcessId(hwnd, &pid);
  if (pid == 0) return TRUE;

  auto* list = reinterpret_cast<std::vector<ProcessEntry>*>(lParam);
  list->push_back({pid, std::wstring(buffer.data())});
  return TRUE;
}

std::string WideToUtf8(const std::wstring& wide) {
  if (wide.empty()) return std::string();
  int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
  if (size <= 0) return std::string();
  std::string utf8(static_cast<size_t>(size) - 1, 0);
  WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, utf8.data(), size, nullptr, nullptr);
  return utf8;
}

Napi::Value ListProcesses(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  std::vector<ProcessEntry> entries;
  EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&entries));

  std::map<DWORD, std::wstring> byPid;
  for (auto& entry : entries) {
    if (byPid.find(entry.pid) == byPid.end()) byPid[entry.pid] = entry.title;
  }

  Napi::Array result = Napi::Array::New(env, byPid.size());
  uint32_t i = 0;
  for (auto& kv : byPid) {
    Napi::Object obj = Napi::Object::New(env);
    obj.Set("pid", Napi::Number::New(env, static_cast<double>(kv.first)));
    obj.Set("title", Napi::String::New(env, WideToUtf8(kv.second)));
    result[i++] = obj;
  }
  return result;
}

// ---------- captura via Process Loopback ----------

// ActivateAudioInterfaceAsync exige que o completion handler seja "agile"
// (chamável de qualquer apartment COM) — sem isso, a chamada falha síncrona
// com E_ILLEGAL_METHOD_CALL (0x8000000E). Responder S_OK para IAgileObject
// (interface marcadora, sem métodos próprios) resolve isso; o IMarshal
// agregado via CoCreateFreeThreadedMarshaler fica como segunda garantia,
// já que é o mecanismo equivalente ao FtmBase do WRL usado na amostra oficial
// da Microsoft para esta mesma API.
class ActivateCompletionHandler : public IActivateAudioInterfaceCompletionHandler {
 public:
  ActivateCompletionHandler() : refCount_(1) {
    event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    CoCreateFreeThreadedMarshaler(static_cast<IActivateAudioInterfaceCompletionHandler*>(this), &marshaler_);
  }

  ~ActivateCompletionHandler() {
    if (marshaler_) marshaler_->Release();
    if (event_) CloseHandle(event_);
  }

  HANDLE Event() const { return event_; }

  STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
    if (riid == __uuidof(IUnknown) || riid == __uuidof(IActivateAudioInterfaceCompletionHandler)) {
      *ppv = static_cast<IActivateAudioInterfaceCompletionHandler*>(this);
      AddRef();
      return S_OK;
    }
    if (riid == __uuidof(IAgileObject)) {
      *ppv = static_cast<IActivateAudioInterfaceCompletionHandler*>(this);
      AddRef();
      return S_OK;
    }
    if (riid == __uuidof(IMarshal) && marshaler_) {
      return marshaler_->QueryInterface(riid, ppv);
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
  }

  STDMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&refCount_); }

  STDMETHODIMP_(ULONG) Release() override {
    ULONG result = InterlockedDecrement(&refCount_);
    if (result == 0) delete this;
    return result;
  }

  STDMETHODIMP ActivateCompleted(IActivateAudioInterfaceAsyncOperation* /*operation*/) override {
    SetEvent(event_);
    return S_OK;
  }

 private:
  LONG refCount_;
  HANDLE event_;
  IUnknown* marshaler_ = nullptr;
};

struct AudioChunk {
  std::vector<float> samples;
  UINT32 channels = 0;
  UINT32 sampleRate = 0;
  std::string error;  // vazio = chunk normal; não-vazio = falha, encerra a sessão
};

struct CaptureSession {
  DWORD pid = 0;
  bool exclude = false;
  std::atomic<bool> stopFlag{false};
  std::thread worker;
  Napi::ThreadSafeFunction tsfn;
};

void EmitError(CaptureSession* session, const char* stage, HRESULT hr) {
  char message[256];
  snprintf(message, sizeof(message), "%s falhou (hr=0x%08lX)", stage, hr);
  fprintf(stderr, "[audio_loopback] %s\n", message);

  auto* chunk = new AudioChunk();
  chunk->error = message;
  session->tsfn.BlockingCall(chunk, [](Napi::Env env, Napi::Function jsCallback, AudioChunk* c) {
    jsCallback.Call({Napi::String::New(env, c->error), env.Null(), env.Null(), env.Null()});
    delete c;
  });
}

// Uma sessão de Process Loopback já ativada e pronta, mais as amostras já
// lidas mas ainda não repassadas adiante e o timestamp do último pacote
// (usado como chute inicial pra alinhar duas sessões, ver SelfSubtractor).
struct AudioEndpoint {
  IAudioClient* audioClient = nullptr;
  IAudioCaptureClient* captureClient = nullptr;
  HANDLE event = nullptr;
  std::vector<float> pending;  // amostras intercaladas por canal, na ordem em que chegaram
  int64_t framesRead = 0;      // quadros lidos desde o início da sessão
  int64_t packetsRead = 0;
  UINT64 lastQpc = 0;          // timestamp (100ns) do 1º quadro do último pacote com timestamp válido
  int64_t lastQpcFrame = 0;    // índice (em framesRead) desse quadro
};

// Ativa uma sessão de Process Loopback (include ou exclude, pro processo
// `targetPid`) e já chama Start() nela. `label` só serve pra identificar o
// estágio numa mensagem de erro, caso algo falhe.
bool ActivateEndpoint(CaptureSession* session, DWORD targetPid, bool excludeMode, const WAVEFORMATEX& format,
                       AudioEndpoint* out, const char* label) {
  AUDIOCLIENT_ACTIVATION_PARAMS activationParams = {};
  activationParams.ActivationType = AUDIOCLIENT_ACTIVATION_TYPE_PROCESS_LOOPBACK;
  activationParams.ProcessLoopbackParams.TargetProcessId = targetPid;
  activationParams.ProcessLoopbackParams.ProcessLoopbackMode =
      excludeMode ? PROCESS_LOOPBACK_MODE_EXCLUDE_TARGET_PROCESS_TREE
                  : PROCESS_LOOPBACK_MODE_INCLUDE_TARGET_PROCESS_TREE;

  PROPVARIANT activateParams;
  PropVariantInit(&activateParams);
  activateParams.vt = VT_BLOB;
  activateParams.blob.cbSize = sizeof(activationParams);
  activateParams.blob.pBlobData = reinterpret_cast<BYTE*>(&activationParams);

  auto* handler = new ActivateCompletionHandler();
  IActivateAudioInterfaceAsyncOperation* asyncOp = nullptr;

  HRESULT hr = ActivateAudioInterfaceAsync(VIRTUAL_AUDIO_DEVICE_PROCESS_LOOPBACK, __uuidof(IAudioClient),
                                            &activateParams, handler, &asyncOp);
  if (FAILED(hr)) {
    EmitError(session, label, hr);
    handler->Release();
    if (asyncOp) asyncOp->Release();
    return false;
  }

  WaitForSingleObject(handler->Event(), INFINITE);

  HRESULT activateResult = S_OK;
  IUnknown* punkAudioInterface = nullptr;
  hr = asyncOp->GetActivateResult(&activateResult, &punkAudioInterface);
  asyncOp->Release();
  handler->Release();

  if (FAILED(hr) || FAILED(activateResult) || !punkAudioInterface) {
    EmitError(session, label, FAILED(hr) ? hr : activateResult);
    return false;
  }

  IAudioClient* audioClient = nullptr;
  hr = punkAudioInterface->QueryInterface(__uuidof(IAudioClient), reinterpret_cast<void**>(&audioClient));
  punkAudioInterface->Release();
  if (FAILED(hr) || !audioClient) {
    EmitError(session, label, hr);
    return false;
  }

  const REFERENCE_TIME bufferDuration = 20 * 10000;  // 20ms, em unidades de 100ns
  hr = audioClient->Initialize(AUDCLNT_SHAREMODE_SHARED,
                                AUDCLNT_STREAMFLAGS_LOOPBACK | AUDCLNT_STREAMFLAGS_EVENTCALLBACK, bufferDuration, 0,
                                &format, nullptr);
  if (FAILED(hr)) {
    EmitError(session, label, hr);
    audioClient->Release();
    return false;
  }

  HANDLE captureEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
  audioClient->SetEventHandle(captureEvent);

  IAudioCaptureClient* captureClient = nullptr;
  hr = audioClient->GetService(__uuidof(IAudioCaptureClient), reinterpret_cast<void**>(&captureClient));
  if (FAILED(hr) || !captureClient) {
    EmitError(session, label, hr);
    CloseHandle(captureEvent);
    audioClient->Release();
    return false;
  }

  hr = audioClient->Start();
  if (FAILED(hr)) {
    EmitError(session, label, hr);
    CloseHandle(captureEvent);
    captureClient->Release();
    audioClient->Release();
    return false;
  }

  out->audioClient = audioClient;
  out->captureClient = captureClient;
  out->event = captureEvent;
  return true;
}

void ReleaseEndpoint(AudioEndpoint* ep) {
  if (ep->audioClient) ep->audioClient->Stop();
  if (ep->captureClient) ep->captureClient->Release();
  if (ep->audioClient) ep->audioClient->Release();
  if (ep->event) CloseHandle(ep->event);
  *ep = AudioEndpoint();
}

// Drena todos os pacotes já prontos de `ep` pra fila pendente dele (amostras
// intercaladas por canal, silêncio explícito quando a flag SILENT vem
// marcada).
void DrainEndpoint(AudioEndpoint* ep, UINT32 channels) {
  UINT32 packetLength = 0;
  ep->captureClient->GetNextPacketSize(&packetLength);
  while (packetLength != 0) {
    BYTE* data = nullptr;
    UINT32 numFrames = 0;
    DWORD flags = 0;
    UINT64 qpc = 0;
    HRESULT hr = ep->captureClient->GetBuffer(&data, &numFrames, &flags, nullptr, &qpc);
    if (FAILED(hr)) break;

    if (qpc != 0 && !(flags & AUDCLNT_BUFFERFLAGS_TIMESTAMP_ERROR)) {
      ep->lastQpc = qpc;
      ep->lastQpcFrame = ep->framesRead;
    }
    ep->framesRead += numFrames;
    ep->packetsRead++;

    size_t base = ep->pending.size();
    ep->pending.resize(base + static_cast<size_t>(numFrames) * channels);
    if (flags & AUDCLNT_BUFFERFLAGS_SILENT) {
      std::fill(ep->pending.begin() + base, ep->pending.end(), 0.0f);
    } else {
      memcpy(ep->pending.data() + base, data, static_cast<size_t>(numFrames) * channels * sizeof(float));
    }

    ep->captureClient->ReleaseBuffer(numFrames);
    ep->captureClient->GetNextPacketSize(&packetLength);
  }
}

void CaptureThreadProc(CaptureSession* session) {
  CoInitializeEx(nullptr, COINIT_MULTITHREADED);

  WAVEFORMATEX format = {};
  format.wFormatTag = WAVE_FORMAT_IEEE_FLOAT;
  format.nChannels = 2;
  format.nSamplesPerSec = 48000;
  format.wBitsPerSample = 32;
  format.nBlockAlign = static_cast<WORD>(format.nChannels * format.wBitsPerSample / 8);
  format.nAvgBytesPerSec = format.nSamplesPerSec * format.nBlockAlign;
  format.cbSize = 0;

  // pid=0 é o sentinela de "áudio do sistema inteiro, exceto este próprio
  // app" (ver comentário em StartCapture) — nesse caso o alvo da exclusão é
  // o próprio processo, e uma única sessão já basta: o WASAPI já exclui o
  // alvo no nível do SO, sem precisar da subtração de DualCaptureThreadProc.
  DWORD targetPid = session->pid == 0 ? GetCurrentProcessId() : session->pid;

  AudioEndpoint ep;
  if (!ActivateEndpoint(session, targetPid, session->exclude, format, &ep, "ActivateAudioInterfaceAsync")) {
    session->tsfn.Release();
    CoUninitialize();
    return;
  }

  while (!session->stopFlag.load()) {
    if (WaitForSingleObject(ep.event, 500) != WAIT_OBJECT_0) continue;

    DrainEndpoint(&ep, format.nChannels);
    if (ep.pending.empty()) continue;

    auto* chunk = new AudioChunk();
    chunk->channels = format.nChannels;
    chunk->sampleRate = format.nSamplesPerSec;
    chunk->samples = std::move(ep.pending);
    ep.pending.clear();

    session->tsfn.BlockingCall(chunk, [](Napi::Env env, Napi::Function jsCallback, AudioChunk* c) {
      Napi::Float32Array arr = Napi::Float32Array::New(env, c->samples.size());
      memcpy(arr.Data(), c->samples.data(), c->samples.size() * sizeof(float));
      jsCallback.Call({env.Null(), arr, Napi::Number::New(env, c->sampleRate), Napi::Number::New(env, c->channels)});
      delete c;
    });
  }

  ReleaseEndpoint(&ep);
  session->tsfn.Release();
  CoUninitialize();
}

// Produto escalar com acumuladores independentes (sem /fp:fast o compilador
// não vetoriza uma soma em sequência; assim pelo menos as somas não ficam
// esperando uma pela outra). É o laço quente da busca de alinhamento.
float Dot(const float* a, const float* b, size_t n) {
  float s0 = 0, s1 = 0, s2 = 0, s3 = 0, s4 = 0, s5 = 0, s6 = 0, s7 = 0;
  size_t i = 0;
  for (; i + 8 <= n; i += 8) {
    s0 += a[i] * b[i];
    s1 += a[i + 1] * b[i + 1];
    s2 += a[i + 2] * b[i + 2];
    s3 += a[i + 3] * b[i + 3];
    s4 += a[i + 4] * b[i + 4];
    s5 += a[i + 5] * b[i + 5];
    s6 += a[i + 6] * b[i + 6];
    s7 += a[i + 7] * b[i + 7];
  }
  for (; i < n; i++) s0 += a[i] * b[i];
  return ((s0 + s1) + (s2 + s3)) + ((s4 + s5) + (s6 + s7));
}

// Tira de uma captura "primary" (tudo exceto o app escolhido) o áudio deste
// próprio app, que chega separado por uma captura "self" — ver
// DualCaptureThreadProc pro porquê das duas.
//
// O difícil é o alinhamento. As duas sessões do WASAPI são independentes:
// cada uma começa a entregar pacotes num ciclo diferente do motor de áudio,
// então o quadro N de uma não é o quadro N da outra. A diferença (`lag_`) é
// sorteada a cada início de captura (medido: 0, +441, -480, -960 quadros) e
// costuma ficar fixa (inclusive com o app parando e voltando a tocar som),
// mas pode pular um pacote quando o Windows reconfigura o áudio (medido
// quando outro programa começou a tocar). Subtrair com o lag errado, nem
// que por 1 quadro, não cancela nada: soma uma cópia atrasada do som
// (medido: eco ~3 dB MAIS ALTO que o original — era o bug da versão
// anterior, que alinhava pela ordem de chegada dos pacotes e acertava ou
// errava conforme a sorte de cada início). Com o lag certo o cancelamento é
// exato, bit a bit, inclusive com reamostragem e com o volume do app mudado
// no mixer do Windows (o ganho continua 1).
//
// Os timestamps (QPC) dos pacotes erram o lag por centenas de quadros, então
// só servem de centro pra busca: o lag de verdade é o deslocamento em que o
// áudio do self aparece dentro do primary (correlação cruzada normalizada,
// testando todo deslocamento num raio de 50ms em volta do chute). Só passa
// a subtrair depois de achar um encaixe com ganho ~1 ("travado"), e confere
// o encaixe a cada 100ms enquanto o self tiver som; se deixar de bater, para
// de subtrair na hora e volta a procurar. Sem encaixe confirmado, o primary
// sai sem subtração nenhuma — no pior caso o eco simples, nunca o dobrado.
class SelfSubtractor {
 public:
  SelfSubtractor(UINT32 channels, UINT32 sampleRate)
      : ch_(channels),
        window_(sampleRate / 10),
        radius_(sampleRate / 20),
        maxHold_(sampleRate * 3 / 100),
        checkEvery_(sampleRate / 10),
        keepFrames_(sampleRate),
        trimSlack_(sampleRate / 2) {}

  void PushPrimary(const std::vector<float>& samples) { Append(&primary_, samples); }
  void PushSelf(const std::vector<float>& samples) { Append(&self_, samples); }

  // Chute do lag vindo dos timestamps (centro da busca).
  void SetLagHint(int64_t hint) {
    hint_ = hint;
    hasHint_ = true;
  }

  // Monta em `out` o próximo trecho pronto pra sair (primary menos o self
  // alinhado). Retorna false se ainda não tem nada.
  bool Pull(std::vector<float>* out) {
    MaybeCheckAlignment();

    int64_t primaryEnd = End(primary_);
    int64_t selfEnd = End(self_);
    int64_t emitTo = primaryEnd;
    if (locked_) {
      // O quadro p precisa de self[p - lag]. Se o pacote correspondente do
      // self ainda não chegou (as duas sessões não acordam juntas), segura
      // um pouco; mas não pra sempre, caso o self pare de entregar.
      emitTo = (std::max)((std::min)(primaryEnd, selfEnd + lag_), primaryEnd - maxHold_);
    }
    if (emitTo <= emitNext_) return false;

    size_t frames = static_cast<size_t>(emitTo - emitNext_);
    out->resize(frames * ch_);
    for (size_t i = 0; i < frames; i++) {
      int64_t frame = emitNext_ + static_cast<int64_t>(i);
      int64_t selfFrame = frame - lag_;
      bool subtract = locked_ && selfFrame >= self_.base && selfFrame < selfEnd;
      const float* a = &primary_.data[static_cast<size_t>(frame - primary_.base) * ch_];
      const float* b = subtract ? &self_.data[static_cast<size_t>(selfFrame - self_.base) * ch_] : nullptr;
      for (UINT32 c = 0; c < ch_; c++) {
        float value = b ? a[c] - b[c] : a[c];
        if (value > 1.0f) value = 1.0f;
        if (value < -1.0f) value = -1.0f;
        (*out)[i * ch_ + c] = value;
      }
    }
    emitNext_ = emitTo;

    // Guarda um histórico pra busca/conferência do alinhamento; o resto vai
    // embora (em blocos, pra não mover a memória toda a cada pacote).
    TrimBefore(&primary_, (std::min)(emitNext_, primaryEnd - keepFrames_));
    TrimBefore(&self_, selfEnd - keepFrames_);
    return true;
  }

 private:
  struct Track {
    std::vector<float> data;  // quadros [base, base + data.size() / ch_), intercalados por canal
    int64_t base = 0;
  };

  static constexpr float kMinSelfEnergy = 1e-7f;  // por quadro (mono somado): abaixo disso o self está em silêncio

  int64_t End(const Track& t) const { return t.base + static_cast<int64_t>(t.data.size() / ch_); }

  void Append(Track* t, const std::vector<float>& samples) { t->data.insert(t->data.end(), samples.begin(), samples.end()); }

  void TrimBefore(Track* t, int64_t frame) {
    if (frame - t->base < trimSlack_) return;
    t->data.erase(t->data.begin(), t->data.begin() + static_cast<size_t>(frame - t->base) * ch_);
    t->base = frame;
  }

  // Copia `count` quadros de `t` a partir de `first`, somando os canais.
  void Mono(const Track& t, int64_t first, size_t count, std::vector<float>* out) const {
    out->resize(count);
    const float* src = &t.data[static_cast<size_t>(first - t.base) * ch_];
    for (size_t i = 0; i < count; i++) {
      float sum = 0;
      for (UINT32 c = 0; c < ch_; c++) sum += src[i * ch_ + c];
      (*out)[i] = sum;
    }
  }

  void MaybeCheckAlignment() {
    int64_t primaryEnd = End(primary_);
    if (primaryEnd < nextCheckAt_) return;

    if (locked_) {
      // Conferência barata: o self ainda aparece com ganho ~1 no lag atual?
      // Se não, para de subtrair na hora (subtrair desalinhado é pior que
      // não subtrair) e volta a procurar.
      double gain = 0;
      if (GainAt(lag_, &gain) && (gain < 0.6 || gain > 1.4)) {
        locked_ = false;
        hasCandidate_ = false;
      }
    }
    if (!locked_) Search();
    nextCheckAt_ = primaryEnd + checkEvery_;
  }

  // Ganho com que self[t - lag] aparece em primary[t] na janela mais
  // recente. Retorna false se ainda não há histórico ou o self está mudo.
  bool GainAt(int64_t lag, double* gain) {
    int64_t windowEnd = (std::min)(End(primary_), End(self_) + lag);
    int64_t windowStart = windowEnd - window_;
    if (windowStart < primary_.base || windowStart - lag < self_.base) return false;

    Mono(primary_, windowStart, static_cast<size_t>(window_), &primaryMono_);
    Mono(self_, windowStart - lag, static_cast<size_t>(window_), &selfMono_);
    double selfEnergy = Dot(selfMono_.data(), selfMono_.data(), selfMono_.size());
    if (selfEnergy < kMinSelfEnergy * window_) return false;
    *gain = Dot(primaryMono_.data(), selfMono_.data(), primaryMono_.size()) / selfEnergy;
    return true;
  }

  // Testa todo lag em [centro - raio, centro + raio] e escolhe o que melhor
  // explica o primary (maior correlação normalizada), se o ganho nele for
  // ~1. Só trava quando duas buscas seguidas concordam: com outro som bem
  // mais alto que o do self tocando junto, um lag errado pode parecer bom
  // por acaso numa janela, mas não no mesmo lugar duas vezes.
  void Search() {
    int64_t center = hasHint_ ? hint_ : lag_;
    int64_t windowEnd = (std::min)(End(primary_), End(self_) + center - radius_);
    int64_t windowStart = windowEnd - window_;
    int64_t selfStart = windowStart - center - radius_;  // self do maior lag testado
    if (windowStart < primary_.base || selfStart < self_.base) return;

    // selfMono_[i + d] é o quadro do self que cai em primary[windowStart + i]
    // com lag = center + radius - d.
    size_t span = static_cast<size_t>(window_ + 2 * radius_);
    Mono(primary_, windowStart, static_cast<size_t>(window_), &primaryMono_);
    Mono(self_, selfStart, span, &selfMono_);

    size_t n = static_cast<size_t>(window_);
    double selfEnergy = Dot(selfMono_.data(), selfMono_.data(), n);
    double bestScore = 0, bestEnergy = 0, bestDot = 0;
    int64_t bestD = -1;
    for (size_t d = 0; d <= static_cast<size_t>(2 * radius_); d++) {
      if (d > 0) {
        double out = selfMono_[d - 1], in = selfMono_[d - 1 + n];
        selfEnergy += in * in - out * out;
      }
      if (selfEnergy < kMinSelfEnergy * window_) continue;
      double dot = Dot(primaryMono_.data(), selfMono_.data() + d, n);
      double score = dot / std::sqrt(selfEnergy);
      if (score > bestScore) {
        bestScore = score;
        bestEnergy = selfEnergy;
        bestDot = dot;
        bestD = static_cast<int64_t>(d);
      }
    }
    if (bestD < 0) return;  // self mudo: nada a decidir (nem a subtrair)

    double gain = bestDot / bestEnergy;
    if (gain < 0.75 || gain > 1.33) {
      hasCandidate_ = false;
      return;
    }
    int64_t lag = center + radius_ - bestD;
    if (hasCandidate_ && candidate_ == lag) {
      lag_ = lag;
      locked_ = true;
    }
    candidate_ = lag;
    hasCandidate_ = true;
  }

  const UINT32 ch_;
  const int64_t window_;      // tamanho da janela de correlação (100ms)
  const int64_t radius_;      // raio da busca em volta do chute (50ms)
  const int64_t maxHold_;     // máximo que segura o primary esperando o self (30ms)
  const int64_t checkEvery_;  // intervalo entre conferências/buscas do encaixe (100ms)
  const int64_t keepFrames_;  // histórico guardado de cada captura (1s)
  const int64_t trimSlack_;   // só apaga histórico em blocos desse tamanho (500ms)

  Track primary_;
  Track self_;
  int64_t emitNext_ = 0;  // próximo quadro do primary a sair
  int64_t lag_ = 0;       // primary[t] contém self[t - lag_]
  bool locked_ = false;   // lag_ confirmado pela correlação: só então subtrai
  int64_t candidate_ = 0;  // lag achado pela última busca, esperando confirmação
  bool hasCandidate_ = false;
  int64_t hint_ = 0;
  bool hasHint_ = false;
  int64_t nextCheckAt_ = 0;
  std::vector<float> primaryMono_;
  std::vector<float> selfMono_;
};

// Modo "excluir": além de excluir o processo escolhido na UI (ex: Discord),
// também precisa tirar o áudio deste PRÓPRIO app da captura — sem isso, a
// voz/som de quem você está assistindo na sala (que sai pelos seus
// alto-falantes através do Sinal P2P) volta a ser capturada e retransmitida,
// criando eco pra quem está do outro lado. A API do Windows só aceita UM
// processo-alvo por ativação (`TargetProcessId` é um DWORD só, não uma
// lista) — não tem como excluir dois processos numa sessão de captura só.
//
// Por isso aqui rodam DUAS capturas em paralelo: uma "tudo exceto o
// processo escolhido" (mesmo mecanismo de sempre) e outra "só o áudio deste
// próprio app" (via GetCurrentProcessId() — pega a árvore de processos
// inteira do Electron, incluindo o processo de áudio onde o som dos outros
// participantes realmente toca). A segunda é SUBTRAÍDA amostra a amostra da
// primeira antes de mandar pro JS, depois de alinhadas (ver SelfSubtractor)
// — o resultado equivale a excluir os dois processos ao mesmo tempo.
void DualCaptureThreadProc(CaptureSession* session) {
  CoInitializeEx(nullptr, COINIT_MULTITHREADED);

  WAVEFORMATEX format = {};
  format.wFormatTag = WAVE_FORMAT_IEEE_FLOAT;
  format.nChannels = 2;
  format.nSamplesPerSec = 48000;
  format.wBitsPerSample = 32;
  format.nBlockAlign = static_cast<WORD>(format.nChannels * format.wBitsPerSample / 8);
  format.nAvgBytesPerSec = format.nSamplesPerSec * format.nBlockAlign;
  format.cbSize = 0;

  AudioEndpoint primary;  // tudo exceto o processo escolhido na UI
  AudioEndpoint self;     // só o áudio deste próprio app (Sinal P2P)

  bool okPrimary = ActivateEndpoint(session, session->pid, /*excludeMode=*/true, format, &primary,
                                     "ActivateAudioInterfaceAsync (processo escolhido)");
  bool okSelf = okPrimary && ActivateEndpoint(session, GetCurrentProcessId(), /*excludeMode=*/false, format, &self,
                                               "ActivateAudioInterfaceAsync (próprio app)");

  if (!okPrimary || !okSelf) {
    if (okPrimary) ReleaseEndpoint(&primary);
    session->tsfn.Release();
    CoUninitialize();
    return;
  }

  HANDLE events[2] = {primary.event, self.event};
  SelfSubtractor subtractor(format.nChannels, format.nSamplesPerSec);

  while (!session->stopFlag.load()) {
    if (WaitForMultipleObjects(2, events, FALSE, 500) == WAIT_TIMEOUT) continue;

    DrainEndpoint(&primary, format.nChannels);
    DrainEndpoint(&self, format.nChannels);
    subtractor.PushPrimary(primary.pending);
    subtractor.PushSelf(self.pending);
    primary.pending.clear();
    self.pending.clear();

    // Chute do lag pelos timestamps: no mesmo instante, quantos quadros o
    // primary tem a mais que o self. Os primeiros pacotes de cada sessão
    // vêm com timestamps fora do compasso, por isso espera alguns.
    if (primary.packetsRead > 10 && self.packetsRead > 10 && primary.lastQpc && self.lastQpc) {
      double qpcDelta = static_cast<double>(static_cast<int64_t>(primary.lastQpc - self.lastQpc));
      subtractor.SetLagHint((primary.lastQpcFrame - self.lastQpcFrame) -
                            static_cast<int64_t>(std::llround(qpcDelta * format.nSamplesPerSec / 1e7)));
    }

    auto* chunk = new AudioChunk();
    if (!subtractor.Pull(&chunk->samples)) {
      delete chunk;
      continue;
    }
    chunk->channels = format.nChannels;
    chunk->sampleRate = format.nSamplesPerSec;

    session->tsfn.BlockingCall(chunk, [](Napi::Env env, Napi::Function jsCallback, AudioChunk* c) {
      Napi::Float32Array arr = Napi::Float32Array::New(env, c->samples.size());
      memcpy(arr.Data(), c->samples.data(), c->samples.size() * sizeof(float));
      jsCallback.Call({env.Null(), arr, Napi::Number::New(env, c->sampleRate), Napi::Number::New(env, c->channels)});
      delete c;
    });
  }

  ReleaseEndpoint(&primary);
  ReleaseEndpoint(&self);
  session->tsfn.Release();
  CoUninitialize();
}

std::mutex g_sessionsMutex;
std::map<int, CaptureSession*> g_sessions;
int g_nextHandle = 1;

Napi::Value StartCapture(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3 || !info[0].IsNumber() || !info[1].IsBoolean() || !info[2].IsFunction()) {
    Napi::TypeError::New(env, "startCapture(pid, exclude, callback) esperado").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  auto* session = new CaptureSession();
  session->pid = static_cast<DWORD>(info[0].As<Napi::Number>().Uint32Value());
  session->exclude = info[1].As<Napi::Boolean>().Value();
  session->tsfn = Napi::ThreadSafeFunction::New(env, info[2].As<Napi::Function>(), "AudioLoopbackCallback", 0, 1);

  // Excluir um app específico (pid != 0) sempre também tira o eco deste
  // próprio app junto (ver DualCaptureThreadProc) — ninguém que exclui um
  // app específico (ex: Discord) quer que a voz de quem está assistindo na
  // sala volte retransmitida por cima. No modo "incluir só X", isso não é
  // necessário: só o áudio de X já sai, o resto (inclusive este app) já
  // fica de fora naturalmente. E no modo "sistema inteiro, exceto este app"
  // (pid == 0) a exclusão do WASAPI já é o próprio alvo, então uma única
  // captura basta — ver CaptureThreadProc.
  bool useDualCapture = session->exclude && session->pid != 0;
  session->worker = std::thread(useDualCapture ? DualCaptureThreadProc : CaptureThreadProc, session);

  int handle;
  {
    std::lock_guard<std::mutex> lock(g_sessionsMutex);
    handle = g_nextHandle++;
    g_sessions[handle] = session;
  }

  return Napi::Number::New(env, handle);
}

Napi::Value StopCapture(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsNumber()) {
    Napi::TypeError::New(env, "stopCapture(handle) esperado").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  int handle = info[0].As<Napi::Number>().Int32Value();
  CaptureSession* session = nullptr;
  {
    std::lock_guard<std::mutex> lock(g_sessionsMutex);
    auto it = g_sessions.find(handle);
    if (it != g_sessions.end()) {
      session = it->second;
      g_sessions.erase(it);
    }
  }

  if (session) {
    session->stopFlag.store(true);
    if (session->worker.joinable()) session->worker.join();
    delete session;
  }

  return env.Undefined();
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("listProcesses", Napi::Function::New(env, ListProcesses));
  exports.Set("startCapture", Napi::Function::New(env, StartCapture));
  exports.Set("stopCapture", Napi::Function::New(env, StopCapture));
  return exports;
}

}  // namespace

NODE_API_MODULE(audio_loopback, Init)
