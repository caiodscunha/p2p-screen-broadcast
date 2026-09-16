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

#include <atomic>
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

void CaptureThreadProc(CaptureSession* session) {
  CoInitializeEx(nullptr, COINIT_MULTITHREADED);

  AUDIOCLIENT_ACTIVATION_PARAMS activationParams = {};
  activationParams.ActivationType = AUDIOCLIENT_ACTIVATION_TYPE_PROCESS_LOOPBACK;
  activationParams.ProcessLoopbackParams.TargetProcessId = session->pid;
  activationParams.ProcessLoopbackParams.ProcessLoopbackMode =
      session->exclude ? PROCESS_LOOPBACK_MODE_EXCLUDE_TARGET_PROCESS_TREE
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
    EmitError(session, "ActivateAudioInterfaceAsync", hr);
    handler->Release();
    if (asyncOp) asyncOp->Release();
    session->tsfn.Release();
    CoUninitialize();
    return;
  }

  WaitForSingleObject(handler->Event(), INFINITE);

  HRESULT activateResult = S_OK;
  IUnknown* punkAudioInterface = nullptr;
  hr = asyncOp->GetActivateResult(&activateResult, &punkAudioInterface);
  asyncOp->Release();
  handler->Release();

  if (FAILED(hr) || FAILED(activateResult) || !punkAudioInterface) {
    EmitError(session, "GetActivateResult", FAILED(hr) ? hr : activateResult);
    session->tsfn.Release();
    CoUninitialize();
    return;
  }

  IAudioClient* audioClient = nullptr;
  hr = punkAudioInterface->QueryInterface(__uuidof(IAudioClient), reinterpret_cast<void**>(&audioClient));
  punkAudioInterface->Release();

  if (FAILED(hr) || !audioClient) {
    EmitError(session, "QueryInterface(IAudioClient)", hr);
    session->tsfn.Release();
    CoUninitialize();
    return;
  }

  WAVEFORMATEX format = {};
  format.wFormatTag = WAVE_FORMAT_IEEE_FLOAT;
  format.nChannels = 2;
  format.nSamplesPerSec = 48000;
  format.wBitsPerSample = 32;
  format.nBlockAlign = static_cast<WORD>(format.nChannels * format.wBitsPerSample / 8);
  format.nAvgBytesPerSec = format.nSamplesPerSec * format.nBlockAlign;
  format.cbSize = 0;

  const REFERENCE_TIME bufferDuration = 20 * 10000;  // 20ms, em unidades de 100ns

  hr = audioClient->Initialize(AUDCLNT_SHAREMODE_SHARED,
                                AUDCLNT_STREAMFLAGS_LOOPBACK | AUDCLNT_STREAMFLAGS_EVENTCALLBACK, bufferDuration, 0,
                                &format, nullptr);
  if (FAILED(hr)) {
    EmitError(session, "IAudioClient::Initialize", hr);
    audioClient->Release();
    session->tsfn.Release();
    CoUninitialize();
    return;
  }

  HANDLE captureEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
  audioClient->SetEventHandle(captureEvent);

  IAudioCaptureClient* captureClient = nullptr;
  hr = audioClient->GetService(__uuidof(IAudioCaptureClient), reinterpret_cast<void**>(&captureClient));
  if (FAILED(hr) || !captureClient) {
    EmitError(session, "GetService(IAudioCaptureClient)", hr);
    CloseHandle(captureEvent);
    audioClient->Release();
    session->tsfn.Release();
    CoUninitialize();
    return;
  }

  hr = audioClient->Start();
  if (FAILED(hr)) {
    EmitError(session, "IAudioClient::Start", hr);
    CloseHandle(captureEvent);
    captureClient->Release();
    audioClient->Release();
    session->tsfn.Release();
    CoUninitialize();
    return;
  }

  while (!session->stopFlag.load()) {
    if (WaitForSingleObject(captureEvent, 500) != WAIT_OBJECT_0) continue;

    UINT32 packetLength = 0;
    captureClient->GetNextPacketSize(&packetLength);

    while (packetLength != 0 && !session->stopFlag.load()) {
      BYTE* data = nullptr;
      UINT32 numFrames = 0;
      DWORD flags = 0;

      HRESULT hrBuffer = captureClient->GetBuffer(&data, &numFrames, &flags, nullptr, nullptr);
      if (FAILED(hrBuffer)) break;

      if (numFrames > 0) {
        auto* chunk = new AudioChunk();
        chunk->channels = format.nChannels;
        chunk->sampleRate = format.nSamplesPerSec;
        chunk->samples.resize(static_cast<size_t>(numFrames) * format.nChannels);

        if (flags & AUDCLNT_BUFFERFLAGS_SILENT) {
          std::fill(chunk->samples.begin(), chunk->samples.end(), 0.0f);
        } else {
          memcpy(chunk->samples.data(), data, chunk->samples.size() * sizeof(float));
        }

        session->tsfn.BlockingCall(chunk, [](Napi::Env env, Napi::Function jsCallback, AudioChunk* c) {
          Napi::Float32Array arr = Napi::Float32Array::New(env, c->samples.size());
          memcpy(arr.Data(), c->samples.data(), c->samples.size() * sizeof(float));
          jsCallback.Call({env.Null(), arr, Napi::Number::New(env, c->sampleRate), Napi::Number::New(env, c->channels)});
          delete c;
        });
      }

      captureClient->ReleaseBuffer(numFrames);
      captureClient->GetNextPacketSize(&packetLength);
    }
  }

  audioClient->Stop();
  captureClient->Release();
  audioClient->Release();
  CloseHandle(captureEvent);
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

  session->worker = std::thread(CaptureThreadProc, session);

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
