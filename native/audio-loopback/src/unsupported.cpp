// Captura de áudio por processo é uma API específica do Windows (WASAPI
// Process Loopback). Em outras plataformas, expõe as mesmas funções como
// stubs que sinalizam "não suportado", para o lado JS poder detectar isso
// sem precisar de lógica condicional por SO em todo lugar que usa o módulo.
#include <napi.h>

namespace {

Napi::Value ListProcesses(const Napi::CallbackInfo& info) {
  return Napi::Array::New(info.Env(), 0);
}

Napi::Value StartCapture(const Napi::CallbackInfo& info) {
  Napi::Error::New(info.Env(), "Captura de áudio por processo só é suportada no Windows")
      .ThrowAsJavaScriptException();
  return info.Env().Undefined();
}

Napi::Value StopCapture(const Napi::CallbackInfo& info) {
  return info.Env().Undefined();
}

// A política de energia por processo (ver DisableProcessThrottling em
// process_loopback.cpp) só existe no Windows; aqui não há o que fazer.
Napi::Value DisableProcessThrottling(const Napi::CallbackInfo& info) {
  return Napi::Boolean::New(info.Env(), false);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("listProcesses", Napi::Function::New(env, ListProcesses));
  exports.Set("startCapture", Napi::Function::New(env, StartCapture));
  exports.Set("stopCapture", Napi::Function::New(env, StopCapture));
  exports.Set("disableProcessThrottling", Napi::Function::New(env, DisableProcessThrottling));
  return exports;
}

}  // namespace

NODE_API_MODULE(audio_loopback, Init)
