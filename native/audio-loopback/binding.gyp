{
  "targets": [
    {
      "target_name": "audio_loopback",
      "conditions": [
        ["OS=='win'", {
          "sources": ["src/process_loopback.cpp"],
          "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"],
          "libraries": ["ole32.lib", "oleaut32.lib", "mmdevapi.lib", "avrt.lib"],
          "msvs_settings": {
            "VCCLCompilerTool": {
              "ExceptionHandling": 1,
              "AdditionalOptions": ["/std:c++17"]
            }
          }
        }, {
          "sources": ["src/unsupported.cpp"]
        }]
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "dependencies": [
        "<!(node -p \"require('node-addon-api').gyp\")"
      ]
    }
  ]
}
