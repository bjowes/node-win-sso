{
  "targets": [
    {
      "target_name": "win-sso",
      "cflags!": [ "-fno-exceptions" ],
      "cflags_cc!": [ "-fno-exceptions" ],
      "sources": [ "src/node-addon/secur32.cc" ],
      "libraries": [
        "-lsecur32"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      'dependencies': [
        "<!(node -p \"require('node-addon-api').gyp\")"
      ],
      'defines': [ 'NAPI_DISABLE_CPP_EXCEPTIONS' ],
    }
  ]
}