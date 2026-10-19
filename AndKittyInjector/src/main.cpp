name: Build AndKittyInjector

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]
  workflow_dispatch:

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
    - name: Checkout repository
      uses: actions/checkout@v4
      with:
        submodules: recursive

    - name: Setup Android NDK
      uses: nttld/setup-ndk@v1
      id: setup-ndk
      with:
        ndk-version: r25c
        add-to-path: true

    - name: Build with ndk-build
      run: |
        ndk-build \
          NDK_PROJECT_PATH=${{ github.workspace }} \
          APP_BUILD_SCRIPT=${{ github.workspace }}/Android.mk \
          NDK_APPLICATION_MK=${{ github.workspace }}/Application.mk \
          NDK_OUT=${{ github.workspace }}/obj \
          NDK_LIBS_OUT=${{ github.workspace }}/libs \
          APP_ABI=arm64-v8a
      env:
        ANDROID_NDK_HOME: ${{ steps.setup-ndk.outputs.ndk-path }}

    - name: Upload Artifact
      uses: actions/upload-artifact@v4
      with:
        name: AndKittyInjector-arm64
        path: libs/arm64-v8a/AndKittyInjector
        if-no-files-found: error
