# TapBridge

TapBridge is an Android-to-Windows local PC controller currently being developed as a secure local-network prototype.

It lets an Android phone control a Windows PC through a private Wi-Fi LAN or an offline USB-tether network connection. The project focuses on low-latency mouse control, keyboard input, media controls, and security-conscious local access.

> **Project status:** Development prototype. It is not production-ready and must not be exposed directly to the public internet.

## Current features

- Large laptop-style Android touchpad
- Adaptive pointer movement designed to reduce jitter and improve slow precision
- One-finger cursor movement and tap-to-click
- Two-finger scrolling and right-click gestures
- Long-press drag support
- Keyboard text entry, special keys, and shortcuts
- Windows media controls:
  - Mute
  - Volume up/down
  - Play/pause
  - Previous/next track
- Persisted haptic-feedback preference
- Android biometric app lock
- Fresh biometric confirmation before an offline USB-tether session
- Private Wi-Fi LAN connection mode
- Offline USB-tether connection mode
- Certificate-pinned TLS transport
- One-time runtime pairing-code gate
- Safe held-mouse-button release when a connection ends
- Foreground session heartbeat support

## Architecture

```text
Android TapBridge app
        ↓
Certificate-pinned TLS connection
        ↓
Private Wi-Fi LAN or USB-tether Ethernet link
        ↓
TapBridge Windows agent
        ↓
Windows SendInput API
        ↓
Mouse, keyboard, media, and presentation controls
