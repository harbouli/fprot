# Changelog

All notable changes to this project will be documented in this file.

## 1.1.3 - 2026-09-26

### Fixed

- Reconnect a conversation when either peer restarts or changes networks without waiting for the heartbeat timeout.
- Ignore duplicate and retired handshake packets so an established connection is not replaced repeatedly.
- Allow applications to pause outgoing reconnect attempts while keeping message storage and incoming signaling active through `pauseReconnect()`.
