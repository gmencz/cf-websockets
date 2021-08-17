export {}

declare global {
  interface WebSocket {
    accept(): void
  }

  class WebSocketPair {
    0: WebSocket
    1: WebSocket
  }

  interface ResponseInit {
    webSocket?: WebSocket
  }
}
