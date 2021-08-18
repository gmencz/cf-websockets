import type { Request as IttyRequest } from 'itty-router'

export interface Env {
  rooms: DurableObjectNamespace
  limiters: DurableObjectNamespace

  AUTH_JWT_ALG: 'HS256'
  AUTH_JWT_SECRET: string
}

export type RoutedRequest = Request & IttyRequest

export type RoutedRequestHandler = (
  request: RoutedRequest,
  env: Env,
) => Response | Promise<Response>

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
