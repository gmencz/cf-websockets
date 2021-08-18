import type { RoutedRequestHandler } from '../types'

let notFoundHandler: RoutedRequestHandler = () => {
  return new Response('Not found', { status: 404 })
}

function json(data: any, init: number | ResponseInit = {}): Response {
  if (typeof init === 'number') {
    init = { status: init }
  }

  let headers = new Headers(init.headers)
  if (!headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json; charset=utf-8')
  }

  return new Response(JSON.stringify(data), { ...init, headers })
}

export { notFoundHandler, json }
