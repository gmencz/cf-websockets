import type { RoutedRequestHandler } from '../types'

let notFoundHandler: RoutedRequestHandler = () => {
  return new Response('Not found', { status: 404 })
}

export { notFoundHandler }
