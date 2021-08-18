import { Router } from 'itty-router'
import { roomController } from './controllers/room'
import { notFoundHandler } from './utils/responses'
import type { Env } from './types'

let router = Router()

router.all('/rooms/:name', roomController.all).all('*', notFoundHandler)

export { Room } from './durable-objects/room'
export { RateLimiter } from './durable-objects/rate-limiter'

export default {
  async fetch(request: Request, env: Env) {
    try {
      let response = await router.handle(request, env)
      return response
    } catch (error) {
      return new Response(error.message, { status: 500 })
    }
  },
}
