import jwt from '@tsndr/cloudflare-worker-jwt'
import { z } from 'zod'
import { Router } from 'itty-router'
import { RateLimiterClient } from './rate-limiter'
import { json } from '../utils/responses'
import type { Env } from '../types'

enum ErrorCode {
  UNAUTHORIZED = 4001,
  ROOM_AT_MAX_CAPACITY = 4002,
}

enum MessageType {
  PRESENCE_USER_JOINED = 'presence.user_joined',
  PRESENCE_USER_LEFT = 'presence.user_left',
  PRESENCE_INFO = 'presence.info',
  ERROR = 'error',
  MESSAGE = 'message',
  PING = 'ping',
  PONG = 'pong',
}

interface Message {
  type: MessageType
  data?: any
}

type User = z.infer<typeof userSchema> & Record<string, unknown>

type Literal = boolean | null | number | string
type Json = Literal | { [key: string]: Json } | Json[]

interface Session {
  user: User
  quit: boolean
  webSocket: WebSocket
}

let accessTokenSchema = z.object({
  'x-user': z.string(),
})

let userSchema = z
  .object({
    id: z.string(),
  })
  .passthrough()

let literalSchema = z.union([z.string(), z.number(), z.boolean(), z.null()])
let jsonSchema: z.ZodSchema<Json> = z.lazy(() =>
  z.union([literalSchema, z.array(jsonSchema), z.record(jsonSchema)]),
)

let clientDataSchema = z.object({
  type: z.enum([MessageType.PING, MessageType.MESSAGE]),
  data: jsonSchema.optional(),
})

class Room implements DurableObject {
  // `storage` provides access to our durable storage. It provides a simple KV
  // get()/put() interface.
  storage: DurableObjectStorage

  // `env` is our environment bindings.
  env: Env

  // We will put the WebSocket objects for each client, along with some metadata, into
  // `sessions`.
  sessions: Session[]

  // The `router` will route incoming requests to the right handler.
  // Note that all the handlers use arrow functions so that we have the right `this` context.
  router!: Router<Request>

  // The maximum amount of sessions a room can have at any given time.
  static maxCapacity = 100

  constructor(state: DurableObjectState, env: Env) {
    this.storage = state.storage
    this.env = env
    this.sessions = []
    this.initRouter()
  }

  initRouter() {
    this.router = Router()
      .all('/rooms/:name', this.handleWebSocket)
      .get('/rooms/:name/users', this.getUsers)
  }

  getUsers = async (request: Request) => {
    try {
      await this.authorize(request.headers.get('Authorization')?.split(' ')[1])
    } catch (error) {
      return new Response(error.message, {
        status: 401,
      })
    }

    let users = this.sessions.map((s) => s.user)
    return json(users)
  }

  handleWebSocket = async (request: Request) => {
    let upgradeHeader = request.headers.get('Upgrade')
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
      return new Response('Expected Upgrade: websocket', { status: 426 })
    }

    // Get the client's IP address for use with the rate limiter.
    let ip = request.headers.get('CF-Connecting-IP')
    if (!ip) {
      return new Response('Expected header: CF-Connecting-IP', { status: 400 })
    }

    // To accept the WebSocket request, we create a WebSocketPair (which is like a socketpair,
    // i.e. two WebSockets that talk to each other), we return one end of the pair in the
    // response, and we operate on the other end. Note that this API is not part of the
    // Fetch API standard; unfortunately, the Fetch API / Service Workers specs do not define
    // any way to act as a WebSocket server today.
    let pair = new WebSocketPair()

    // We're going to take pair[1] as our end, and return pair[0] to the client.
    await this.handleSession(pair[1], new URL(request.url), ip)

    // Now we return the other end of the pair to the client.
    return new Response(null, { status: 101, webSocket: pair[0] })
  }

  async fetch(request: Request) {
    try {
      let response = await this.router.handle(request)
      return response
    } catch (error) {
      return new Response(error.message, { status: 500 })
    }
  }

  async handleSession(webSocket: WebSocket, url: URL, ip: string) {
    // Accept our end of the WebSocket. This tells the runtime that we'll be terminating the
    // WebSocket in JavaScript, not sending it elsewhere.
    webSocket.accept()

    // Close the WebSocket if the room is at max capacity.
    if (this.sessions.length >= Room.maxCapacity) {
      return webSocket.close(
        ErrorCode.ROOM_AT_MAX_CAPACITY,
        'This room is at max capacity',
      )
    }

    // Authorize the request and retrieve the user.
    let user
    try {
      user = await this.authorize(url.searchParams.get('access_token'))
    } catch (error) {
      return webSocket.close(ErrorCode.UNAUTHORIZED, error.message)
    }

    // Set up our rate limiter client.
    let limiterId = this.env.limiters.idFromName(ip)
    let limiter = new RateLimiterClient(
      () => this.env.limiters.get(limiterId),
      (err) => webSocket.close(1011, err.stack),
    )

    // Create our session.
    let session: Session = { webSocket, user, quit: false }

    // If the user doesn't have any existing sessions in this room, notify all users in the room
    // that they joined.
    let isExistingUser = this.sessions.some(
      (s) => s.user.id === session.user.id,
    )
    if (!isExistingUser) {
      this.broadcast(
        {
          type: MessageType.PRESENCE_USER_JOINED,
          data: {
            user: session.user,
          },
        },
        session.user.id,
      )
    }

    // Add the new session to the sessions list and give the user info about the room's presence.
    this.sessions.push(session)
    this.send(
      {
        type: MessageType.PRESENCE_INFO,
        data: {
          users: this.sessions.map((s) => s.user),
        },
      },
      session,
    )

    // Set event handlers to receive messages.
    webSocket.addEventListener('message', async (message) => {
      try {
        if (session.quit) {
          // Whoops, when trying to send to this WebSocket in the past, it threw an exception and
          // we marked it broken. But somehow we got another message? I guess try sending a
          // close(), which might throw, in which case we'll try to send an error, which will also
          // throw, and whatever, at least we won't accept the message. (This probably can't
          // actually happen. This is defensive coding.)
          webSocket.close(1011, 'Internal Server Error')
          return
        }

        // Check if the user is over their rate limit and reject the message if so.
        let isOverRateLimit = !limiter.checkLimit()
        if (isOverRateLimit) {
          return this.send(
            {
              type: MessageType.ERROR,
              data: {
                message:
                  'Your IP is being rate-limited, please try again later',
              },
            },
            session,
          )
        }

        // Parse the message as JSON, if the message is invalid reject it.
        let data
        try {
          data = clientDataSchema.parse(JSON.parse(message.data))
        } catch (error) {
          return this.send(
            {
              type: MessageType.ERROR,
              data: {
                message: 'Invalid message',
              },
            },
            session,
          )
        }

        switch (data.type) {
          case MessageType.PING: {
            return this.send({ type: MessageType.PONG }, session)
          }

          case MessageType.MESSAGE: {
            if (!data.data) {
              return this.send(
                {
                  type: MessageType.ERROR,
                  data: {
                    message: 'Invalid `data` field',
                  },
                },
                session,
              )
            }

            return this.broadcast(
              {
                type: MessageType.MESSAGE,
                data: data.data,
              },
              session.user.id,
            )
          }
        }
      } catch (error) {
        return this.send(
          {
            type: MessageType.ERROR,
            data: {
              message: 'Internal Server Error',
            },
          },
          session,
        )
      }
    })

    webSocket.addEventListener('close', ({ code, reason }) => {
      try {
        session.webSocket.close(code, reason)
      } catch {}

      this.endSession(session)
    })

    webSocket.addEventListener('error', () => {
      try {
        session.webSocket.close(1006)
      } catch {}

      this.endSession(session)
    })
  }

  endSession(session: Session) {
    session.quit = true
    this.sessions = this.sessions.filter((s) => s.user.id !== session.user.id)

    let hasOtherSessions = this.sessions.some(
      (s) => s.user.id === session.user.id,
    )

    // If the user doesn't have any other sessions, notify all users in the room
    // that this user left the room.
    if (!hasOtherSessions) {
      this.broadcast({
        type: MessageType.PRESENCE_USER_LEFT,
        data: {
          user: session.user,
        },
      })
    }
  }

  broadcast(message: Message, skipUserId?: string) {
    if (skipUserId) {
      return this.sessions
        .filter((session) => session.user.id !== skipUserId)
        .forEach((session) => this.send(message, session))
    }

    this.sessions.forEach((session) => this.send(message, session))
  }

  send(message: Message, session: Session) {
    try {
      session.webSocket.send(JSON.stringify(message))
    } catch (error) {
      // Whoops, this connection is dead. End the session.
      this.endSession(session)
    }
  }

  async authorize(accessToken: string | null | undefined): Promise<User> {
    if (!accessToken) {
      throw new Error('Missing access token')
    }

    let isValid = await jwt.verify(
      accessToken,
      this.env.AUTH_JWT_SECRET,
      this.env.AUTH_JWT_ALG,
    )

    if (!isValid) {
      throw new Error('Invalid access token')
    }

    let payload
    try {
      payload = accessTokenSchema.parse(jwt.decode(accessToken))
    } catch (error) {
      throw new Error('Invalid access token claims')
    }

    try {
      let user = userSchema.parse(JSON.parse(payload['x-user']))
      return user
    } catch (error) {
      throw new Error('Invalid access token x-user claim')
    }
  }
}

export { Room }
