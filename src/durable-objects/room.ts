import jwt from '@tsndr/cloudflare-worker-jwt'
import { z } from 'zod'
import { RateLimiterClient } from './rate-limiter'
import type { Env } from '../types'

let errorCodes = {
  unauthorized: 4001,
  maxCapacity: 4002,
}

let events = {
  userJoined: 'user_joined',
  userLeft: 'user_left',
  error: 'error',
  message: 'message',
}

let accessTokenSchema = z.object({
  'x-user': z.string(),
})

let userSchema = z
  .object({
    id: z.string(),
  })
  .passthrough()

class Room implements DurableObject {
  // `storage` provides access to our durable storage. It provides a simple KV
  // get()/put() interface.
  storage: DurableObjectStorage

  // `env` is our environment bindings.
  env: Env

  // We will put the WebSocket objects for each client, along with some metadata, into
  // `sessions`.
  sessions: Session[]

  // The maximum amount of sessions a room can have at any given time.
  static maxCapacity = 100

  constructor(state: DurableObjectState, env: Env) {
    this.storage = state.storage
    this.env = env
    this.sessions = []
  }

  async fetch(request: Request) {
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

  async handleSession(webSocket: WebSocket, url: URL, ip: string) {
    // Accept our end of the WebSocket. This tells the runtime that we'll be terminating the
    // WebSocket in JavaScript, not sending it elsewhere.
    webSocket.accept()

    // Close the WebSocket if the room is full.
    if (this.sessions.length >= Room.maxCapacity) {
      return webSocket.close(
        errorCodes.maxCapacity,
        'This room is at max capacity',
      )
    }

    // Authorize the session and retrieve the user.
    let user
    try {
      user = await this.authorizeSession(url)
    } catch (error) {
      return webSocket.close(errorCodes.unauthorized, error.message)
    }

    // Set up our rate limiter client.
    let limiterId = this.env.limiters.idFromName(ip)
    let limiter = new RateLimiterClient(
      () => this.env.limiters.get(limiterId),
      (err) => webSocket.close(1011, err.stack),
    )

    // Create our session, add it to the sessions list.
    let session: Session = { webSocket, user, quit: false }
    this.sessions.push(session)

    // If the user doesn't have any existing sessions in this room, notify all users in the room
    // that this user joined.
    // TODO: FIX THIS LOGIC; DOESNT WORK FOR SOME REASON
    let isNewUser = !this.sessions.some((s) => s.user.id === session.user.id)
    if (isNewUser) {
    }
    this.broadcast(
      {
        event: events.userJoined,
        data: {
          user: session.user,
        },
      },
      session.user.id,
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

        if (message.data === 'PING') {
          return this.send('PONG', session)
        }

        // Check if the user is over their rate limit and reject the message if so.
        let isOverRateLimit = !limiter.checkLimit()
        if (isOverRateLimit) {
          return this.send(
            {
              event: events.error,
              data: {
                message:
                  'Your IP is being rate-limited, please try again later',
              },
            },
            session,
          )
        }

        // Parse the message as JSON, if the message contains invalid JSON, reject it.
        let data
        try {
          data = JSON.parse(message.data)
        } catch (error) {
          return this.send(
            {
              event: events.error,
              data: {
                message: 'Invalid message',
              },
            },
            session,
          )
        }

        // Broadcast the message to all other users except the one sending it.
        this.broadcast({ event: events.message, data }, session.user.id)
      } catch (error) {
        return this.send(
          {
            event: events.error,
            data: {
              message: 'Internal Server Error',
            },
          },
          session,
        )
      }
    })

    let closeOrErrorHandler = () => {
      this.endSession(session)
    }

    webSocket.addEventListener('close', closeOrErrorHandler)
    webSocket.addEventListener('error', closeOrErrorHandler)
  }

  endSession(session: Session) {
    session.quit = true
    this.sessions = this.sessions.filter((s) => s.user.id !== session.user.id)

    // If the user doesn't have any other sessions, notify all users in the room
    // that this user left the room.
    let hasOtherSessions = this.sessions.some(
      (s) => s.user.id === session.user.id,
    )
    if (!hasOtherSessions) {
      this.broadcast({
        event: events.userLeft,
        data: { user: session.user },
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
      session.webSocket.send(
        typeof message === 'string' ? message : JSON.stringify(message),
      )
    } catch (error) {
      // Whoops, this connection is dead. End the session.
      this.endSession(session)
    }
  }

  async authorizeSession(url: URL): Promise<User> {
    let params = url.searchParams
    let accessToken = params.get('access_token')

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

type Message =
  | {
      event: string
      data: Record<string, unknown>
    }
  | string

type User = z.infer<typeof userSchema> & Record<string, unknown>

interface Session {
  user: User
  quit: boolean
  webSocket: WebSocket
}

export { Room }
