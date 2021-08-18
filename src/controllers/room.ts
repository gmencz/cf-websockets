import { Controller } from '.'

const ROOM_NAME_MAX_LENGTH = 200

let roomController = Controller({
  all: async (request, env) => {
    let name = request.params?.name
    if (!name) {
      return new Response('Missing room name', { status: 400 })
    }

    if (name.length > ROOM_NAME_MAX_LENGTH) {
      return new Response('Room name is too long', { status: 400 })
    }

    let id = env.rooms.idFromName(name)
    let roomObject = env.rooms.get(id)
    let response = await roomObject.fetch(request)
    return response
  },
})

export { roomController }
