import { Controller } from '.'

let httpController = Controller({
  slash: () => {
    return new Response('CF WebSockets 1.0')
  },

  notFound: () => {
    return new Response('Not found', { status: 404 })
  },
})

export { httpController }
