import type { Env, RoutedRequest } from '../types'

type ControllerType = Record<
  string,
  (request: RoutedRequest, env: Env) => Response | Promise<Response>
>

function Controller<TController extends ControllerType>(
  controller: TController,
) {
  return controller
}

export { Controller }
