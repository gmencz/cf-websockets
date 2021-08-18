import type { RoutedRequestHandler } from '../types'

type ControllerType = Record<string, RoutedRequestHandler>

function Controller<TController extends ControllerType>(
  controller: TController,
) {
  return controller
}

export { Controller }
