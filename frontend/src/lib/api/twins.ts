import { get, post, del } from '../apiClient'
import type { TwinDestroyResponse, TwinProvisionRequest, TwinProvisionResponse } from '../types'

export const listTwins = () => get<TwinProvisionResponse[]>('/twins/')

export const getTwin = (id: number) => get<TwinProvisionResponse>(`/twins/${id}`)

export const provisionTwin = (payload: TwinProvisionRequest) =>
  post<TwinProvisionResponse>('/twins/provision', payload)

// DELETE /twins/{id} and POST /twins/{id}/destroy are the same handler
// (TwinProvisioningService.destroy()) under two URL conventions -- this
// actually destroys the twin via the Digital Twin Generator, it is not a
// bare row deletion.
export const destroyTwin = (id: number) => del<TwinDestroyResponse>(`/twins/${id}`)
