import { get } from '../apiClient'
import type { DriftResponse, TrustStatisticsResponse } from '../types'

export const getTrustStatistics = () => get<TrustStatisticsResponse>('/trust/statistics')

export const listDrift = () => get<DriftResponse[]>('/trust/drift')
