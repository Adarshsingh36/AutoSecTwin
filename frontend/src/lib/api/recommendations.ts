import { post } from '../apiClient'
import type { RecommendationGenerateRequest, RecommendationResponse } from '../types'

export const generateRecommendation = (payload: RecommendationGenerateRequest) =>
  post<RecommendationResponse>('/recommendation/generate', payload)
