import { get } from '../apiClient'
import type { ValidationResponse } from '../types'

export const listValidations = () => get<ValidationResponse[]>('/validations/')

export const getValidation = (id: number) => get<ValidationResponse>(`/validations/${id}`)
