import { apiFetchBlob, get, post } from '../apiClient'
import type { ReportResponse } from '../types'

export const listReports = () => get<ReportResponse[]>('/reports/')

export const getReport = (id: number) => get<ReportResponse>(`/reports/${id}`)

export const createClosedLoopReport = (remediationId: number) =>
  post<ReportResponse>(`/reports/closed-loop/${remediationId}`)

export const getReportHtmlUrl = (id: number) => `/reports/${id}/html`

export const fetchReportPdfBlob = (id: number) => apiFetchBlob(`/reports/${id}/pdf`)
