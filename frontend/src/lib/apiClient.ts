/**
 * Thin fetch wrapper used by every function in src/lib/api/*.
 *
 * Base URL: in dev, Vite's proxy (vite.config.ts) forwards /api/* to the
 * FastAPI backend, so this stays a relative path and never needs CORS
 * config. In production, set VITE_API_BASE_URL to the deployed backend's
 * URL (see .env.example).
 */

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '/api'

export class ApiError extends Error {
  status: number
  detail: string

  constructor(status: number, detail: string) {
    super(detail)
    this.name = 'ApiError'
    this.status = status
    this.detail = detail
  }
}

async function parseErrorDetail(response: Response): Promise<string> {
  try {
    const body = await response.json()
    if (typeof body.detail === 'string') return body.detail
    if (Array.isArray(body.detail)) {
      return body.detail.map((e: { msg?: string }) => e.msg).filter(Boolean).join('; ')
    }
    return response.statusText
  } catch {
    return response.statusText || `Request failed with status ${response.status}`
  }
}

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...init?.headers,
    },
  })

  if (!response.ok) {
    throw new ApiError(response.status, await parseErrorDetail(response))
  }

  const text = await response.text()
  return (text ? JSON.parse(text) : undefined) as T
}

export async function apiFetchBlob(path: string): Promise<Blob> {
  const response = await fetch(`${API_BASE_URL}${path}`)
  if (!response.ok) {
    throw new ApiError(response.status, await parseErrorDetail(response))
  }
  return response.blob()
}

export const get = <T>(path: string) => apiFetch<T>(path)

export const post = <T>(path: string, body?: unknown) =>
  apiFetch<T>(path, { method: 'POST', body: body !== undefined ? JSON.stringify(body) : undefined })

export const patch = <T>(path: string, body?: unknown) =>
  apiFetch<T>(path, { method: 'PATCH', body: body !== undefined ? JSON.stringify(body) : undefined })

export const del = <T>(path: string) => apiFetch<T>(path, { method: 'DELETE' })
