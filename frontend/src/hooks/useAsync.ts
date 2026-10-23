import { useCallback, useEffect, useState } from 'react'
import { ApiError } from '../lib/apiClient'

interface AsyncState<T> {
  data: T | null
  loading: boolean
  error: string | null
}

/** Fetches `fn()` on mount and whenever `deps` change. Exposes `refetch`
 * for manual re-fetching after a mutation (approve, execute, etc). */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [state, setState] = useState<AsyncState<T>>({ data: null, loading: true, error: null })

  const run = useCallback(() => {
    setState((s) => ({ ...s, loading: true, error: null }))
    fn()
      .then((data) => setState({ data, loading: false, error: null }))
      .catch((err) => {
        const message = err instanceof ApiError ? err.detail : err instanceof Error ? err.message : 'Unknown error'
        setState({ data: null, loading: false, error: message })
      })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)

  useEffect(() => {
    run()
  }, [run])

  return { ...state, refetch: run }
}
