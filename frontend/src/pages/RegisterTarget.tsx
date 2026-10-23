import { useRef, useState } from 'react'
import { PageShell } from '../components/layout/PageShell'
import { Button } from '../components/ui/Button'

type TargetType = 'url' | 'upload' | 'twin'

function isValidUrl(value: string): boolean {
  try {
    const parsed = new URL(value)
    return parsed.protocol === 'http:' || parsed.protocol === 'https:'
  } catch {
    return false
  }
}

const MAX_FILE_SIZE_MB = 200
const ACCEPTED_EXTENSIONS = ['.zip', '.tar.gz', '.tgz']

export function RegisterTarget() {
  const [targetType, setTargetType] = useState<TargetType>('url')
  const [url, setUrl] = useState('')
  const [urlError, setUrlError] = useState<string | null>(null)
  const [file, setFile] = useState<File | null>(null)
  const [fileError, setFileError] = useState<string | null>(null)
  const [dragActive, setDragActive] = useState(false)
  const [authorized, setAuthorized] = useState(false)
  const [registered, setRegistered] = useState<{ type: TargetType; label: string } | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const folderInputRef = useRef<HTMLInputElement>(null)

  function validateAndSetFile(candidate: File) {
    const sizeMb = candidate.size / (1024 * 1024)
    if (sizeMb > MAX_FILE_SIZE_MB) {
      setFileError(`${candidate.name} is ${sizeMb.toFixed(1)}MB, which exceeds the ${MAX_FILE_SIZE_MB}MB limit.`)
      setFile(null)
      return
    }
    const hasAcceptedExtension = ACCEPTED_EXTENSIONS.some((ext) => candidate.name.toLowerCase().endsWith(ext))
    if (!hasAcceptedExtension) {
      setFileError(`${candidate.name} is not a supported archive type (${ACCEPTED_EXTENSIONS.join(', ')}).`)
      setFile(null)
      return
    }
    setFileError(null)
    setFile(candidate)
  }

  function handleDrop(e: React.DragEvent<HTMLDivElement>) {
    e.preventDefault()
    setDragActive(false)
    const dropped = e.dataTransfer.files?.[0]
    if (dropped) validateAndSetFile(dropped)
  }

  function handleUrlBlur() {
    if (url && !isValidUrl(url)) {
      setUrlError('Enter a valid http:// or https:// URL.')
    } else {
      setUrlError(null)
    }
  }

  function handleSubmit() {
    if (targetType === 'url') {
      if (!url || !isValidUrl(url)) {
        setUrlError('Enter a valid http:// or https:// URL before submitting.')
        return
      }
      setRegistered({ type: 'url', label: url })
    } else if (targetType === 'upload') {
      if (!file) {
        setFileError('Select a file or folder to upload first.')
        return
      }
      setRegistered({ type: 'upload', label: file.name })
    }
  }

  const canSubmit = authorized && (targetType === 'url' ? !!url && !urlError : targetType === 'upload' ? !!file : true)

  return (
    <PageShell
      title="Register Target Application"
      subtitle="Provide an application for security assessment via URL, uploaded project, or managed digital twin."
    >
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="panel panel-glow p-6 lg:col-span-2">
          <div className="mb-5 flex gap-2 rounded-lg bg-station-void/60 p-1">
            {(['url', 'upload', 'twin'] as TargetType[]).map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setTargetType(t)}
                className={`flex-1 rounded-md px-3 py-2 text-xs font-semibold uppercase tracking-wide transition-colors ${
                  targetType === t ? 'bg-neon-cyan/15 text-neon-cyan' : 'text-text-muted hover:text-text-primary'
                }`}
              >
                {t === 'url' ? 'Application URL' : t === 'upload' ? 'Upload Project' : 'Managed Digital Twin'}
              </button>
            ))}
          </div>

          {targetType === 'url' && (
            <div>
              <label htmlFor="target-url" className="mb-1.5 block text-sm font-medium text-text-primary">
                Application URL
              </label>
              <input
                id="target-url"
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onBlur={handleUrlBlur}
                placeholder="https://staging.example.com"
                className="w-full rounded-lg border border-station-border bg-station-void/60 px-3 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-neon-cyan focus:outline-none"
                aria-invalid={!!urlError}
                aria-describedby="url-error"
              />
              {urlError && (
                <p id="url-error" className="mt-1.5 text-xs text-alert-critical">
                  {urlError}
                </p>
              )}
            </div>
          )}

          {targetType === 'upload' && (
            <div>
              <div
                onDragOver={(e) => {
                  e.preventDefault()
                  setDragActive(true)
                }}
                onDragLeave={() => setDragActive(false)}
                onDrop={handleDrop}
                className={`flex flex-col items-center justify-center gap-3 rounded-lg border-2 border-dashed p-10 text-center transition-colors ${
                  dragActive ? 'border-neon-cyan bg-neon-cyan/5' : 'border-station-border'
                }`}
              >
                <div className="text-3xl opacity-50">&#9729;</div>
                <p className="text-sm text-text-muted">Drag and drop a project archive, or</p>
                <div className="flex gap-3">
                  <Button variant="secondary" onClick={() => fileInputRef.current?.click()}>
                    Browse Files
                  </Button>
                  <Button
                    variant="ghost"
                    onClick={() => folderInputRef.current?.click()}
                    title="Folder selection support varies by browser"
                  >
                    Select Folder
                  </Button>
                </div>
                <p className="text-xs text-text-muted">
                  Accepted: {ACCEPTED_EXTENSIONS.join(', ')} · Max {MAX_FILE_SIZE_MB}MB
                </p>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept={ACCEPTED_EXTENSIONS.join(',')}
                  className="hidden"
                  onChange={(e) => e.target.files?.[0] && validateAndSetFile(e.target.files[0])}
                />
                <input
                  ref={folderInputRef}
                  type="file"
                  // @ts-expect-error -- webkitdirectory is non-standard but widely supported
                  webkitdirectory=""
                  directory=""
                  className="hidden"
                  onChange={(e) => e.target.files?.[0] && validateAndSetFile(e.target.files[0])}
                />
              </div>

              {file && (
                <div className="mt-4 flex items-center justify-between rounded-lg border border-station-border bg-station-void/40 px-4 py-3">
                  <div>
                    <p className="text-sm text-text-primary">{file.name}</p>
                    <p className="text-xs text-text-muted">{(file.size / (1024 * 1024)).toFixed(2)} MB</p>
                  </div>
                  <Button variant="ghost" onClick={() => setFile(null)}>
                    Remove
                  </Button>
                </div>
              )}
              {fileError && <p className="mt-2 text-xs text-alert-critical">{fileError}</p>}
            </div>
          )}

          {targetType === 'twin' && (
            <p className="text-sm text-text-muted">
              To assess an existing managed digital twin, select it from the{' '}
              <a href="/twins" className="text-neon-cyan hover:underline">
                Digital Twins
              </a>{' '}
              inventory and trigger assessment from there.
            </p>
          )}

          <div className="mt-6 flex items-start gap-2.5 rounded-lg border border-station-border bg-station-void/40 p-4">
            <input
              id="authorized"
              type="checkbox"
              checked={authorized}
              onChange={(e) => setAuthorized(e.target.checked)}
              className="mt-0.5 h-4 w-4 accent-neon-cyan"
            />
            <label htmlFor="authorized" className="text-sm text-text-muted">
              I confirm I am authorized to submit this target for security assessment, and that scope is limited to
              what I have explicit permission to test.
            </label>
          </div>

          <Button className="mt-6 w-full" disabled={!canSubmit} onClick={handleSubmit}>
            Start Security Assessment
          </Button>

          {registered && (
            <div className="mt-5 rounded-lg border border-alert-warning/40 bg-alert-warning/5 p-4">
              <p className="text-sm font-semibold text-alert-warning">Registered — no scan was performed</p>
              <p className="mt-1 text-sm text-text-muted">
                <span className="font-mono text-text-primary">{registered.label}</span> has been recorded on this
                page only. The backend currently has no endpoint to accept a URL or uploaded project for automated
                scanning — see the integration note on the right. To get a real vulnerability record into the
                system today, use the Vulnerabilities page to record a known CVE finding manually, or provision a
                Digital Twin directly for an existing vulnerability record.
              </p>
            </div>
          )}
        </div>

        <aside className="panel border-neon-purple/30 p-5">
          <h2 className="font-display text-sm font-semibold text-neon-purple">Integration Boundary</h2>
          <p className="mt-2 text-sm leading-relaxed text-text-muted">
            This backend does not currently expose an endpoint to accept a target URL or uploaded project and turn
            it into a scan. The closest existing primitives are:
          </p>
          <ul className="mt-3 list-inside list-disc space-y-1.5 text-sm text-text-muted">
            <li>
              <code className="text-neon-cyan">POST /vulnerabilities/</code> — manually record a known CVE finding
            </li>
            <li>
              <code className="text-neon-cyan">POST /twins/provision</code> — provision a Digital Twin for an
              existing vulnerability record
            </li>
            <li>
              <code className="text-neon-cyan">POST /orchestration/run</code> — run the closed loop (twin → validate
              → recommend) for an existing vulnerability
            </li>
          </ul>
          <p className="mt-3 text-sm leading-relaxed text-text-muted">
            Backend work needed for this feature to go live: an asset-registration endpoint that accepts a URL or
            uploaded archive, a scanner/crawler integration to discover vulnerabilities in it, and a way to link the
            result back to a <code className="text-neon-cyan">Vulnerability</code> record.
          </p>
        </aside>
      </div>
    </PageShell>
  )
}
