import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { PageShell } from '../components/layout/PageShell'
import { Button } from '../components/ui/Button'
import { ErrorState, LoadingState } from '../components/ui/States'
import { useAsync } from '../hooks/useAsync'
import { getReport, fetchReportPdfBlob, getReportHtmlUrl } from '../lib/api/reports'

export function ReportDetail() {
  const { id } = useParams()
  const reportId = Number(id)
  const { data: report, loading, error, refetch } = useAsync(() => getReport(reportId), [reportId])
  const [downloading, setDownloading] = useState(false)

  async function handleDownloadPdf() {
    setDownloading(true)
    try {
      const blob = await fetchReportPdfBlob(reportId)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `autosectwin-report-${reportId}.pdf`
      a.click()
      URL.revokeObjectURL(url)
    } finally {
      setDownloading(false)
    }
  }

  if (loading) return <PageShell title="Report"><LoadingState /></PageShell>
  if (error) return <PageShell title="Report"><ErrorState message={error} onRetry={refetch} /></PageShell>
  if (!report) return null

  return (
    <PageShell
      title={report.title}
      subtitle={`Report #${report.id} · ${report.report_type.replace(/_/g, ' ')} · Generated ${new Date(report.created_at).toLocaleString()}`}
      actions={
        <>
          <Link to="/reports"><Button variant="ghost">Back to Reports</Button></Link>
          <Button variant="secondary" loading={downloading} onClick={handleDownloadPdf}>
            Download PDF
          </Button>
        </>
      }
    >
      <div className="panel panel-glow overflow-hidden">
        <iframe
          title={`Report ${report.id}`}
          src={getReportHtmlUrl(report.id)}
          className="h-[80vh] w-full bg-white"
        />
      </div>
    </PageShell>
  )
}
