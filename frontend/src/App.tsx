import { Route, Routes } from 'react-router-dom'
import { TopNav } from './components/layout/TopNav'
import { Dashboard } from './pages/Dashboard'
import { RegisterTarget } from './pages/RegisterTarget'
import { Reports } from './pages/Reports'
import { ReportDetail } from './pages/ReportDetail'
import { Approvals } from './pages/Approvals'
import { Twins } from './pages/Twins'
import { TwinViewer } from './pages/TwinViewer'
import { Vulnerabilities } from './pages/Vulnerabilities'
import { SystemHealth } from './pages/SystemHealth'

export default function App() {
  return (
    <div className="min-h-screen">
      <TopNav />
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/applications" element={<RegisterTarget />} />
        <Route path="/vulnerabilities" element={<Vulnerabilities />} />
        <Route path="/twins" element={<Twins />} />
        <Route path="/twins/:id" element={<TwinViewer />} />
        <Route path="/approvals" element={<Approvals />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/reports/:id" element={<ReportDetail />} />
        <Route path="/system-health" element={<SystemHealth />} />
      </Routes>
    </div>
  )
}
