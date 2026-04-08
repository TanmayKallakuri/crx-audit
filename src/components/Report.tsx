import type { AnalysisReport } from '../types'
import OverviewCard from './OverviewCard'
import PermissionTable from './PermissionTable'
import CombinationCards from './CombinationCards'
import CSPSection from './CSPSection'
import CodePatterns from './CodePatterns'
import HostPermissions from './HostPermissions'
import ManifestVersion from './ManifestVersion'

interface ReportProps {
  report: AnalysisReport
}

export default function Report({ report }: ReportProps) {
  return (
    <div className="space-y-6 w-full max-w-4xl mx-auto">
      <OverviewCard report={report} />
      <PermissionTable permissions={report.permissions} />
      <CombinationCards combinations={report.combinations} />
      <CSPSection csp={report.csp} />
      <CodePatterns patterns={report.codePatterns} />
      <HostPermissions findings={report.hostPermissions} />
      <ManifestVersion finding={report.manifestVersionAnalysis} />
    </div>
  )
}
