import type { AnalysisReport } from '../types'
import OverviewCard from './OverviewCard'
import PermissionTable from './PermissionTable'
import CombinationCards from './CombinationCards'
import CSPSection from './CSPSection'
import CodePatterns from './CodePatterns'
import HostPermissions from './HostPermissions'
import WebAccessibleResources from './WebAccessibleResources'
import ManifestVersion from './ManifestVersion'

interface ReportProps {
  report: AnalysisReport
}

export default function Report({ report }: ReportProps) {
  return (
    <div className="stagger pt-8 space-y-5">
      <OverviewCard report={report} />
      <PermissionTable permissions={report.permissions} />
      {report.combinations.length > 0 && (
        <CombinationCards combinations={report.combinations} />
      )}
      <CSPSection csp={report.csp} />
      {report.codePatterns.length > 0 && (
        <CodePatterns patterns={report.codePatterns} />
      )}
      {report.hostPermissions.length > 0 && (
        <HostPermissions findings={report.hostPermissions} />
      )}
      {report.webAccessibleResources.length > 0 && (
        <WebAccessibleResources findings={report.webAccessibleResources} />
      )}
      <ManifestVersion finding={report.manifestVersionAnalysis} />
    </div>
  )
}
