import { useState } from 'react'
import ExtensionInput from './components/ExtensionInput'
import Report from './components/Report'
import { analyzeExtension } from './analyzer'
import type { AnalysisReport, ExtensionFiles, InputMethod } from './types'
import { Shield } from 'lucide-react'

export default function App() {
  const [report, setReport] = useState<AnalysisReport | null>(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleAnalyze = async (files: ExtensionFiles, method: InputMethod) => {
    setError(null)
    setAnalyzing(true)
    setReport(null)
    try {
      const result = analyzeExtension(files, method)
      setReport(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed.')
    } finally {
      setAnalyzing(false)
    }
  }

  const handleReset = () => {
    setReport(null)
    setError(null)
  }

  return (
    <>
      {/* Header */}
      <header className="sticky top-0 z-50 border-b border-[var(--color-border-subtle)] bg-[var(--color-surface-0)]/90 backdrop-blur-xl">
        <div className="max-w-[1100px] mx-auto px-6 h-14 flex items-center justify-between">
          <button onClick={handleReset} className="flex items-center gap-2.5 group">
            <Shield className="w-5 h-5 text-amber-500 group-hover:text-amber-400 transition-colors" />
            <span className="font-display font-bold text-[15px] tracking-tight text-[var(--color-text-primary)]">
              CRX Audit
            </span>
            <span className="text-[11px] font-mono text-[var(--color-text-tertiary)] hidden sm:inline">
              v1.0
            </span>
          </button>
          {report && (
            <button
              onClick={handleReset}
              className="text-[13px] font-medium text-[var(--color-text-tertiary)] hover:text-[var(--color-text-secondary)] transition-colors font-display"
            >
              New Scan
            </button>
          )}
        </div>
      </header>

      {/* Main */}
      <main className="max-w-[1100px] mx-auto px-6 pb-20">
        {!report && !analyzing && (
          <div className="animate-fade-up pt-16 sm:pt-24">
            <div className="text-center mb-12">
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-amber-500/10 border border-amber-500/20 text-amber-500 text-[11px] font-mono font-medium tracking-wide uppercase mb-6">
                <div className="w-1.5 h-1.5 rounded-full bg-amber-500 animate-pulse" />
                Open Source Security Analysis
              </div>
              <h1 className="font-display font-bold text-3xl sm:text-4xl tracking-tight text-[var(--color-text-primary)] mb-3">
                Analyze Chrome Extensions
              </h1>
              <p className="text-[15px] text-[var(--color-text-secondary)] max-w-md mx-auto leading-relaxed">
                Transparent permission analysis, dangerous combination detection,
                and CSP evaluation. All client-side.
              </p>
            </div>
            <ExtensionInput onAnalyze={handleAnalyze} />
          </div>
        )}

        {analyzing && (
          <div className="flex flex-col items-center justify-center py-32 gap-5 animate-fade-in">
            <div className="relative">
              <div className="w-10 h-10 border-2 border-amber-500/30 rounded-full" />
              <div className="absolute inset-0 w-10 h-10 border-2 border-amber-500 border-t-transparent rounded-full animate-spin" />
            </div>
            <p className="text-sm font-mono text-[var(--color-text-tertiary)]">
              Analyzing extension...
            </p>
          </div>
        )}

        {error && (
          <div className="max-w-xl mx-auto mt-8 bg-red-500/8 border border-red-500/20 rounded-lg px-4 py-3 text-sm text-red-400 font-mono animate-fade-up">
            {error}
          </div>
        )}

        {report && <Report report={report} />}
      </main>

      {/* Footer */}
      <footer className="border-t border-[var(--color-border-subtle)] py-6">
        <div className="max-w-[1100px] mx-auto px-6 flex items-center justify-between text-[11px] font-mono text-[var(--color-text-tertiary)]">
          <span>CRX Audit — Static analysis only</span>
          <span>Does not execute extension code</span>
        </div>
      </footer>
    </>
  )
}
