import { useState } from 'react'
import ExtensionInput from './components/ExtensionInput'
import Report from './components/Report'
import { analyzeExtension } from './analyzer'
import type { AnalysisReport, ExtensionFiles, InputMethod } from './types'

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
    <div className="min-h-screen bg-gray-950 text-gray-100">
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-950/80 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-5xl mx-auto px-6 py-4 flex items-center justify-between">
          <div>
            <h1
              className="text-xl font-bold tracking-tight text-gray-100 cursor-pointer"
              onClick={handleReset}
            >
              CRX Audit
            </h1>
            <p className="text-xs text-gray-500 mt-0.5">
              Chrome Extension Security Analyzer
            </p>
          </div>
          {report && (
            <button
              onClick={handleReset}
              className="text-sm text-gray-500 hover:text-gray-300 transition-colors"
            >
              New Scan
            </button>
          )}
        </div>
      </header>

      {/* Main */}
      <main className="max-w-5xl mx-auto px-6 py-10">
        {!report && !analyzing && (
          <div className="pt-8">
            <div className="text-center mb-10">
              <h2 className="text-2xl font-semibold text-gray-100 mb-2">
                Analyze a Chrome Extension
              </h2>
              <p className="text-sm text-gray-500 max-w-md mx-auto">
                Upload a .crx file, paste a manifest, or enter an extension ID to scan
                for security issues, risky permissions, and suspicious code patterns.
              </p>
            </div>
            <ExtensionInput onAnalyze={handleAnalyze} />
          </div>
        )}

        {analyzing && (
          <div className="flex flex-col items-center justify-center py-24 gap-4">
            <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
            <p className="text-sm text-gray-400">Running security analysis...</p>
          </div>
        )}

        {error && (
          <div className="max-w-2xl mx-auto bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-400 mb-6">
            {error}
          </div>
        )}

        {report && <Report report={report} />}
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800 mt-16">
        <div className="max-w-5xl mx-auto px-6 py-4 text-center text-xs text-gray-600">
          CRX Audit — Static analysis only. Does not execute extension code.
        </div>
      </footer>
    </div>
  )
}
