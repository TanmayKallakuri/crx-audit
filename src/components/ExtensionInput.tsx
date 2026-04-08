import { useState, useCallback, useRef } from 'react'
import { Search, Upload, FileText, ArrowRight } from 'lucide-react'
import type { ExtensionFiles, InputMethod } from '../types'
import { extractExtensionId, extractExtensionName } from '../utils/helpers'
import { extractFromFile, extractFromManifest, extractFromId } from '../analyzer/crx-extractor'

type Tab = 'id' | 'upload' | 'paste'

interface ExtensionInputProps {
  onAnalyze: (files: ExtensionFiles, method: InputMethod) => void
}

export default function ExtensionInput({ onAnalyze }: ExtensionInputProps) {
  const [activeTab, setActiveTab] = useState<Tab>('upload')
  const [idInput, setIdInput] = useState('')
  const [manifestInput, setManifestInput] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [dragActive, setDragActive] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const tabs: { key: Tab; label: string; icon: React.ReactNode }[] = [
    { key: 'id', label: 'Web Store URL', icon: <Search className="w-3.5 h-3.5" /> },
    { key: 'upload', label: 'Upload', icon: <Upload className="w-3.5 h-3.5" /> },
    { key: 'paste', label: 'Manifest', icon: <FileText className="w-3.5 h-3.5" /> },
  ]

  const handleError = (err: unknown) => {
    setError(err instanceof Error ? err.message : 'An unexpected error occurred.')
  }

  const handleIdSubmit = async () => {
    setError(null)
    const extensionId = extractExtensionId(idInput)
    if (!extensionId) {
      setError('Enter a valid 32-character extension ID or Chrome Web Store URL.')
      return
    }
    setLoading(true)
    try {
      const files = await extractFromId(extensionId)
      onAnalyze(files, 'id')
    } catch (err) {
      handleError(err)
    } finally {
      setLoading(false)
    }
  }

  const handleFileUpload = async (file: File) => {
    setError(null)
    if (!file.name.endsWith('.crx') && !file.name.endsWith('.zip')) {
      setError('Please upload a .crx or .zip file.')
      return
    }
    setLoading(true)
    try {
      const files = await extractFromFile(file)
      onAnalyze(files, 'upload')
    } catch (err) {
      handleError(err)
    } finally {
      setLoading(false)
    }
  }

  const handleManifestSubmit = () => {
    setError(null)
    try {
      const files = extractFromManifest(manifestInput)
      onAnalyze(files, 'paste')
    } catch (err) {
      handleError(err)
    }
  }

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragActive(false)
    const file = e.dataTransfer.files[0]
    if (file) handleFileUpload(file)
  }, [])

  return (
    <div className="w-full max-w-xl mx-auto">
      {/* Tab selector */}
      <div className="flex gap-1 p-1 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] mb-5">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => { setActiveTab(tab.key); setError(null) }}
            className={`flex-1 flex items-center justify-center gap-2 py-2.5 text-[13px] font-medium rounded-md transition-all duration-200 ${
              activeTab === tab.key
                ? 'bg-[var(--color-surface-0)] text-[var(--color-text-primary)] shadow-sm'
                : 'text-[var(--color-text-tertiary)] hover:text-[var(--color-text-secondary)]'
            }`}
          >
            {tab.icon}
            <span className="font-display">{tab.label}</span>
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div>
        {activeTab === 'id' && (
          <div className="space-y-3 animate-fade-in">
            <label className="block text-[12px] font-mono text-[var(--color-text-tertiary)] uppercase tracking-wider">
              Paste a Chrome Web Store URL
            </label>
            {extractExtensionName(idInput) && (
              <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-amber-500/8 border border-amber-500/15">
                <div className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                <span className="text-[13px] font-display font-medium text-amber-400">
                  {extractExtensionName(idInput)}
                </span>
              </div>
            )}
            <div className="flex gap-2">
              <input
                type="text"
                value={idInput}
                onChange={(e) => setIdInput(e.target.value)}
                placeholder="https://chromewebstore.google.com/detail/extension-name/abc..."
                className="flex-1 bg-[var(--color-surface-1)] border border-[var(--color-border)] rounded-lg px-4 py-3 text-sm font-mono text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] focus:outline-none focus:border-amber-500/50 focus:ring-1 focus:ring-amber-500/20 transition-all"
                onKeyDown={(e) => e.key === 'Enter' && handleIdSubmit()}
              />
              <button
                onClick={handleIdSubmit}
                disabled={loading || !idInput.trim()}
                className="px-5 py-3 bg-amber-500 hover:bg-amber-400 disabled:bg-[var(--color-surface-3)] disabled:text-[var(--color-text-tertiary)] text-black text-sm font-display font-semibold rounded-lg transition-all flex items-center gap-2"
              >
                Scan
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
            <p className="text-[11px] text-[var(--color-text-tertiary)]">
              Copy the URL from any extension's Chrome Web Store page. Extension IDs also work.
            </p>
          </div>
        )}

        {activeTab === 'upload' && (
          <div
            onDrop={handleDrop}
            onDragOver={(e) => { e.preventDefault(); setDragActive(true) }}
            onDragLeave={() => setDragActive(false)}
            onClick={() => fileInputRef.current?.click()}
            className={`group relative border-2 border-dashed rounded-xl p-14 text-center cursor-pointer transition-all duration-300 animate-fade-in ${
              dragActive
                ? 'border-amber-500/60 bg-amber-500/5'
                : 'border-[var(--color-border)] hover:border-[var(--color-text-tertiary)] bg-[var(--color-surface-1)]/50'
            }`}
          >
            <div className={`mx-auto w-12 h-12 rounded-xl flex items-center justify-center mb-4 transition-all duration-300 ${
              dragActive ? 'bg-amber-500/15 text-amber-500 scale-110' : 'bg-[var(--color-surface-3)] text-[var(--color-text-tertiary)] group-hover:text-[var(--color-text-secondary)]'
            }`}>
              <Upload className="w-5 h-5" />
            </div>
            <p className="text-[14px] text-[var(--color-text-secondary)] mb-1 font-display">
              Drop a <span className="font-mono text-amber-500/80">.crx</span> or{' '}
              <span className="font-mono text-amber-500/80">.zip</span> file
            </p>
            <p className="text-[12px] text-[var(--color-text-tertiary)]">or click to browse</p>
            <input
              ref={fileInputRef}
              type="file"
              accept=".crx,.zip"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0]
                if (file) handleFileUpload(file)
              }}
            />
          </div>
        )}

        {activeTab === 'paste' && (
          <div className="space-y-3 animate-fade-in">
            <label className="block text-[12px] font-mono text-[var(--color-text-tertiary)] uppercase tracking-wider">
              manifest.json contents
            </label>
            <textarea
              value={manifestInput}
              onChange={(e) => setManifestInput(e.target.value)}
              placeholder='{"manifest_version": 3, "name": "My Extension", ...}'
              rows={8}
              className="w-full bg-[var(--color-surface-1)] border border-[var(--color-border)] rounded-lg px-4 py-3 text-sm font-mono text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] focus:outline-none focus:border-amber-500/50 focus:ring-1 focus:ring-amber-500/20 transition-all resize-y leading-relaxed"
            />
            <button
              onClick={handleManifestSubmit}
              disabled={!manifestInput.trim()}
              className="px-5 py-2.5 bg-amber-500 hover:bg-amber-400 disabled:bg-[var(--color-surface-3)] disabled:text-[var(--color-text-tertiary)] text-black text-sm font-display font-semibold rounded-lg transition-all flex items-center gap-2"
            >
              Analyze
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {error && (
          <div className="mt-4 bg-red-500/8 border border-red-500/20 rounded-lg px-4 py-3 text-[13px] text-red-400 font-mono animate-fade-up">
            {error}
          </div>
        )}

        {loading && (
          <div className="mt-6 flex items-center justify-center gap-3 py-4 text-[var(--color-text-tertiary)] text-[13px] font-mono animate-fade-in">
            <div className="w-4 h-4 border-2 border-amber-500 border-t-transparent rounded-full animate-spin" />
            Extracting and analyzing...
          </div>
        )}
      </div>
    </div>
  )
}
