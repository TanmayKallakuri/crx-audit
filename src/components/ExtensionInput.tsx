import { useState, useCallback, useRef } from 'react'
import { Search, Upload, FileText } from 'lucide-react'
import type { ExtensionFiles, InputMethod } from '../types'
import { extractExtensionId } from '../utils/helpers'
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
    { key: 'id', label: 'Extension ID', icon: <Search className="w-4 h-4" /> },
    { key: 'upload', label: 'Upload File', icon: <Upload className="w-4 h-4" /> },
    { key: 'paste', label: 'Paste Manifest', icon: <FileText className="w-4 h-4" /> },
  ]

  const handleError = (err: unknown) => {
    setError(err instanceof Error ? err.message : 'An unexpected error occurred.')
  }

  const handleIdSubmit = async () => {
    setError(null)
    const extensionId = extractExtensionId(idInput)
    if (!extensionId) {
      setError('Please enter a valid 32-character extension ID or Chrome Web Store URL.')
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

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragActive(true)
  }, [])

  const handleDragLeave = useCallback(() => {
    setDragActive(false)
  }, [])

  return (
    <div className="w-full max-w-2xl mx-auto">
      {/* Tab Bar */}
      <div className="flex border-b border-gray-800 mb-6">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => { setActiveTab(tab.key); setError(null) }}
            className={`flex items-center gap-2 px-5 py-3 text-sm font-medium transition-colors border-b-2 -mb-px ${
              activeTab === tab.key
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="space-y-4">
        {activeTab === 'id' && (
          <div className="space-y-3">
            <label className="block text-sm text-gray-400">
              Enter a Chrome extension ID or Web Store URL
            </label>
            <div className="flex gap-3">
              <input
                type="text"
                value={idInput}
                onChange={(e) => setIdInput(e.target.value)}
                placeholder="e.g. cjpalhdlnbpafiamejdnhcphjbkeiagm"
                className="flex-1 bg-gray-900 border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                onKeyDown={(e) => e.key === 'Enter' && handleIdSubmit()}
              />
              <button
                onClick={handleIdSubmit}
                disabled={loading || !idInput.trim()}
                className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm font-medium rounded-lg transition-colors"
              >
                {loading ? 'Scanning...' : 'Scan'}
              </button>
            </div>
          </div>
        )}

        {activeTab === 'upload' && (
          <div
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-colors ${
              dragActive
                ? 'border-blue-500 bg-blue-500/10'
                : 'border-gray-700 hover:border-gray-600 bg-gray-900/50'
            }`}
          >
            <Upload className="w-10 h-10 text-gray-500 mx-auto mb-3" />
            <p className="text-sm text-gray-300 mb-1">
              Drag and drop a <span className="text-blue-400 font-medium">.crx</span> or{' '}
              <span className="text-blue-400 font-medium">.zip</span> file here
            </p>
            <p className="text-xs text-gray-500">or click to browse</p>
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
          <div className="space-y-3">
            <label className="block text-sm text-gray-400">
              Paste the contents of manifest.json
            </label>
            <textarea
              value={manifestInput}
              onChange={(e) => setManifestInput(e.target.value)}
              placeholder='{"manifest_version": 3, "name": "My Extension", ...}'
              rows={10}
              className="w-full bg-gray-900 border border-gray-700 rounded-lg px-4 py-3 text-sm text-gray-100 placeholder-gray-600 font-mono focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 resize-y"
            />
            <button
              onClick={handleManifestSubmit}
              disabled={!manifestInput.trim()}
              className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm font-medium rounded-lg transition-colors"
            >
              Analyze
            </button>
          </div>
        )}

        {/* Error Display */}
        {error && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-400">
            {error}
          </div>
        )}

        {/* Loading */}
        {loading && (
          <div className="flex items-center justify-center gap-3 py-4 text-gray-400 text-sm">
            <div className="w-4 h-4 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
            Extracting and analyzing extension...
          </div>
        )}
      </div>
    </div>
  )
}
