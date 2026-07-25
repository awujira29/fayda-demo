import { useEffect, useState } from 'react'
import { cn } from '../lib/cn.js'

/**
 * A machine value rendered as a real button: reachable and copyable from the
 * keyboard, sharing the global focus ring, still mouse/touch-selectable.
 */
export function CopyValue({ value, className, accent = false }) {
  const [copied, setCopied] = useState(false)
  useEffect(() => {
    if (!copied) return
    const t = setTimeout(() => setCopied(false), 1800)
    return () => clearTimeout(t)
  }, [copied])
  return (
    <button
      type="button"
      title="Copy to clipboard"
      aria-label={`Copy ${value}`}
      onClick={() => navigator.clipboard?.writeText(value).then(() => setCopied(true))}
      className={cn(
        'doc-value block w-full cursor-copy border-0 bg-transparent p-0 text-left leading-relaxed hover:underline',
        accent ? 'text-verify-ink' : 'text-ink',
        className,
      )}
    >
      {value}
      {/* persistent live region: toggling only the text is what screen
          readers reliably announce */}
      <span aria-live="polite" className="doc-label ml-2 select-none !text-verify-ink">
        {copied ? 'copied' : ''}
      </span>
    </button>
  )
}
