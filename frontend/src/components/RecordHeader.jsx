import { useCallback, useSyncExternalStore } from 'react'
import { Guilloche } from './Guilloche.jsx'

function useTheme() {
  const theme = useSyncExternalStore(
    (cb) => {
      const obs = new MutationObserver(cb)
      obs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
      return () => obs.disconnect()
    },
    () => document.documentElement.dataset.theme,
  )
  const toggle = useCallback(() => {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'
    document.documentElement.dataset.theme = next
    localStorage.setItem('theme', next)
  }, [])
  return [theme, toggle]
}

export function RecordHeader() {
  const [theme, toggle] = useTheme()
  return (
    <header className="mb-8">
      <div className="flex items-start justify-between gap-4">
        <p className="doc-label mb-3">
          Fayda &middot; wallet registry &middot; internal proof of concept
        </p>
        <button
          type="button"
          onClick={toggle}
          aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
          className="doc-label cursor-pointer rounded-doc border border-rule bg-transparent px-2.5 py-1 hover:border-rule-strong"
        >
          {theme === 'dark' ? 'Light theme' : 'Dark theme'}
        </button>
      </div>
      <h1 className="font-display text-[2.25rem] leading-tight tracking-[-0.01em] max-[420px]:text-[1.75rem]">
        <span className="font-[300]">One verified person, </span>
        <span className="font-[700]">one wallet.</span>
      </h1>
      <p className="mt-2 max-w-[62ch] text-muted">
        A registry binding a Fayda-verified identity to at most one
        self-custodied wallet per chain. No custody taken, no keys held — only
        cryptographic proof of control.
      </p>
      <div className="mt-5 text-verify">
        <Guilloche />
      </div>
    </header>
  )
}
