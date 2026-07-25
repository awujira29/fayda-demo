/**
 * The security-print band: interleaved sine guilloché, the mark of an issued
 * document. Inline SVG, currentColor, subtle by design — a texture, not a
 * decoration. Appears exactly once, under the record masthead.
 */
export function Guilloche({ className }) {
  const wave = (amp, phase, n) => {
    let d = `M0 8`
    for (let x = 0; x <= 1200; x += 12) {
      const y = 8 + amp * Math.sin((x / 1200) * Math.PI * n + phase)
      d += ` L${x} ${y.toFixed(2)}`
    }
    return d
  }
  return (
    <svg
      viewBox="0 0 1200 16"
      preserveAspectRatio="none"
      aria-hidden="true"
      className={className}
      style={{ width: '100%', height: 14, display: 'block' }}
    >
      <g fill="none" stroke="currentColor" strokeWidth="0.75" opacity="0.55">
        <path d={wave(5, 0, 26)} />
        <path d={wave(5, Math.PI, 26)} />
        <path d={wave(3, Math.PI / 2, 26)} opacity="0.6" />
      </g>
    </svg>
  )
}
