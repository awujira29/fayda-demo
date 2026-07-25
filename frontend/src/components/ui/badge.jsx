import { cva } from 'class-variance-authority'
import { cn } from '../../lib/cn.js'

// Status marks. Text label always present — status must survive greyscale.
const badge = cva(
  'inline-flex items-center rounded-[3px] font-mono text-[0.65rem] font-medium uppercase tracking-[0.08em] px-2 py-0.5 border',
  {
    variants: {
      status: {
        active: 'bg-verify-soft text-verify-ink border-verify/30',
        pending: 'bg-cooling-soft text-cooling-ink border-cooling/30',
        archived: 'bg-surface text-muted border-rule',
        cancelled: 'bg-danger-soft text-danger-ink border-danger/30',
        none: 'bg-surface text-muted border-rule',
      },
    },
    defaultVariants: { status: 'none' },
  },
)

export function Badge({ className, status, children, ...props }) {
  return (
    <span className={cn(badge({ status }), className)} {...props}>
      {children}
    </span>
  )
}
