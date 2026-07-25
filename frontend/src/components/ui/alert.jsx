import { cva } from 'class-variance-authority'
import { cn } from '../../lib/cn.js'

const alert = cva('rounded-doc border px-4 py-3 text-[0.875rem] leading-relaxed', {
  variants: {
    tone: {
      info: 'bg-surface border-rule text-ink',
      success: 'bg-verify-soft border-verify/30 text-verify-ink',
      warning: 'bg-cooling-soft border-cooling/30 text-cooling-ink',
      danger: 'bg-danger-soft border-danger/30 text-danger-ink',
    },
  },
  defaultVariants: { tone: 'info' },
})

export function Alert({ className, tone, title, children, ...props }) {
  return (
    <div role={tone === 'danger' ? 'alert' : 'status'} className={cn(alert({ tone }), className)} {...props}>
      {title && <div className="font-semibold mb-0.5">{title}</div>}
      {children}
    </div>
  )
}
