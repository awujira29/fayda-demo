import { cva } from 'class-variance-authority'
import { cn } from '../../lib/cn.js'

const button = cva(
  'inline-flex items-center justify-center gap-2 rounded-doc font-ui font-semibold cursor-pointer transition-opacity duration-100 disabled:opacity-40 disabled:cursor-not-allowed',
  {
    variants: {
      variant: {
        // Primary = the accent, because the primary action here IS
        // verification. The one place the accent is spent on a control.
        primary: 'bg-verify text-paper hover:opacity-90 border border-verify',
        outline: 'bg-transparent text-ink border border-rule-strong hover:bg-surface',
        ghost: 'bg-transparent text-muted border border-transparent hover:text-ink hover:bg-surface',
        danger: 'bg-transparent text-danger-ink border border-danger hover:bg-danger-soft',
      },
      size: {
        md: 'text-[0.875rem] px-4 py-2',
        sm: 'text-[0.8125rem] px-3 py-1.5',
      },
    },
    defaultVariants: { variant: 'outline', size: 'md' },
  },
)

export function Button({ className, variant, size, ...props }) {
  return <button className={cn(button({ variant, size }), className)} {...props} />
}
