import { cn } from '../../lib/cn.js'

export function Card({ className, ...props }) {
  return (
    <div
      className={cn('rounded-doc border border-rule bg-card px-5 py-4', className)}
      {...props}
    />
  )
}
