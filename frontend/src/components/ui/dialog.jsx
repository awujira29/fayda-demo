import * as DialogPrimitive from '@radix-ui/react-dialog'
import { cn } from '../../lib/cn.js'

// The only modal in the product. It exists because signing an attestation
// needs protected focus — the user is about to authorise something with a
// key, and the wallet extension will open alongside.
export const Dialog = DialogPrimitive.Root
export const DialogTrigger = DialogPrimitive.Trigger
export const DialogClose = DialogPrimitive.Close

export function DialogContent({ className, children, ...props }) {
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-ink/40" />
      <DialogPrimitive.Content
        className={cn(
          'attest-enter fixed left-1/2 top-1/2 z-50 w-[min(94vw,34rem)] -translate-x-1/2 -translate-y-1/2',
          'max-h-[88vh] overflow-y-auto rounded-doc border border-rule-strong bg-card p-6 shadow-xl',
          className,
        )}
        {...props}
      >
        {children}
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  )
}

export function DialogTitle({ className, ...props }) {
  return (
    <DialogPrimitive.Title
      className={cn('font-display text-[1.25rem] font-bold', className)}
      {...props}
    />
  )
}

export function DialogDescription({ className, ...props }) {
  return (
    <DialogPrimitive.Description className={cn('text-muted text-[0.875rem]', className)} {...props} />
  )
}
