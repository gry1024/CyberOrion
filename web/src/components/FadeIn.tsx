// FadeIn — shared entrance animation for panels/cards:
// { filter: blur(10px), opacity: 0, y: 20 } → clear, easeOut; pass `delay`
// for ~0.08s staggers. Renders instantly under prefers-reduced-motion.

import type { ReactNode } from 'react'
import { motion, useReducedMotion } from 'framer-motion'

export function FadeIn({
  children,
  delay = 0,
  className = '',
}: {
  children: ReactNode
  delay?: number
  className?: string
}) {
  const reduced = useReducedMotion()
  if (reduced) return <div className={className}>{children}</div>
  return (
    <motion.div
      className={className}
      initial={{ filter: 'blur(10px)', opacity: 0, y: 20 }}
      animate={{ filter: 'blur(0px)', opacity: 1, y: 0 }}
      transition={{ duration: 0.6, delay, ease: 'easeOut' }}
    >
      {children}
    </motion.div>
  )
}
