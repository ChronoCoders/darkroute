"use client";

import { motion } from "framer-motion";
import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

import { AnimatedCounter } from "./animated-counter";

// The headline metric primitive used across every authenticated page.
// Visual treatment: oversized animated number, optional accessory
// (sparkline, mini diagram), corner icon, ambient gradient halo on
// hover. Replaces the flat label/value/hint cards from the first cut.

interface MetricCardProps {
  label: string;
  value: number;
  format?: (n: number) => string;
  trailing?: string;
  hint?: string;
  icon?: LucideIcon;
  accessory?: ReactNode;
  emphasis?: "default" | "primary";
  delay?: number;
}

export function MetricCard({
  label,
  value,
  format,
  trailing,
  hint,
  icon: Icon,
  accessory,
  emphasis = "default",
  delay = 0,
}: MetricCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45, delay, ease: "easeOut" }}
      className={`group relative overflow-hidden rounded-2xl border border-white/[0.06] bg-zinc-950/40 p-6 backdrop-blur transition-colors hover:border-white/[0.12]`}
    >
      {emphasis === "primary" && (
        <div
          aria-hidden
          className="pointer-events-none absolute -inset-px rounded-2xl bg-gradient-to-br from-zinc-100/[0.08] via-transparent to-transparent"
        />
      )}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-x-0 -top-px h-px bg-gradient-to-r from-transparent via-white/15 to-transparent opacity-0 transition-opacity group-hover:opacity-100"
      />
      <div className="relative flex items-start justify-between">
        <span className="text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-500">
          {label}
        </span>
        {Icon && (
          <Icon className="h-4 w-4 text-zinc-600 transition-colors group-hover:text-zinc-400" />
        )}
      </div>
      <div className="relative mt-4 flex items-baseline gap-1.5">
        <span className="text-4xl font-semibold tracking-tight tabular-nums text-zinc-100">
          <AnimatedCounter value={value} format={format} />
        </span>
        {trailing && (
          <span className="text-sm font-medium text-zinc-500">{trailing}</span>
        )}
      </div>
      {hint && (
        <p className="relative mt-1 text-xs text-zinc-500">{hint}</p>
      )}
      {accessory && <div className="relative mt-4">{accessory}</div>}
    </motion.div>
  );
}
