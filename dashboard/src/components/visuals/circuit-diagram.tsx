"use client";

import { motion } from "framer-motion";

import { shortId, timeSince } from "@/lib/format";

// Horizontal three-hop visualization of one circuit assignment.
// Replaces a flat table row with a diagram that makes the
// guard → middle → exit topology immediately legible. Subtle stagger
// on mount (per-row delay applied by the caller) gives a sense of
// the recent feed loading in.

interface CircuitDiagramProps {
  id: string;
  guardId: string;
  middleId: string;
  exitId: string;
  createdAt: string;
  delay?: number;
}

export function CircuitDiagram({
  id,
  guardId,
  middleId,
  exitId,
  createdAt,
  delay = 0,
}: CircuitDiagramProps) {
  const hops = [
    { layer: "Inbound", id: guardId },
    { layer: "Transit", id: middleId },
    { layer: "Outbound", id: exitId },
  ];
  return (
    <motion.li
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay, ease: "easeOut" }}
      className="group relative grid grid-cols-[1fr_auto] items-center gap-6 border-b border-white/[0.04] px-6 py-5 last:border-b-0 hover:bg-white/[0.02]"
    >
      <div className="flex min-w-0 items-center gap-3">
        <span className="hidden font-mono text-[10px] uppercase tracking-[0.14em] text-zinc-600 sm:inline">
          {shortId(id)}
        </span>
        <div className="flex min-w-0 flex-1 items-center">
          {hops.map((h, i) => (
            <div key={h.layer + i} className="flex min-w-0 items-center">
              <div className="flex min-w-0 items-center gap-2 rounded-md border border-white/[0.06] bg-zinc-900/40 px-2.5 py-1">
                <span
                  aria-hidden
                  className="h-1.5 w-1.5 rounded-full bg-zinc-400"
                />
                <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-zinc-500">
                  {h.layer}
                </span>
                <span className="font-mono text-xs text-zinc-200">
                  {shortId(h.id)}
                </span>
              </div>
              {i < hops.length - 1 && (
                <svg
                  width="32"
                  height="14"
                  viewBox="0 0 32 14"
                  className="mx-1 shrink-0 text-zinc-600"
                  aria-hidden
                >
                  <defs>
                    <linearGradient
                      id={`hop-${id}-${i}`}
                      x1="0"
                      x2="1"
                      y1="0"
                      y2="0"
                    >
                      <stop offset="0%" stopColor="currentColor" stopOpacity="0.1" />
                      <stop offset="50%" stopColor="currentColor" stopOpacity="0.6" />
                      <stop offset="100%" stopColor="currentColor" stopOpacity="0.1" />
                    </linearGradient>
                  </defs>
                  <line
                    x1="0"
                    y1="7"
                    x2="32"
                    y2="7"
                    stroke={`url(#hop-${id}-${i})`}
                    strokeWidth="1"
                  />
                  <path
                    d="M24 4 L28 7 L24 10"
                    fill="none"
                    stroke="currentColor"
                    strokeOpacity="0.5"
                    strokeWidth="1"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              )}
            </div>
          ))}
        </div>
      </div>
      <span className="shrink-0 text-xs tabular-nums text-zinc-500">
        {timeSince(createdAt)}
      </span>
    </motion.li>
  );
}
