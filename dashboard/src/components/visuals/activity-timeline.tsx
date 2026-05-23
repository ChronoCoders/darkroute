"use client";

import { motion } from "framer-motion";
import { KeyRound } from "lucide-react";

import { formatDateTime, shortId, timeSince } from "@/lib/format";

// Compact left-rail timeline view for token issuance events.
// Vertical dotted line with a node per event; metadata reads cleanly
// at a glance. Used on the Tokens page in place of the table.

interface ActivityTimelineProps {
  items: Array<{ id: string; issued_at: string }>;
}

export function ActivityTimeline({ items }: ActivityTimelineProps) {
  return (
    <ol className="relative">
      <div
        aria-hidden
        className="pointer-events-none absolute left-[19px] top-3 bottom-3 w-px bg-gradient-to-b from-white/0 via-white/10 to-white/0"
      />
      {items.map((item, i) => (
        <motion.li
          key={item.id}
          initial={{ opacity: 0, x: -8 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.3, delay: Math.min(i * 0.03, 0.4) }}
          className="relative flex items-start gap-4 py-3"
        >
          <div className="relative z-10 flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-white/[0.06] bg-zinc-950">
            <KeyRound className="h-3.5 w-3.5 text-zinc-400" />
          </div>
          <div className="flex min-w-0 flex-1 items-center justify-between gap-4">
            <div className="min-w-0">
              <p className="text-sm text-zinc-200">
                Access key generated
                <span className="ml-2 font-mono text-[11px] text-zinc-500">
                  {shortId(item.id)}
                </span>
              </p>
              <p className="text-[11px] text-zinc-500">
                {formatDateTime(item.issued_at)}
              </p>
            </div>
            <span className="shrink-0 text-xs tabular-nums text-zinc-500">
              {timeSince(item.issued_at)}
            </span>
          </div>
        </motion.li>
      ))}
    </ol>
  );
}
