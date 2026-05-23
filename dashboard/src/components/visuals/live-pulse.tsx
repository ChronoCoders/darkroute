"use client";

import { motion } from "framer-motion";

// A breathing dot indicator. Conveys "this is live data, the system
// is healthy" without text. Used on the mesh-health header and in
// the sidebar's footer to signal the dashboard is connected to the
// authority. Color is intentionally restrained: emerald only when
// the underlying state actually says so.

interface LivePulseProps {
  tone?: "emerald" | "amber" | "rose" | "zinc";
  size?: number;
  className?: string;
}

const TONES: Record<NonNullable<LivePulseProps["tone"]>, string> = {
  emerald: "bg-emerald-400",
  amber: "bg-amber-400",
  rose: "bg-rose-400",
  zinc: "bg-zinc-400",
};

export function LivePulse({
  tone = "emerald",
  size = 8,
  className,
}: LivePulseProps) {
  const halo = TONES[tone];
  return (
    <span
      className={`relative inline-flex shrink-0 ${className ?? ""}`}
      style={{ width: size, height: size }}
      aria-hidden
    >
      <motion.span
        className={`absolute inset-0 rounded-full ${halo} opacity-60`}
        animate={{ scale: [1, 1.8, 1], opacity: [0.6, 0, 0.6] }}
        transition={{ duration: 2, repeat: Infinity, ease: "easeOut" }}
      />
      <span
        className={`relative inline-flex h-full w-full rounded-full ${halo}`}
      />
    </span>
  );
}
