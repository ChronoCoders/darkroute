"use client";

import { motion } from "framer-motion";

// Reads an array of ISO timestamps, buckets them into N equal-width
// intervals across the lookback window, and draws the histogram as a
// line. Used to show real activity over time on metric cards — the
// data is real (timestamps from the authority), the visual is the
// trend itself, not decoration.

interface SparklineProps {
  points: string[]; // ISO timestamps
  buckets?: number;
  lookbackMs?: number;
  height?: number;
  className?: string;
}

export function Sparkline({
  points,
  buckets = 24,
  lookbackMs = 24 * 60 * 60 * 1000,
  height = 36,
  className,
}: SparklineProps) {
  const now = Date.now();
  const cutoff = now - lookbackMs;

  const counts = new Array<number>(buckets).fill(0);
  for (const iso of points) {
    const t = Date.parse(iso);
    if (Number.isNaN(t) || t < cutoff) continue;
    const idx = Math.min(
      buckets - 1,
      Math.floor(((t - cutoff) / lookbackMs) * buckets),
    );
    counts[idx]++;
  }
  const max = Math.max(1, ...counts);

  const viewWidth = 100;
  const viewHeight = 28;
  const step = viewWidth / (buckets - 1);
  const yFor = (n: number) => viewHeight - (n / max) * (viewHeight - 4) - 2;

  const linePoints = counts.map((c, i) => `${i * step},${yFor(c)}`).join(" ");
  const areaPath = `M0,${viewHeight} L${counts
    .map((c, i) => `${i * step},${yFor(c)}`)
    .join(" L")} L${viewWidth},${viewHeight} Z`;

  const total = counts.reduce((a, b) => a + b, 0);

  return (
    <svg
      viewBox={`0 0 ${viewWidth} ${viewHeight}`}
      preserveAspectRatio="none"
      width="100%"
      height={height}
      className={className}
      aria-label={`Recent activity sparkline, ${total} events in lookback window`}
      role="img"
    >
      <defs>
        <linearGradient id="spark-fill" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor="rgb(228 228 231 / 0.25)" />
          <stop offset="100%" stopColor="rgb(228 228 231 / 0)" />
        </linearGradient>
      </defs>
      <motion.path
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.4 }}
        d={areaPath}
        fill="url(#spark-fill)"
      />
      <motion.polyline
        initial={{ pathLength: 0, opacity: 0 }}
        animate={{ pathLength: 1, opacity: 1 }}
        transition={{ duration: 0.8, ease: "easeOut" }}
        fill="none"
        stroke="rgb(228 228 231)"
        strokeWidth={1.2}
        strokeLinejoin="round"
        strokeLinecap="round"
        points={linePoints}
      />
    </svg>
  );
}
