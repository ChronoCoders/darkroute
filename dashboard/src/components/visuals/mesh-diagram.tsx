"use client";

import { motion } from "framer-motion";

import type { RelayRoleCounts } from "@/lib/types";

// Inline SVG visualization of the relay mesh. Three role nodes
// (guard / middle / exit) connected by gradient lines. Node radius
// scales with the available relay count for that role so an empty
// role visually shrinks. Live data: counts come from /api/v1/usage.

interface MeshDiagramProps {
  counts: RelayRoleCounts;
  height?: number;
}

const NODE_X = { guard: 60, middle: 200, exit: 340 } as const;
const NODE_Y = 60;
const MIN_R = 14;
const MAX_R = 26;

function radiusFor(count: number, peak: number) {
  if (peak === 0) return MIN_R;
  const t = Math.min(1, count / peak);
  return MIN_R + (MAX_R - MIN_R) * t;
}

export function MeshDiagram({ counts, height = 140 }: MeshDiagramProps) {
  const peak = Math.max(counts.guard, counts.middle, counts.exit, 1);
  const nodes = [
    { role: "inbound" as const, label: "Inbound", count: counts.guard, x: NODE_X.guard },
    { role: "transit" as const, label: "Transit", count: counts.middle, x: NODE_X.middle },
    { role: "outbound" as const, label: "Outbound", count: counts.exit, x: NODE_X.exit },
  ];
  const allHealthy = counts.guard > 0 && counts.middle > 0 && counts.exit > 0;

  return (
    <div className="relative">
      <svg
        viewBox="0 0 400 140"
        preserveAspectRatio="xMidYMid meet"
        width="100%"
        height={height}
        role="img"
        aria-label="Network availability"
      >
        <defs>
          <linearGradient id="mesh-link" x1="0" x2="1" y1="0" y2="0">
            <stop offset="0%" stopColor="rgb(228 228 231 / 0.05)" />
            <stop offset="50%" stopColor="rgb(228 228 231 / 0.3)" />
            <stop offset="100%" stopColor="rgb(228 228 231 / 0.05)" />
          </linearGradient>
          <radialGradient id="node-fill" cx="0.3" cy="0.3" r="0.8">
            <stop offset="0%" stopColor="rgb(244 244 245)" />
            <stop offset="100%" stopColor="rgb(63 63 70)" />
          </radialGradient>
          <radialGradient id="node-empty" cx="0.3" cy="0.3" r="0.8">
            <stop offset="0%" stopColor="rgb(82 82 91)" />
            <stop offset="100%" stopColor="rgb(24 24 27)" />
          </radialGradient>
        </defs>

        {/* connecting lines */}
        <motion.line
          x1={NODE_X.guard}
          y1={NODE_Y}
          x2={NODE_X.middle}
          y2={NODE_Y}
          stroke="url(#mesh-link)"
          strokeWidth={1.5}
          initial={{ pathLength: 0 }}
          animate={{ pathLength: 1 }}
          transition={{ duration: 0.6, ease: "easeOut" }}
        />
        <motion.line
          x1={NODE_X.middle}
          y1={NODE_Y}
          x2={NODE_X.exit}
          y2={NODE_Y}
          stroke="url(#mesh-link)"
          strokeWidth={1.5}
          initial={{ pathLength: 0 }}
          animate={{ pathLength: 1 }}
          transition={{ duration: 0.6, delay: 0.15, ease: "easeOut" }}
        />

        {/* nodes */}
        {nodes.map((n, i) => {
          const r = radiusFor(n.count, peak);
          const fill = n.count > 0 ? "url(#node-fill)" : "url(#node-empty)";
          return (
            <g key={n.role}>
              {n.count > 0 && (
                <motion.circle
                  cx={n.x}
                  cy={NODE_Y}
                  r={r + 6}
                  fill="rgb(228 228 231 / 0.08)"
                  initial={{ scale: 0.8, opacity: 0 }}
                  animate={{ scale: [0.8, 1.1, 0.95], opacity: [0, 0.6, 0.3] }}
                  transition={{
                    duration: 2.4,
                    delay: i * 0.2,
                    repeat: Infinity,
                    repeatType: "loop",
                  }}
                  style={{ transformOrigin: `${n.x}px ${NODE_Y}px` }}
                />
              )}
              <motion.circle
                cx={n.x}
                cy={NODE_Y}
                r={r}
                fill={fill}
                stroke="rgb(228 228 231 / 0.18)"
                strokeWidth={1}
                initial={{ scale: 0, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{
                  duration: 0.5,
                  delay: 0.1 + i * 0.08,
                  ease: "easeOut",
                }}
                style={{ transformOrigin: `${n.x}px ${NODE_Y}px` }}
              />
              <text
                x={n.x}
                y={NODE_Y + 5}
                textAnchor="middle"
                className="fill-zinc-900 font-semibold"
                fontSize="13"
              >
                {n.count}
              </text>
              <text
                x={n.x}
                y={NODE_Y + r + 18}
                textAnchor="middle"
                className="fill-zinc-500 uppercase"
                fontSize="9"
                style={{ letterSpacing: "0.14em" }}
              >
                {n.label}
              </text>
            </g>
          );
        })}
      </svg>
      <div className="mt-1 flex items-center justify-between text-[11px] text-zinc-500">
        <span className="uppercase tracking-[0.14em]">Network health</span>
        <span
          className={`flex items-center gap-1.5 ${
            allHealthy ? "text-emerald-400" : "text-amber-400"
          }`}
        >
          <span
            className={`h-1.5 w-1.5 rounded-full ${
              allHealthy ? "bg-emerald-400" : "bg-amber-400"
            }`}
          />
          {allHealthy ? "All layers healthy" : "Coverage gap"}
        </span>
      </div>
    </div>
  );
}
