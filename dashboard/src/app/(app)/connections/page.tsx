"use client";

import { motion } from "framer-motion";
import { Activity, Network } from "lucide-react";

import { PageHeader } from "@/components/app-shell";
import { Skeleton } from "@/components/ui/skeleton";
import { LivePulse } from "@/components/visuals/live-pulse";
import { MeshDiagram } from "@/components/visuals/mesh-diagram";
import { MetricCard } from "@/components/visuals/metric-card";
import { useAccount, useUsage } from "@/lib/queries";

export default function ConnectionsPage() {
  const usage = useUsage();
  const account = useAccount();
  const status = account.data?.subscription.status;
  const canRoute = status === "active";

  return (
    <>
      <PageHeader
        title="Connections"
        description="Your app builds its own route through several separate network points. Nothing about those routes is stored here."
      />

      <section className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {usage.isLoading || !usage.data ? (
          <>
            <Skeleton className="h-48" />
            <Skeleton className="h-48" />
            <Skeleton className="h-48" />
          </>
        ) : (
          <>
            <MetricCard
              label="Inbound · Transit pool"
              value={
                usage.data.active_relays.guard + usage.data.active_relays.middle
              }
              trailing={`/${
                usage.data.active_relays.guard +
                usage.data.active_relays.middle +
                usage.data.active_relays.exit
              }`}
              hint="Active network points feeding new connections"
              icon={Activity}
              delay={0.05}
            />
            <MetricCard
              label="Outbound pool"
              value={usage.data.active_relays.exit}
              hint="Residential outbound points"
              delay={0.1}
            />
          </>
        )}
      </section>

      <section className="mt-8 grid grid-cols-1 gap-4 lg:grid-cols-[1fr_360px]">
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45 }}
          className="rounded-2xl border border-white/[0.06] bg-zinc-950/40 backdrop-blur"
        >
          <div className="flex items-center justify-between border-b border-white/[0.04] px-6 py-4">
            <div>
              <p className="text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-500">
                Connections
              </p>
              <p className="mt-1 text-xs text-zinc-500">
                Private by design
              </p>
            </div>
            {canRoute && (
              <span className="flex items-center gap-1.5 text-[11px] text-emerald-400">
                <LivePulse tone="emerald" size={6} />
                Live
              </span>
            )}
          </div>
          <div className="px-6 py-16 text-center">
            <Network className="mx-auto h-6 w-6 text-zinc-600" />
            <p className="mt-3 text-sm text-zinc-300">
              QuietHop keeps no record of your connections. Your app chooses its
              own route, and we never see which one.
            </p>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, delay: 0.1 }}
          className="space-y-4"
        >
          <div className="relative overflow-hidden rounded-2xl border border-white/[0.06] bg-zinc-950/40 p-6 backdrop-blur">
            <div
              aria-hidden
              className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top,oklch(0.3_0.02_264/0.18),transparent_60%)]"
            />
            <p className="relative text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-500">
              Network
            </p>
            <p className="relative mt-1 text-xs text-zinc-500">
              Active network points right now
            </p>
            <div className="relative mt-4">
              {usage.isLoading || !usage.data ? (
                <Skeleton className="h-36" />
              ) : (
                <MeshDiagram counts={usage.data.active_relays} />
              )}
            </div>
          </div>

          <div className="rounded-2xl border border-white/[0.06] bg-zinc-950/40 p-6 backdrop-blur">
            <p className="text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-500">
              How connections work
            </p>
            <ol className="mt-4 space-y-3 text-xs text-zinc-400">
              <li className="flex gap-3">
                <span className="font-mono text-[10px] text-zinc-600">01</span>
                <span>
                  Each connection is routed through multiple network points,
                  selected at random from the active pool.
                </span>
              </li>
              <li className="flex gap-3">
                <span className="font-mono text-[10px] text-zinc-600">02</span>
                <span>
                  Each layer is a distinct point. The same point never serves
                  two layers in one connection.
                </span>
              </li>
              <li className="flex gap-3">
                <span className="font-mono text-[10px] text-zinc-600">03</span>
                <span>
                  Each network point only sees its adjacent layers, never the
                  whole path.
                </span>
              </li>
            </ol>
          </div>
        </motion.div>
      </section>
    </>
  );
}
