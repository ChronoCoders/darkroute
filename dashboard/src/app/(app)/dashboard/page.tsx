"use client";

import { motion } from "framer-motion";
import {
  Activity,
  ArrowUpRight,
  KeyRound,
  Network,
  ShieldCheck,
} from "lucide-react";
import Link from "next/link";

import { PageHeader } from "@/components/app-shell";
import { Skeleton } from "@/components/ui/skeleton";
import { CircuitDiagram } from "@/components/visuals/circuit-diagram";
import { LivePulse } from "@/components/visuals/live-pulse";
import { MeshDiagram } from "@/components/visuals/mesh-diagram";
import { MetricCard } from "@/components/visuals/metric-card";
import { Sparkline } from "@/components/visuals/sparkline";
import { formatBytes, timeSince } from "@/lib/format";
import { useAccount, useCircuits, useTokens, useUsage } from "@/lib/queries";

export default function DashboardPage() {
  const account = useAccount();
  const usage = useUsage();
  const tokens = useTokens();
  const circuits = useCircuits();

  const tokenStamps = tokens.data?.recent.map((t) => t.issued_at) ?? [];
  const circuitStamps = circuits.data?.recent.map((c) => c.created_at) ?? [];

  return (
    <>
      <PageHeader
        title="Overview"
        description="Live picture of the network and your connection activity. Everything is fetched in real time."
        actions={
          <div className="flex items-center gap-2 rounded-full border border-white/[0.06] bg-zinc-950/60 px-3 py-1.5 text-xs text-zinc-400">
            <LivePulse tone="emerald" size={6} />
            Streaming
          </div>
        }
      />

      <section className="grid grid-cols-1 gap-4 lg:grid-cols-12">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="relative overflow-hidden rounded-2xl border border-white/[0.06] bg-zinc-950/40 p-6 backdrop-blur lg:col-span-6"
        >
          <div
            aria-hidden
            className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top,oklch(0.3_0.02_264/0.25),transparent_60%)]"
          />
          <div className="relative flex items-center justify-between">
            <div>
              <p className="text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-500">
                Network
              </p>
              <p className="mt-1 text-sm text-zinc-400">
                {usage.data
                  ? `${
                      usage.data.active_relays.guard +
                      usage.data.active_relays.middle +
                      usage.data.active_relays.exit
                    } active network points`
                  : "Loading…"}
              </p>
            </div>
            <ShieldCheck className="h-4 w-4 text-zinc-600" />
          </div>
          <div className="relative mt-4">
            {usage.isLoading || !usage.data ? (
              <Skeleton className="h-36" />
            ) : (
              <MeshDiagram counts={usage.data.active_relays} />
            )}
          </div>
        </motion.div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:col-span-6">
          {usage.isLoading || !usage.data || tokens.isLoading || circuits.isLoading ? (
            <>
              <Skeleton className="h-48" />
              <Skeleton className="h-48" />
              <Skeleton className="h-48" />
              <Skeleton className="h-48" />
            </>
          ) : (
            <>
              <MetricCard
                label="Keys generated"
                value={usage.data.tokens_issued}
                hint="Lifetime, this account"
                icon={KeyRound}
                accessory={<Sparkline points={tokenStamps} />}
                delay={0.05}
              />
              <MetricCard
                label="Connection requests"
                value={usage.data.circuits_assigned}
                hint="This billing period"
                icon={Network}
                accessory={<Sparkline points={circuitStamps} />}
                delay={0.1}
              />
              <MetricCard
                label="Data transferred"
                value={usage.data.bandwidth_used}
                format={formatBytes}
                hint="Metered, this period"
                icon={Activity}
                delay={0.15}
              />
              <MetricCard
                label="Period day"
                value={periodDay(usage.data.current_period_start)}
                trailing="of 30"
                hint="Billing cycle progress"
                delay={0.2}
              />
            </>
          )}
        </div>
      </section>

      <section className="mt-8 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, delay: 0.1 }}
          className="rounded-2xl border border-white/[0.06] bg-zinc-950/40 backdrop-blur lg:col-span-2"
        >
          <div className="flex items-center justify-between border-b border-white/[0.04] px-6 py-4">
            <div>
              <p className="text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-500">
                Recent connections
              </p>
              <p className="mt-1 text-xs text-zinc-500">
                Last 5 connection requests
              </p>
            </div>
            <Link
              href="/connections"
              className="inline-flex items-center gap-1 text-xs text-zinc-400 transition hover:text-zinc-200"
            >
              All connections <ArrowUpRight className="h-3 w-3" />
            </Link>
          </div>
          {circuits.isLoading ? (
            <div className="space-y-3 p-6">
              <Skeleton className="h-8" />
              <Skeleton className="h-8" />
              <Skeleton className="h-8" />
            </div>
          ) : circuits.data && circuits.data.recent.length > 0 ? (
            <ol>
              {circuits.data.recent.slice(0, 5).map((c, i) => (
                <CircuitDiagram
                  key={c.id}
                  id={c.id}
                  guardId={c.guard_id}
                  middleId={c.middle_id}
                  exitId={c.exit_id}
                  createdAt={c.created_at}
                  delay={i * 0.04}
                />
              ))}
            </ol>
          ) : (
            <EmptyState
              title="No connections yet"
              body={
                account.data?.subscription.status === "active"
                  ? "Connections appear here as soon as your client requests one."
                  : "Connections unlock after your account is activated."
              }
            />
          )}
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, delay: 0.15 }}
          className="rounded-2xl border border-white/[0.06] bg-zinc-950/40 backdrop-blur"
        >
          <div className="border-b border-white/[0.04] px-6 py-4">
            <p className="text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-500">
              Latest access keys
            </p>
            <p className="mt-1 text-xs text-zinc-500">
              Timestamps only — key values never persist
            </p>
          </div>
          {tokens.isLoading ? (
            <div className="space-y-3 p-6">
              <Skeleton className="h-6" />
              <Skeleton className="h-6" />
              <Skeleton className="h-6" />
            </div>
          ) : tokens.data && tokens.data.recent.length > 0 ? (
            <ul className="divide-y divide-white/[0.04]">
              {tokens.data.recent.slice(0, 5).map((t, i) => (
                <motion.li
                  key={t.id}
                  initial={{ opacity: 0, x: -6 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.3, delay: i * 0.04 }}
                  className="flex items-center justify-between px-6 py-3"
                >
                  <span className="flex items-center gap-2 text-xs text-zinc-300">
                    <span className="h-1 w-1 rounded-full bg-zinc-500" />
                    <span className="font-mono text-[10px] text-zinc-500">
                      {t.id.slice(0, 8)}
                    </span>
                  </span>
                  <span className="text-xs tabular-nums text-zinc-500">
                    {timeSince(t.issued_at)}
                  </span>
                </motion.li>
              ))}
            </ul>
          ) : (
            <EmptyState
              title="No keys generated yet"
              body={
                account.data?.subscription.status === "active"
                  ? "Generate an access key from your client to see it here."
                  : "Key generation unlocks after your account is activated."
              }
            />
          )}
        </motion.div>
      </section>
    </>
  );
}

function periodDay(periodStart: string): number {
  const start = Date.parse(periodStart);
  if (Number.isNaN(start)) return 0;
  return Math.max(0, Math.floor((Date.now() - start) / (24 * 3600 * 1000)));
}

function EmptyState({ title, body }: { title: string; body: string }) {
  return (
    <div className="px-6 py-10 text-center">
      <p className="text-sm font-medium text-zinc-300">{title}</p>
      <p className="mt-1 text-xs text-zinc-500">{body}</p>
    </div>
  );
}
