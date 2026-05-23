"use client";

import { motion } from "framer-motion";
import { Activity, Clock, KeyRound, Network, ShieldCheck } from "lucide-react";

import { PageHeader, StatusPill } from "@/components/app-shell";
import { Skeleton } from "@/components/ui/skeleton";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { LivePulse } from "@/components/visuals/live-pulse";
import { MetricCard } from "@/components/visuals/metric-card";
import { useAccount, useUsage } from "@/lib/queries";
import { formatBytes, formatDate, formatDateTime } from "@/lib/format";

export default function AccountPage() {
  const account = useAccount();
  const usage = useUsage();

  if (account.isLoading || !account.data) {
    return (
      <>
        <PageHeader title="Account" />
        <div className="space-y-4">
          <Skeleton className="h-44" />
          <Skeleton className="h-32" />
        </div>
      </>
    );
  }

  const sub = account.data.subscription;
  const initials = account.data.email.slice(0, 2).toUpperCase();
  const periodProgress = computeProgress(
    sub.current_period_start,
    sub.current_period_end,
  );

  return (
    <>
      <PageHeader
        title="Account"
        description="Profile, account state, and billing-period progress."
      />

      <motion.section
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="relative overflow-hidden rounded-2xl border border-white/[0.06] bg-zinc-950/40 p-8 backdrop-blur"
      >
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_right,oklch(0.32_0.02_264/0.25),transparent_60%)]"
        />
        <div className="relative flex flex-col gap-6 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex items-center gap-5">
            <Avatar className="h-14 w-14 ring-1 ring-white/10">
              <AvatarFallback className="bg-gradient-to-br from-zinc-700 to-zinc-900 text-base text-zinc-100">
                {initials}
              </AvatarFallback>
            </Avatar>
            <div>
              <p className="text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-500">
                Operator
              </p>
              <p className="mt-1 text-xl font-semibold text-zinc-100">
                {account.data.email}
              </p>
              <p className="mt-1 text-xs text-zinc-500">
                {account.data.role === "admin" ? "Admin" : "Operator"} · Joined{" "}
                {formatDate(account.data.created_at)}
              </p>
            </div>
          </div>
          <div className="flex flex-col items-start gap-3 sm:items-end">
            <StatusPill status={sub.status} />
            <div className="flex items-center gap-3 text-[11px] text-zinc-500">
              <span className="font-mono uppercase tracking-[0.14em]">
                Plan
              </span>
              <span className="font-mono text-zinc-200">{sub.tier}</span>
            </div>
          </div>
        </div>

        <div className="relative mt-8">
          <div className="flex items-center justify-between text-[11px] text-zinc-500">
            <span className="uppercase tracking-[0.14em]">Billing period</span>
            <span className="tabular-nums">
              {Math.round(periodProgress * 100)}%
            </span>
          </div>
          <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/[0.04]">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${periodProgress * 100}%` }}
              transition={{ duration: 0.8, ease: "easeOut" }}
              className="h-full rounded-full bg-gradient-to-r from-zinc-400 via-zinc-200 to-zinc-400"
            />
          </div>
          <div className="mt-2 flex justify-between text-[11px] text-zinc-500">
            <span>{formatDateTime(sub.current_period_start)}</span>
            <span>{formatDateTime(sub.current_period_end)}</span>
          </div>
        </div>

        {sub.status !== "active" && (
          <div className="relative mt-6 flex items-start gap-3 rounded-xl border border-amber-500/20 bg-amber-500/[0.06] px-4 py-3 text-sm">
            <LivePulse tone="amber" />
            <div>
              <p className="font-medium text-amber-100">
                Awaiting activation
              </p>
              <p className="mt-0.5 text-xs text-amber-200/80">
                Manual review is required before connections and access keys
                unlock. Typically within one business day.
              </p>
            </div>
          </div>
        )}
      </motion.section>

      <section className="mt-8 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {usage.isLoading || !usage.data ? (
          <>
            <Skeleton className="h-36" />
            <Skeleton className="h-36" />
            <Skeleton className="h-36" />
            <Skeleton className="h-36" />
          </>
        ) : (
          <>
            <MetricCard
              label="Keys generated"
              value={usage.data.tokens_issued}
              icon={KeyRound}
              hint="Lifetime, this account"
            />
            <MetricCard
              label="Data transferred"
              value={usage.data.bandwidth_used}
              format={formatBytes}
              icon={Activity}
              hint="This billing period"
              delay={0.05}
            />
            <MetricCard
              label="Connections"
              value={usage.data.circuits_assigned}
              icon={Network}
              hint="Requests this period"
              delay={0.1}
            />
            <MetricCard
              label="Network size"
              value={
                usage.data.active_relays.guard +
                usage.data.active_relays.middle +
                usage.data.active_relays.exit
              }
              icon={ShieldCheck}
              hint="Active network points"
              delay={0.15}
            />
          </>
        )}
      </section>

      <motion.section
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.45, delay: 0.1 }}
        className="mt-8 rounded-2xl border border-white/[0.06] bg-zinc-950/40 p-6 backdrop-blur"
      >
        <div className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-500">
          <Clock className="h-3.5 w-3.5" />
          Plan upgrades
        </div>
        <p className="mt-2 text-sm text-zinc-400">
          Every signup currently lands on the free plan. Plan upgrades happen
          out-of-band — contact us to move to a paid plan.
        </p>
      </motion.section>
    </>
  );
}

function computeProgress(startISO: string, endISO: string): number {
  const start = Date.parse(startISO);
  const end = Date.parse(endISO);
  if (Number.isNaN(start) || Number.isNaN(end) || end <= start) return 0;
  const now = Date.now();
  if (now <= start) return 0;
  if (now >= end) return 1;
  return (now - start) / (end - start);
}
