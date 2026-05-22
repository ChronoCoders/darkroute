"use client";

import { motion } from "framer-motion";
import {
  Activity,
  KeyRound,
  Network,
  ShieldCheck,
} from "lucide-react";

import { PageHeader, StatCard } from "@/components/app-shell";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { useAccount, useCircuits, useTokens, useUsage } from "@/lib/queries";
import {
  formatBytes,
  formatNumber,
  shortId,
  timeSince,
} from "@/lib/format";

export default function DashboardPage() {
  const account = useAccount();
  const usage = useUsage();
  const tokens = useTokens();
  const circuits = useCircuits();

  return (
    <>
      <PageHeader
        title="Overview"
        description="Live picture of your relay mesh and circuit usage."
      />

      <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {usage.isLoading ? (
          <>
            <Skeleton className="h-28" />
            <Skeleton className="h-28" />
            <Skeleton className="h-28" />
            <Skeleton className="h-28" />
          </>
        ) : usage.data ? (
          <>
            <StatCard
              label="Tokens issued"
              value={formatNumber(usage.data.tokens_issued)}
              hint="This billing period"
              icon={KeyRound}
            />
            <StatCard
              label="Circuits assigned"
              value={formatNumber(usage.data.circuits_assigned)}
              hint="This billing period"
              icon={Network}
            />
            <StatCard
              label="Bandwidth"
              value={formatBytes(usage.data.bandwidth_used)}
              hint="Metered usage"
              icon={Activity}
            />
            <StatCard
              label="Relay mesh"
              value={`${usage.data.active_relays.guard}·${usage.data.active_relays.middle}·${usage.data.active_relays.exit}`}
              hint="guard · middle · exit"
              icon={ShieldCheck}
            />
          </>
        ) : null}
      </section>

      <section className="mt-10 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
          className="rounded-xl border border-border/60 bg-card/60 lg:col-span-2"
        >
          <div className="flex items-center justify-between border-b border-border/60 px-5 py-4">
            <div>
              <h3 className="text-sm font-medium">Recent circuits</h3>
              <p className="text-xs text-muted-foreground">
                Last 5 circuit assignments
              </p>
            </div>
          </div>
          {circuits.isLoading ? (
            <div className="space-y-3 p-5">
              <Skeleton className="h-5" />
              <Skeleton className="h-5" />
              <Skeleton className="h-5" />
            </div>
          ) : circuits.data && circuits.data.recent.length > 0 ? (
            <ul className="divide-y divide-border/60">
              {circuits.data.recent.slice(0, 5).map((c) => (
                <li
                  key={c.id}
                  className="flex items-center justify-between px-5 py-3 text-sm"
                >
                  <div className="flex items-center gap-3 font-mono text-xs text-muted-foreground">
                    <Badge variant="outline" className="font-mono">
                      {shortId(c.guard_id)}
                    </Badge>
                    <span>→</span>
                    <Badge variant="outline" className="font-mono">
                      {shortId(c.middle_id)}
                    </Badge>
                    <span>→</span>
                    <Badge variant="outline" className="font-mono">
                      {shortId(c.exit_id)}
                    </Badge>
                  </div>
                  <span className="text-xs text-muted-foreground">
                    {timeSince(c.created_at)}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState
              title="No circuits yet"
              body={
                account.data?.subscription.status === "active"
                  ? "Hit GET /api/v1/circuits/route to request your first assignment."
                  : "Circuit assignment unlocks after your subscription is approved."
              }
            />
          )}
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.05 }}
          className="rounded-xl border border-border/60 bg-card/60"
        >
          <div className="flex items-center justify-between border-b border-border/60 px-5 py-4">
            <div>
              <h3 className="text-sm font-medium">Recent token issuances</h3>
              <p className="text-xs text-muted-foreground">Last 5 events</p>
            </div>
          </div>
          {tokens.isLoading ? (
            <div className="space-y-3 p-5">
              <Skeleton className="h-5" />
              <Skeleton className="h-5" />
              <Skeleton className="h-5" />
            </div>
          ) : tokens.data && tokens.data.recent.length > 0 ? (
            <ul className="divide-y divide-border/60">
              {tokens.data.recent.slice(0, 5).map((t) => (
                <li
                  key={t.id}
                  className="flex items-center justify-between px-5 py-3 text-sm"
                >
                  <span className="font-mono text-xs text-muted-foreground">
                    {shortId(t.id)}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {timeSince(t.issued_at)}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState
              title="No tokens issued"
              body={
                account.data?.subscription.status === "active"
                  ? "Use POST /api/v1/tokens/issue to mint a blind-signed token."
                  : "Token issuance unlocks after approval."
              }
            />
          )}
        </motion.div>
      </section>
    </>
  );
}

function EmptyState({ title, body }: { title: string; body: string }) {
  return (
    <div className="px-5 py-10 text-center">
      <p className="text-sm font-medium">{title}</p>
      <p className="mt-1 text-xs text-muted-foreground">{body}</p>
    </div>
  );
}
