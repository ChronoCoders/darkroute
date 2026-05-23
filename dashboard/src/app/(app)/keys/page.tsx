"use client";

import { motion } from "framer-motion";
import { KeyRound, Sparkles, Terminal } from "lucide-react";

import { PageHeader } from "@/components/app-shell";
import { Skeleton } from "@/components/ui/skeleton";
import { ActivityTimeline } from "@/components/visuals/activity-timeline";
import { LivePulse } from "@/components/visuals/live-pulse";
import { MetricCard } from "@/components/visuals/metric-card";
import { Sparkline } from "@/components/visuals/sparkline";
import { useAccount, useTokens } from "@/lib/queries";

export default function KeysPage() {
  const tokens = useTokens();
  const account = useAccount();
  const status = account.data?.subscription.status;
  const canIssue = status === "active";
  const stamps = tokens.data?.recent.map((t) => t.issued_at) ?? [];

  return (
    <>
      <PageHeader
        title="Access keys"
        description="Anonymous credentials that authorize your connections. Generated using a blind signature scheme — the value is built locally and never linked back to your account."
      />

      <section className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {tokens.isLoading || !tokens.data ? (
          <>
            <Skeleton className="h-48" />
            <Skeleton className="h-48" />
            <Skeleton className="h-48" />
          </>
        ) : (
          <>
            <MetricCard
              label="Total keys"
              value={tokens.data.tokens_issued}
              hint="Generated under this account"
              icon={KeyRound}
              accessory={<Sparkline points={stamps} />}
              emphasis="primary"
            />
            <MetricCard
              label="Last 24 hours"
              value={countLast24h(stamps)}
              hint="Recent generation activity"
              icon={Sparkles}
              accessory={<Sparkline points={stamps} lookbackMs={24 * 3600_000} />}
              delay={0.05}
            />
            <MetricCard
              label="Generation"
              value={canIssue ? 1 : 0}
              format={() => (canIssue ? "Available" : "Unavailable")}
              hint={
                canIssue
                  ? "Key generation is enabled for this account"
                  : "Waiting on account activation"
              }
              delay={0.1}
            />
          </>
        )}
      </section>

      <section className="mt-8 grid grid-cols-1 gap-4 lg:grid-cols-[1fr_440px]">
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45 }}
          className="rounded-2xl border border-white/[0.06] bg-zinc-950/40 backdrop-blur"
        >
          <div className="flex items-center justify-between border-b border-white/[0.04] px-6 py-4">
            <div>
              <p className="text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-500">
                Recent keys
              </p>
              <p className="mt-1 text-xs text-zinc-500">
                Timestamps only — key values are never stored
              </p>
            </div>
            {canIssue && (
              <span className="flex items-center gap-1.5 text-[11px] text-emerald-400">
                <LivePulse tone="emerald" size={6} />
                Live
              </span>
            )}
          </div>
          <div className="px-6 py-4">
            {tokens.isLoading ? (
              <div className="space-y-3">
                <Skeleton className="h-10" />
                <Skeleton className="h-10" />
                <Skeleton className="h-10" />
              </div>
            ) : tokens.data && tokens.data.recent.length > 0 ? (
              <ActivityTimeline items={tokens.data.recent} />
            ) : (
              <div className="px-2 py-12 text-center">
                <KeyRound className="mx-auto h-6 w-6 text-zinc-600" />
                <p className="mt-3 text-sm font-medium text-zinc-200">
                  No keys generated yet
                </p>
                <p className="mt-1 text-xs text-zinc-500">
                  {canIssue
                    ? "Generated keys appear here as soon as your client requests one."
                    : "Awaiting account activation."}
                </p>
              </div>
            )}
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, delay: 0.1 }}
          className="relative overflow-hidden rounded-2xl border border-white/[0.06] bg-zinc-950/40 p-6 backdrop-blur"
        >
          <div className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-500">
            <Terminal className="h-3.5 w-3.5" />
            Generate a key
          </div>
          <p className="mt-2 text-xs text-zinc-500">
            Access keys use a blind signature scheme. Your client builds the
            blinded value locally and only the signed result comes back —
            the key itself stays on your side.
          </p>
          <pre className="mt-4 overflow-x-auto rounded-lg border border-white/[0.06] bg-black/40 p-4 font-mono text-[11px] leading-relaxed text-zinc-300">
{`# Build a blinded value locally
secret=$(openssl rand -hex 32)
blinded=$(client-blind "$secret")

# Request a signed key
curl -X POST https://api.darkroute/api/v1/tokens/issue \\
  -H "Authorization: Bearer $JWT" \\
  -H "Content-Type: application/json" \\
  -d "{\\"blinded\\": \\"$blinded\\"}"

# Unblind locally. The resulting key verifies at any
# network point without revealing your identity.`}
          </pre>
          {!canIssue && (
            <div className="mt-4 flex items-start gap-2 rounded-lg border border-amber-500/20 bg-amber-500/[0.06] px-3 py-2.5 text-[11px] text-amber-200">
              <LivePulse tone="amber" size={6} className="mt-1" />
              <p>
                Key generation is unavailable until your account is
                activated. Existing keys continue to work.
              </p>
            </div>
          )}
        </motion.div>
      </section>
    </>
  );
}

function countLast24h(stamps: string[]): number {
  const cutoff = Date.now() - 24 * 3600 * 1000;
  let count = 0;
  for (const s of stamps) {
    const t = Date.parse(s);
    if (!Number.isNaN(t) && t >= cutoff) count++;
  }
  return count;
}
