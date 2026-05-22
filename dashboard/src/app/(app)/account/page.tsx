"use client";

import { motion } from "framer-motion";
import { Activity, Clock, Mail, ShieldCheck } from "lucide-react";

import { PageHeader, StatCard, StatusPill } from "@/components/app-shell";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { useAccount, useUsage } from "@/lib/queries";
import {
  formatBytes,
  formatDate,
  formatDateTime,
  formatNumber,
} from "@/lib/format";

export default function AccountPage() {
  const account = useAccount();
  const usage = useUsage();

  if (account.isLoading || !account.data) {
    return (
      <>
        <PageHeader title="Account" />
        <div className="space-y-4">
          <Skeleton className="h-28" />
          <Skeleton className="h-28" />
          <Skeleton className="h-28" />
        </div>
      </>
    );
  }

  const sub = account.data.subscription;

  return (
    <>
      <PageHeader
        title="Account"
        description="Profile and subscription state. Provisioning, billing tier, and approval status."
      />

      <motion.section
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="rounded-2xl border border-border/60 bg-card/40 p-6"
      >
        <div className="flex flex-col gap-6 sm:flex-row sm:items-start sm:justify-between">
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-xs uppercase tracking-wide text-muted-foreground">
              <Mail className="h-3.5 w-3.5" />
              Identity
            </div>
            <p className="text-lg font-medium">{account.data.email}</p>
            <p className="text-xs text-muted-foreground">
              Role: {account.data.role === "admin" ? "Admin" : "Operator"} ·
              Joined {formatDate(account.data.created_at)}
            </p>
          </div>
          <div className="flex flex-col items-start gap-2 sm:items-end">
            <span className="text-xs uppercase tracking-wide text-muted-foreground">
              Subscription
            </span>
            <StatusPill status={sub.status} />
            <p className="font-mono text-xs text-muted-foreground">
              Tier: {sub.tier}
            </p>
          </div>
        </div>

        {sub.status !== "active" && (
          <>
            <Separator className="my-6" />
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-4 text-sm text-amber-200">
              <p className="font-medium">Your account is pending review.</p>
              <p className="mt-1 text-amber-200/80">
                An operator reviews each new subscription before unlocking
                circuit assignment and token issuance. We approve manually to
                screen for fraud and abuse — usually within one business day.
              </p>
            </div>
          </>
        )}
      </motion.section>

      <section className="mt-8 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {usage.isLoading || !usage.data ? (
          <>
            <Skeleton className="h-28" />
            <Skeleton className="h-28" />
            <Skeleton className="h-28" />
            <Skeleton className="h-28" />
          </>
        ) : (
          <>
            <StatCard
              label="Tokens issued"
              value={formatNumber(usage.data.tokens_issued)}
              hint="Lifetime, this subscription"
              icon={ShieldCheck}
            />
            <StatCard
              label="Bandwidth used"
              value={formatBytes(usage.data.bandwidth_used)}
              icon={Activity}
            />
            <StatCard
              label="Circuits"
              value={formatNumber(usage.data.circuits_assigned)}
              hint="This billing period"
            />
            <StatCard
              label="Period ends"
              value={formatDate(usage.data.current_period_end)}
              hint={`Started ${formatDate(usage.data.current_period_start)}`}
              icon={Clock}
            />
          </>
        )}
      </section>

      <motion.section
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.05 }}
        className="mt-8 rounded-2xl border border-border/60 bg-card/40 p-6"
      >
        <h2 className="text-sm font-medium">Billing period</h2>
        <p className="mt-2 text-xs text-muted-foreground">
          Current period: {formatDateTime(sub.current_period_start)} →{" "}
          {formatDateTime(sub.current_period_end)}
        </p>
        <p className="mt-2 text-xs text-muted-foreground">
          Every signup currently lands on the free tier. Tier upgrades
          happen out-of-band — contact us to move to a paid plan.
        </p>
      </motion.section>
    </>
  );
}
