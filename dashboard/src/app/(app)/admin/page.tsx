"use client";

import { motion } from "framer-motion";
import { CheckCircle2, Loader2, ShieldCheck, Users } from "lucide-react";
import { toast } from "sonner";

import { PageHeader, StatusPill } from "@/components/app-shell";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { LivePulse } from "@/components/visuals/live-pulse";
import { MetricCard } from "@/components/visuals/metric-card";
import {
  useAdminSubscribers,
  useApproveSubscriber,
} from "@/lib/queries";
import { formatDate, formatNumber, timeSince } from "@/lib/format";
import type { AdminSubscriber } from "@/lib/types";

export default function AdminPage() {
  const subscribers = useAdminSubscribers();
  const approve = useApproveSubscriber();

  const pending =
    subscribers.data?.subscribers.filter((s) => s.status === "pending_review") ??
    [];
  const active =
    subscribers.data?.subscribers.filter((s) => s.status === "active") ?? [];

  function handleActivate(s: AdminSubscriber) {
    approve.mutate(
      { subscriberId: s.id },
      {
        onSuccess: () => toast.success(`Activated ${s.email}`),
        onError: () => toast.error("Activation failed. Please retry."),
      },
    );
  }

  return (
    <>
      <PageHeader
        title="Admin"
        description="Account review and activation. Acting here is the only way to enable connections for a new account."
      />

      <section className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        {subscribers.isLoading ? (
          <>
            <Skeleton className="h-36" />
            <Skeleton className="h-36" />
            <Skeleton className="h-36" />
          </>
        ) : (
          <>
            <MetricCard
              label="Under review"
              value={pending.length}
              hint="Awaiting activation"
              icon={ShieldCheck}
              emphasis={pending.length > 0 ? "primary" : "default"}
            />
            <MetricCard
              label="Active accounts"
              value={active.length}
              icon={Users}
              delay={0.05}
            />
            <MetricCard
              label="Total accounts"
              value={subscribers.data?.subscribers.length ?? 0}
              hint="All states including lapsed"
              delay={0.1}
            />
          </>
        )}
      </section>

      <motion.section
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.45 }}
        className="mt-8 rounded-2xl border border-white/[0.06] bg-zinc-950/40 backdrop-blur"
      >
        <div className="flex items-center justify-between border-b border-white/[0.04] px-6 py-4">
          <div>
            <p className="text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-500">
              Activation queue
            </p>
            <p className="mt-1 text-xs text-zinc-500">
              Activating enables connections and access key generation for the
              account
            </p>
          </div>
          {pending.length > 0 && (
            <span className="flex items-center gap-1.5 text-[11px] text-amber-300">
              <LivePulse tone="amber" size={6} />
              {pending.length} waiting
            </span>
          )}
        </div>
        {subscribers.isLoading ? (
          <div className="grid grid-cols-1 gap-3 p-6 sm:grid-cols-2">
            <Skeleton className="h-24" />
            <Skeleton className="h-24" />
          </div>
        ) : pending.length > 0 ? (
          <ul className="grid grid-cols-1 gap-3 p-6 sm:grid-cols-2">
            {pending.map((s, i) => (
              <motion.li
                key={s.id}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.35, delay: i * 0.04 }}
                className="group relative flex flex-col gap-4 rounded-xl border border-white/[0.05] bg-zinc-900/40 p-4 transition-colors hover:border-white/[0.12]"
              >
                <div className="flex items-start gap-3">
                  <Avatar className="h-9 w-9 ring-1 ring-white/10">
                    <AvatarFallback className="bg-gradient-to-br from-zinc-700 to-zinc-900 text-[11px] text-zinc-100">
                      {s.email.slice(0, 2).toUpperCase()}
                    </AvatarFallback>
                  </Avatar>
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium text-zinc-100">
                      {s.email}
                    </p>
                    <p className="font-mono text-[10px] text-zinc-500">
                      {s.id}
                    </p>
                  </div>
                  <StatusPill status="pending_review" />
                </div>
                <div className="flex items-center justify-between text-[11px] text-zinc-500">
                  <span>
                    Signed up {formatDate(s.subscriber_created_at)} ·{" "}
                    {timeSince(s.subscriber_created_at)}
                  </span>
                  <Button
                    size="sm"
                    onClick={() => handleActivate(s)}
                    disabled={
                      approve.isPending &&
                      approve.variables?.subscriberId === s.id
                    }
                    className="gap-2 bg-zinc-100 text-zinc-900 hover:bg-white"
                  >
                    {approve.isPending &&
                    approve.variables?.subscriberId === s.id ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <CheckCircle2 className="h-3.5 w-3.5" />
                    )}
                    Activate
                  </Button>
                </div>
              </motion.li>
            ))}
          </ul>
        ) : (
          <div className="px-6 py-14 text-center">
            <CheckCircle2 className="mx-auto h-6 w-6 text-emerald-400" />
            <p className="mt-3 text-sm font-medium text-zinc-200">Inbox zero</p>
            <p className="mt-1 text-xs text-zinc-500">
              No accounts waiting for review.
            </p>
          </div>
        )}
      </motion.section>

      <motion.section
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.45, delay: 0.05 }}
        className="mt-8 rounded-2xl border border-white/[0.06] bg-zinc-950/40 backdrop-blur"
      >
        <div className="border-b border-white/[0.04] px-6 py-4">
          <p className="text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-500">
            All accounts
          </p>
          <p className="mt-1 text-xs text-zinc-500">
            Active, under review, and historical
          </p>
        </div>
        {subscribers.isLoading ? (
          <div className="space-y-3 p-6">
            <Skeleton className="h-8" />
            <Skeleton className="h-8" />
            <Skeleton className="h-8" />
          </div>
        ) : subscribers.data && subscribers.data.subscribers.length > 0 ? (
          <Table>
            <TableHeader>
              <TableRow className="border-b border-white/[0.04] hover:bg-transparent">
                <TableHead className="text-[10px] uppercase tracking-[0.14em] text-zinc-500">
                  Email
                </TableHead>
                <TableHead className="text-[10px] uppercase tracking-[0.14em] text-zinc-500">
                  Status
                </TableHead>
                <TableHead className="text-[10px] uppercase tracking-[0.14em] text-zinc-500">
                  Plan
                </TableHead>
                <TableHead className="text-[10px] uppercase tracking-[0.14em] text-zinc-500">
                  Keys
                </TableHead>
                <TableHead className="text-[10px] uppercase tracking-[0.14em] text-zinc-500">
                  Signed up
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {subscribers.data.subscribers.map((s) => (
                <TableRow key={s.id} className="border-b border-white/[0.04]">
                  <TableCell className="text-sm">
                    <p className="text-zinc-100">{s.email}</p>
                    <p className="font-mono text-[10px] text-zinc-600">{s.id}</p>
                  </TableCell>
                  <TableCell>
                    {s.status ? <StatusPill status={s.status} /> : "—"}
                  </TableCell>
                  <TableCell className="text-xs text-zinc-400">
                    {s.tier || "—"}
                  </TableCell>
                  <TableCell className="text-xs tabular-nums text-zinc-400">
                    {formatNumber(s.tokens_issued)}
                  </TableCell>
                  <TableCell className="text-xs text-zinc-500">
                    {formatDate(s.subscriber_created_at)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <div className="px-6 py-12 text-center text-sm text-zinc-500">
            No accounts found.
          </div>
        )}
      </motion.section>
    </>
  );
}
