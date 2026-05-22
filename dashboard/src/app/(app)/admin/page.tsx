"use client";

import { motion } from "framer-motion";
import { CheckCircle2, Loader2, ShieldCheck, Users } from "lucide-react";
import { toast } from "sonner";

import { PageHeader, StatCard, StatusPill } from "@/components/app-shell";
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
import {
  useAdminSubscribers,
  useApproveSubscriber,
} from "@/lib/queries";
import { formatDate, formatNumber } from "@/lib/format";
import type { AdminSubscriber } from "@/lib/types";

export default function AdminPage() {
  const subscribers = useAdminSubscribers();
  const approve = useApproveSubscriber();

  const pending = subscribers.data?.subscribers.filter(
    (s) => s.status === "pending_review",
  ) ?? [];
  const active = subscribers.data?.subscribers.filter(
    (s) => s.status === "active",
  ) ?? [];

  function handleApprove(s: AdminSubscriber) {
    approve.mutate(
      { subscriberId: s.id },
      {
        onSuccess: () => {
          toast.success(`Approved ${s.email}`);
        },
        onError: () => {
          toast.error("Approval failed. Please retry.");
        },
      },
    );
  }

  return (
    <>
      <PageHeader
        title="Admin"
        description="Manual subscriber review and relay topology controls."
      />

      <section className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-3">
        {subscribers.isLoading ? (
          <>
            <Skeleton className="h-28" />
            <Skeleton className="h-28" />
            <Skeleton className="h-28" />
          </>
        ) : (
          <>
            <StatCard
              label="Pending review"
              value={formatNumber(pending.length)}
              hint="Awaiting manual approval"
              icon={ShieldCheck}
            />
            <StatCard
              label="Active subscribers"
              value={formatNumber(active.length)}
              icon={Users}
            />
            <StatCard
              label="Total"
              value={formatNumber(subscribers.data?.subscribers.length ?? 0)}
              hint="Including lapsed and cancelled"
            />
          </>
        )}
      </section>

      <motion.section
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="rounded-2xl border border-border/60 bg-card/40"
      >
        <div className="border-b border-border/60 px-6 py-4">
          <h2 className="text-sm font-medium">Pending approval queue</h2>
          <p className="text-xs text-muted-foreground">
            Manually approve subscribers to unlock their circuit access.
          </p>
        </div>
        {subscribers.isLoading ? (
          <div className="space-y-3 p-6">
            <Skeleton className="h-8" />
            <Skeleton className="h-8" />
          </div>
        ) : pending.length > 0 ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Subscriber</TableHead>
                <TableHead>Joined</TableHead>
                <TableHead>Tier</TableHead>
                <TableHead className="text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {pending.map((s) => (
                <TableRow key={s.id}>
                  <TableCell>
                    <p className="font-medium">{s.email}</p>
                    <p className="font-mono text-[11px] text-muted-foreground">
                      {s.id}
                    </p>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {formatDate(s.subscriber_created_at)}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {s.tier || "—"}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      size="sm"
                      onClick={() => handleApprove(s)}
                      disabled={
                        approve.isPending &&
                        approve.variables?.subscriberId === s.id
                      }
                      className="gap-2"
                    >
                      {approve.isPending &&
                      approve.variables?.subscriberId === s.id ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <CheckCircle2 className="h-3.5 w-3.5" />
                      )}
                      Approve
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <div className="px-6 py-12 text-center">
            <CheckCircle2 className="mx-auto h-6 w-6 text-emerald-400" />
            <p className="mt-3 text-sm font-medium">Inbox zero</p>
            <p className="mt-1 text-xs text-muted-foreground">
              No subscribers waiting for review.
            </p>
          </div>
        )}
      </motion.section>

      <motion.section
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.05 }}
        className="mt-8 rounded-2xl border border-border/60 bg-card/40"
      >
        <div className="border-b border-border/60 px-6 py-4">
          <h2 className="text-sm font-medium">All subscribers</h2>
          <p className="text-xs text-muted-foreground">
            Approved, pending, and historical subscribers.
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
              <TableRow>
                <TableHead>Email</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Tier</TableHead>
                <TableHead>Tokens</TableHead>
                <TableHead>Joined</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {subscribers.data.subscribers.map((s) => (
                <TableRow key={s.id}>
                  <TableCell>
                    <p>{s.email}</p>
                    <p className="font-mono text-[11px] text-muted-foreground">
                      {s.id}
                    </p>
                  </TableCell>
                  <TableCell>
                    {s.status ? <StatusPill status={s.status} /> : "—"}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {s.tier || "—"}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {formatNumber(s.tokens_issued)}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {formatDate(s.subscriber_created_at)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <div className="px-6 py-12 text-center text-sm text-muted-foreground">
            No subscribers found.
          </div>
        )}
      </motion.section>
    </>
  );
}
