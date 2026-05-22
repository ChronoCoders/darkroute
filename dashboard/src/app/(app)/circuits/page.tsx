"use client";

import { motion } from "framer-motion";
import { Network } from "lucide-react";

import { PageHeader, StatCard } from "@/components/app-shell";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAccount, useCircuits, useUsage } from "@/lib/queries";
import {
  formatDateTime,
  formatNumber,
  shortId,
  timeSince,
} from "@/lib/format";

export default function CircuitsPage() {
  const circuits = useCircuits();
  const usage = useUsage();
  const account = useAccount();
  const status = account.data?.subscription.status;
  const canRoute = status === "active";

  return (
    <>
      <PageHeader
        title="Circuits"
        description="Recent route assignments and active relay capacity. Each circuit is three distinct nodes per SECURITY_MODEL §9."
      />

      <section className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-3">
        {usage.isLoading ? (
          <>
            <Skeleton className="h-28" />
            <Skeleton className="h-28" />
            <Skeleton className="h-28" />
          </>
        ) : usage.data ? (
          <>
            <StatCard
              label="Assignments this period"
              value={formatNumber(usage.data.circuits_assigned)}
              hint="Counted at route request"
              icon={Network}
            />
            <StatCard
              label="Available guards / middles"
              value={`${usage.data.active_relays.guard} / ${usage.data.active_relays.middle}`}
              hint="Active in the mesh"
            />
            <StatCard
              label="Available exits"
              value={formatNumber(usage.data.active_relays.exit)}
              hint="Decodo-fronted egress"
            />
          </>
        ) : null}
      </section>

      <motion.section
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="rounded-2xl border border-border/60 bg-card/40"
      >
        <div className="border-b border-border/60 px-6 py-4">
          <h2 className="text-sm font-medium">Recent circuit assignments</h2>
          <p className="text-xs text-muted-foreground">
            Last 50 routes returned to your subscriber. Relay IDs only —
            endpoints are not stored client-side.
          </p>
        </div>
        {circuits.isLoading ? (
          <div className="space-y-3 p-6">
            <Skeleton className="h-6" />
            <Skeleton className="h-6" />
            <Skeleton className="h-6" />
          </div>
        ) : circuits.data && circuits.data.recent.length > 0 ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Circuit</TableHead>
                <TableHead>Guard</TableHead>
                <TableHead>Middle</TableHead>
                <TableHead>Exit</TableHead>
                <TableHead>Assigned</TableHead>
                <TableHead className="text-right">Age</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {circuits.data.recent.map((c) => (
                <TableRow key={c.id}>
                  <TableCell>
                    <Badge variant="outline" className="font-mono text-xs">
                      {shortId(c.id)}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {shortId(c.guard_id)}
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {shortId(c.middle_id)}
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {shortId(c.exit_id)}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {formatDateTime(c.created_at)}
                  </TableCell>
                  <TableCell className="text-right text-xs text-muted-foreground">
                    {timeSince(c.created_at)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <div className="px-6 py-14 text-center">
            <Network className="mx-auto h-6 w-6 text-muted-foreground" />
            <p className="mt-3 text-sm font-medium">No circuits yet</p>
            <p className="mt-1 text-xs text-muted-foreground">
              {canRoute
                ? "Call GET /api/v1/circuits/route to request your first assignment."
                : "Circuit assignment is gated on subscription approval."}
            </p>
          </div>
        )}
      </motion.section>
    </>
  );
}
