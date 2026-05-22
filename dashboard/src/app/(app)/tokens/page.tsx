"use client";

import { motion } from "framer-motion";
import { KeyRound, Sparkles } from "lucide-react";

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
import { useAccount, useTokens } from "@/lib/queries";
import {
  formatDateTime,
  formatNumber,
  shortId,
  timeSince,
} from "@/lib/format";

export default function TokensPage() {
  const tokens = useTokens();
  const account = useAccount();
  const status = account.data?.subscription.status;
  const canIssue = status === "active";

  return (
    <>
      <PageHeader
        title="Tokens"
        description="Blind-signed circuit credentials. The authority counts them; relays verify them; nobody links them to you."
      />

      <section className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {tokens.isLoading ? (
          <>
            <Skeleton className="h-28" />
            <Skeleton className="h-28" />
            <Skeleton className="h-28" />
          </>
        ) : tokens.data ? (
          <>
            <StatCard
              label="Lifetime tokens"
              value={formatNumber(tokens.data.tokens_issued)}
              icon={KeyRound}
            />
            <StatCard
              label="Recent issuances"
              value={formatNumber(tokens.data.recent.length)}
              hint="Last 50 events shown"
            />
            <StatCard
              label="Status"
              value={canIssue ? "Active" : "Pending approval"}
              hint={canIssue ? "Issue at will" : "Issuance is gated"}
              icon={Sparkles}
            />
          </>
        ) : null}
      </section>

      <motion.section
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="rounded-2xl border border-border/60 bg-card/40 p-6"
      >
        <h2 className="text-sm font-medium">Request a token</h2>
        <p className="mt-1 text-xs text-muted-foreground">
          Tokens use Chaum blind signatures, so the client builds the blinded
          message locally and only the result is sent to the authority. Run
          this from your application:
        </p>
        <pre className="mt-4 overflow-x-auto rounded-lg border border-border/60 bg-background/60 p-4 font-mono text-xs leading-relaxed">
{`curl -X POST https://api.darkroute.example/api/v1/tokens/issue \\
  -H "Authorization: Bearer $JWT" \\
  -H "Content-Type: application/json" \\
  -d '{"blinded": "<hex>"}'`}
        </pre>
        {!canIssue && (
          <p className="mt-3 text-xs text-amber-200">
            Your subscription is {status?.replace("_", " ") ?? "unknown"}.
            Token issuance returns 403 until an operator approves you.
          </p>
        )}
      </motion.section>

      <motion.section
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.05 }}
        className="mt-8 rounded-2xl border border-border/60 bg-card/40"
      >
        <div className="border-b border-border/60 px-6 py-4">
          <h2 className="text-sm font-medium">Recent issuances</h2>
          <p className="text-xs text-muted-foreground">
            Timestamps only — token bytes are never persisted
            (SECURITY_MODEL §5.2 step 8).
          </p>
        </div>
        {tokens.isLoading ? (
          <div className="space-y-3 p-6">
            <Skeleton className="h-6" />
            <Skeleton className="h-6" />
            <Skeleton className="h-6" />
          </div>
        ) : tokens.data && tokens.data.recent.length > 0 ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Event</TableHead>
                <TableHead>Issued</TableHead>
                <TableHead className="text-right">Age</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {tokens.data.recent.map((t) => (
                <TableRow key={t.id}>
                  <TableCell>
                    <Badge variant="outline" className="font-mono text-xs">
                      {shortId(t.id)}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {formatDateTime(t.issued_at)}
                  </TableCell>
                  <TableCell className="text-right text-xs text-muted-foreground">
                    {timeSince(t.issued_at)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <div className="px-6 py-14 text-center">
            <KeyRound className="mx-auto h-6 w-6 text-muted-foreground" />
            <p className="mt-3 text-sm font-medium">No tokens issued yet</p>
            <p className="mt-1 text-xs text-muted-foreground">
              {canIssue
                ? "Once you call /api/v1/tokens/issue, events show up here."
                : "Awaiting subscription approval."}
            </p>
          </div>
        )}
      </motion.section>
    </>
  );
}
