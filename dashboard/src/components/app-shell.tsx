"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, type ReactNode } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  KeyRound,
  LayoutDashboard,
  LogOut,
  Network,
  Shield,
  UserRound,
} from "lucide-react";

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Marketing } from "@/components/marketing";
import { LivePulse } from "@/components/visuals/live-pulse";
import { isUnauthorized } from "@/lib/api";
import { useAccount, useLogout } from "@/lib/queries";
import type { SubscriptionStatus } from "@/lib/types";

type NavItem = {
  href: string;
  label: string;
  icon: typeof LayoutDashboard;
  adminOnly?: boolean;
};

const NAV: NavItem[] = [
  { href: "/dashboard", label: "Overview", icon: LayoutDashboard },
  { href: "/keys", label: "Access keys", icon: KeyRound },
  { href: "/connections", label: "Connections", icon: Network },
  { href: "/account", label: "Account", icon: UserRound },
  { href: "/admin", label: "Admin", icon: Shield, adminOnly: true },
];

function statusLabel(status: SubscriptionStatus): string {
  switch (status) {
    case "pending_review":
      return "Under review";
    case "active":
      return "Active";
    case "lapsed":
      return "Lapsed";
    case "cancelled":
      return "Cancelled";
    default:
      return status;
  }
}

export function AppShell({ children }: { children: ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const { data: account, isLoading, error } = useAccount();
  const logout = useLogout();

  useEffect(() => {
    if (error && isUnauthorized(error)) {
      router.replace("/login");
    }
  }, [error, router]);

  useEffect(() => {
    if (account && account.role !== "admin" && pathname.startsWith("/admin")) {
      router.replace("/dashboard");
    }
  }, [account, pathname, router]);

  if (isLoading || !account) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.4 }}
          className="flex items-center gap-3 text-sm text-zinc-500"
        >
          <LivePulse tone="zinc" />
          Loading…
        </motion.div>
      </div>
    );
  }

  const isAdmin = account.role === "admin";
  const items = NAV.filter((n) => !n.adminOnly || isAdmin);
  const status = account.subscription.status;
  const initials = account.email.slice(0, 2).toUpperCase();

  return (
    <div className="relative min-h-screen bg-background text-foreground">
      <div aria-hidden className="pointer-events-none absolute inset-0 -z-10 bg-grid" />
      <div className="relative z-10 mx-auto grid min-h-screen max-w-7xl grid-cols-[240px_1fr] gap-0">
        <aside className="sticky top-0 flex h-screen flex-col border-r border-white/[0.04] bg-zinc-950/40 px-4 py-6 backdrop-blur-xl">
          <div className="px-2">
            <Marketing.Logo />
          </div>
          <div className="mx-2 mt-3 flex items-center gap-2 text-[10px] uppercase tracking-[0.18em] text-zinc-600">
            <LivePulse tone="emerald" size={6} />
            <span>Service connected</span>
          </div>
          <nav className="mt-8 flex flex-1 flex-col gap-0.5">
            <p className="px-3 pb-2 text-[10px] font-medium uppercase tracking-[0.18em] text-zinc-600">
              Workspace
            </p>
            {items.map((item) => {
              const active =
                pathname === item.href || pathname.startsWith(`${item.href}/`);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`group relative flex items-center gap-3 rounded-md px-3 py-2 text-sm transition ${
                    active
                      ? "bg-white/[0.05] text-zinc-100"
                      : "text-zinc-500 hover:bg-white/[0.03] hover:text-zinc-200"
                  }`}
                >
                  {active && (
                    <motion.span
                      layoutId="nav-active"
                      className="absolute inset-y-1 left-0 w-0.5 rounded-r bg-zinc-200"
                      transition={{ type: "spring", stiffness: 400, damping: 30 }}
                    />
                  )}
                  <item.icon className="h-4 w-4" />
                  <span className="flex-1">{item.label}</span>
                  {item.adminOnly && (
                    <Badge
                      variant="outline"
                      className="border-white/10 px-1.5 py-0 text-[9px] uppercase tracking-[0.14em] text-zinc-500"
                    >
                      Admin
                    </Badge>
                  )}
                </Link>
              );
            })}
          </nav>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button className="flex items-center gap-3 rounded-lg border border-white/[0.04] bg-zinc-900/40 p-2.5 text-left transition hover:bg-zinc-900/70">
                <Avatar className="h-8 w-8">
                  <AvatarFallback className="bg-gradient-to-br from-zinc-700 to-zinc-900 text-xs text-zinc-100">
                    {initials}
                  </AvatarFallback>
                </Avatar>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-xs font-medium text-zinc-200">
                    {account.email}
                  </p>
                  <p className="text-[10px] uppercase tracking-[0.14em] text-zinc-500">
                    {account.role === "admin" ? "Admin" : "Operator"}
                  </p>
                </div>
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start" className="w-56">
              <DropdownMenuLabel className="truncate">
                {account.email}
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem asChild>
                <Link href="/account" className="cursor-pointer">
                  <UserRound className="mr-2 h-4 w-4" />
                  Account
                </Link>
              </DropdownMenuItem>
              <DropdownMenuItem
                className="cursor-pointer"
                onClick={() => {
                  logout.mutate(undefined, {
                    onSettled: () => router.replace("/login"),
                  });
                }}
              >
                <LogOut className="mr-2 h-4 w-4" />
                Log out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </aside>

        <main className="min-w-0 px-10 py-10">
          <AnimatePresence mode="popLayout">
            {status !== "active" && (
              <motion.div
                key="pending-banner"
                initial={{ opacity: 0, y: -8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -8 }}
                transition={{ duration: 0.3 }}
                className="mb-8 flex items-center gap-3 rounded-xl border border-amber-500/20 bg-amber-500/[0.06] px-5 py-4 text-sm"
              >
                <LivePulse tone="amber" />
                <div className="flex-1">
                  <p className="font-medium text-amber-100">
                    Your account is {statusLabel(status).toLowerCase()}
                  </p>
                  <p className="mt-0.5 text-xs text-amber-200/70">
                    Connections and access keys unlock once your account is
                    activated.
                  </p>
                </div>
                <Badge
                  variant="outline"
                  className="border-amber-500/30 text-amber-200"
                >
                  {statusLabel(status)}
                </Badge>
              </motion.div>
            )}
          </AnimatePresence>
          {children}
        </main>
      </div>
    </div>
  );
}

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="mb-10 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight text-zinc-100">
          {title}
        </h1>
        {description && (
          <p className="mt-2 max-w-xl text-sm text-zinc-500">{description}</p>
        )}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </header>
  );
}

export function StatusPill({ status }: { status: SubscriptionStatus }) {
  const colors = {
    active: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
    pending_review: "border-amber-500/30 bg-amber-500/10 text-amber-300",
    lapsed: "border-zinc-500/30 bg-zinc-500/10 text-zinc-400",
    cancelled: "border-zinc-500/30 bg-zinc-500/10 text-zinc-400",
  } as const;
  const cls = colors[status] ?? colors.lapsed;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium uppercase tracking-[0.14em] ${cls}`}
    >
      <span className={`h-1 w-1 rounded-full ${
        status === "active"
          ? "bg-emerald-400"
          : status === "pending_review"
            ? "bg-amber-400"
            : "bg-zinc-400"
      }`} />
      {statusLabel(status)}
    </span>
  );
}
