"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, type ReactNode } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  Activity,
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
  { href: "/tokens", label: "Tokens", icon: KeyRound },
  { href: "/circuits", label: "Circuits", icon: Network },
  { href: "/account", label: "Account", icon: UserRound },
  { href: "/admin", label: "Admin", icon: Shield, adminOnly: true },
];

function statusBadgeVariant(status: SubscriptionStatus) {
  switch (status) {
    case "active":
      return "default" as const;
    case "pending_review":
      return "secondary" as const;
    default:
      return "outline" as const;
  }
}

function statusLabel(status: SubscriptionStatus): string {
  switch (status) {
    case "pending_review":
      return "Pending review";
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

  // Redirect to /login on auth failure. Done in an effect so we don't
  // call router.push during render.
  useEffect(() => {
    if (error && isUnauthorized(error)) {
      router.replace("/login");
    }
  }, [error, router]);

  // If we're admin-paging without admin role, bounce to the overview.
  useEffect(() => {
    if (
      account &&
      account.role !== "admin" &&
      pathname.startsWith("/admin")
    ) {
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
          className="flex items-center gap-3 text-sm text-muted-foreground"
        >
          <span className="h-2 w-2 animate-pulse rounded-full bg-zinc-400" />
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
      <Marketing.BackgroundGrid />
      <div className="relative z-10 mx-auto grid min-h-screen max-w-7xl grid-cols-[240px_1fr] gap-0">
        <aside className="sticky top-0 flex h-screen flex-col border-r border-border/60 bg-background/60 px-4 py-6 backdrop-blur">
          <Marketing.Logo />
          <nav className="mt-10 flex flex-1 flex-col gap-1">
            {items.map((item) => {
              const active =
                pathname === item.href || pathname.startsWith(`${item.href}/`);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`group flex items-center gap-3 rounded-md px-3 py-2 text-sm transition ${
                    active
                      ? "bg-card text-foreground"
                      : "text-muted-foreground hover:bg-card/60 hover:text-foreground"
                  }`}
                >
                  <item.icon className="h-4 w-4" />
                  {item.label}
                  {item.label === "Admin" && (
                    <Badge variant="outline" className="ml-auto text-[10px]">
                      Admin
                    </Badge>
                  )}
                </Link>
              );
            })}
          </nav>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button className="flex items-center gap-3 rounded-md border border-border/60 bg-card/40 p-2 text-left transition hover:bg-card/70">
                <Avatar className="h-8 w-8">
                  <AvatarFallback className="bg-zinc-700 text-xs text-zinc-100">
                    {initials}
                  </AvatarFallback>
                </Avatar>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium">
                    {account.email}
                  </p>
                  <p className="text-[11px] text-muted-foreground">
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

        <main className="min-w-0 px-8 py-8">
          <AnimatePresence mode="popLayout">
            {status !== "active" && (
              <motion.div
                key="pending-banner"
                initial={{ opacity: 0, y: -8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -8 }}
                transition={{ duration: 0.3 }}
                className="mb-6 flex items-center gap-3 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-200"
              >
                <Activity className="h-4 w-4" />
                <div>
                  <p className="font-medium">
                    Your account is {statusLabel(status).toLowerCase()}.
                  </p>
                  <p className="text-amber-200/80">
                    Circuit assignment and token issuance unlock once an
                    operator approves your subscription.
                  </p>
                </div>
                <Badge
                  variant={statusBadgeVariant(status)}
                  className="ml-auto"
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
    <header className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {description && (
          <p className="mt-1 text-sm text-muted-foreground">{description}</p>
        )}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </header>
  );
}

export function StatCard({
  label,
  value,
  hint,
  icon: Icon,
}: {
  label: string;
  value: string | number;
  hint?: string;
  icon?: typeof LayoutDashboard;
}) {
  return (
    <div className="rounded-xl border border-border/60 bg-card/60 p-5">
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>{label}</span>
        {Icon && <Icon className="h-4 w-4" />}
      </div>
      <p className="mt-3 text-2xl font-semibold tracking-tight">{value}</p>
      {hint && <p className="mt-1 text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

export function StatusPill({ status }: { status: SubscriptionStatus }) {
  return (
    <Badge variant={statusBadgeVariant(status)} className="capitalize">
      {statusLabel(status)}
    </Badge>
  );
}
