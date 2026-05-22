"use client";

import Link from "next/link";
import { motion } from "framer-motion";
import {
  ArrowRight,
  KeyRound,
  Lock,
  Network,
  ShieldCheck,
  Workflow,
} from "lucide-react";

import { Button } from "@/components/ui/button";

function Logo({ className }: { className?: string }) {
  return (
    <Link
      href="/"
      className={`flex items-center gap-2 font-semibold tracking-tight ${className ?? ""}`}
    >
      <span
        aria-hidden
        className="grid h-8 w-8 place-items-center rounded-md border border-border/80 bg-gradient-to-br from-zinc-900 to-zinc-700 text-zinc-50 shadow-inner"
      >
        <span className="block h-3 w-3 rounded-sm bg-zinc-50/90" />
      </span>
      <span className="text-lg">darkroute</span>
    </Link>
  );
}

function BackgroundGrid() {
  return (
    <>
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 -z-10 bg-[radial-gradient(circle_at_top,theme(colors.zinc.700/.4),transparent_55%)]"
      />
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 -z-10 [background-image:linear-gradient(to_right,theme(colors.zinc.800/.35)_1px,transparent_1px),linear-gradient(to_bottom,theme(colors.zinc.800/.35)_1px,transparent_1px)] [background-size:48px_48px] [mask-image:radial-gradient(ellipse_at_top,black,transparent_70%)]"
      />
    </>
  );
}

function Hero() {
  return (
    <section className="py-20 sm:py-28">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: "easeOut" }}
        className="max-w-3xl"
      >
        <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-border/80 bg-card/60 px-3 py-1 text-xs text-muted-foreground backdrop-blur">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
          Operator-grade onion routing
        </div>
        <h1 className="text-balance text-4xl font-semibold tracking-tight sm:text-6xl">
          A managed mesh for{" "}
          <span className="bg-gradient-to-r from-zinc-100 via-zinc-400 to-zinc-100 bg-clip-text text-transparent">
            unlinkable
          </span>{" "}
          traffic.
        </h1>
        <p className="mt-6 max-w-2xl text-lg text-muted-foreground">
          Blind-token-gated circuits across guard, middle, and exit relays.
          The authority issues tokens it cannot link to traffic; relays
          verify tokens they cannot link to subscribers. End users see only
          the residential exit IP.
        </p>
        <div className="mt-10 flex flex-col gap-3 sm:flex-row">
          <Button asChild size="lg">
            <Link href="/signup" className="gap-2">
              Get access <ArrowRight className="h-4 w-4" />
            </Link>
          </Button>
          <Button asChild size="lg" variant="ghost">
            <Link href="/login">I have an account</Link>
          </Button>
        </div>
      </motion.div>
    </section>
  );
}

const FEATURES: Array<{
  icon: typeof KeyRound;
  title: string;
  body: string;
}> = [
  {
    icon: KeyRound,
    title: "Blind tokens",
    body: "Chaum RSA-2048 blind signatures. The authority counts issuances; it never sees the token value that a relay later verifies.",
  },
  {
    icon: Network,
    title: "Three-hop circuits",
    body: "Guard, middle, exit. Each hop is a distinct physical node — same host cannot serve two roles in one circuit.",
  },
  {
    icon: Lock,
    title: "Layered AES-256-GCM",
    body: "X25519 ECDH per hop, HKDF-SHA256 keys, fresh nonce per frame. Session keys zeroize on circuit teardown.",
  },
  {
    icon: ShieldCheck,
    title: "Residential exit",
    body: "Outbound dialing through Decodo's sticky dedicated IPs. Destination ports are gated by the relay before any SOCKS5 dial.",
  },
];

function Features() {
  return (
    <section className="py-16">
      <div className="grid gap-4 sm:grid-cols-2">
        {FEATURES.map((f, i) => (
          <motion.div
            key={f.title}
            initial={{ opacity: 0, y: 16 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-80px" }}
            transition={{ delay: i * 0.05, duration: 0.45, ease: "easeOut" }}
            className="group relative overflow-hidden rounded-2xl border border-border/80 bg-card/40 p-6 backdrop-blur"
          >
            <div className="absolute inset-x-0 -top-px h-px bg-gradient-to-r from-transparent via-zinc-500/40 to-transparent" />
            <f.icon className="h-6 w-6 text-zinc-300" aria-hidden />
            <h3 className="mt-4 text-lg font-medium">{f.title}</h3>
            <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
              {f.body}
            </p>
          </motion.div>
        ))}
      </div>
    </section>
  );
}

const STEPS: Array<{ k: string; title: string; body: string }> = [
  {
    k: "01",
    title: "Sign up",
    body: "Create an account. Your subscription is pending review until an operator approves it.",
  },
  {
    k: "02",
    title: "Get approved",
    body: "Human review for fraud screening. Once approved, your account unlocks circuit assignment and token issuance.",
  },
  {
    k: "03",
    title: "Issue tokens",
    body: "Blind-sign tokens via the authority API. Use them to open circuits without revealing identity to relays.",
  },
  {
    k: "04",
    title: "Route traffic",
    body: "Build a guard → middle → exit circuit, layer-encrypt your payload, send it. The exit dials your destination via Decodo.",
  },
];

function HowItWorks() {
  return (
    <section className="border-t border-border/60 py-20">
      <div className="mb-10">
        <h2 className="text-3xl font-semibold tracking-tight">How it works</h2>
        <p className="mt-2 text-muted-foreground">
          Four steps, plain protocols, no magic.
        </p>
      </div>
      <ol className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {STEPS.map((s, i) => (
          <motion.li
            key={s.k}
            initial={{ opacity: 0, y: 16 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-60px" }}
            transition={{ delay: i * 0.06, duration: 0.45, ease: "easeOut" }}
            className="relative rounded-2xl border border-border/80 bg-card/40 p-6 backdrop-blur"
          >
            <span className="font-mono text-xs text-muted-foreground">
              {s.k}
            </span>
            <h3 className="mt-3 text-base font-medium">{s.title}</h3>
            <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
              {s.body}
            </p>
          </motion.li>
        ))}
      </ol>
    </section>
  );
}

function CTA() {
  return (
    <section className="border-t border-border/60 py-20">
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: "-80px" }}
        transition={{ duration: 0.5, ease: "easeOut" }}
        className="rounded-3xl border border-border/80 bg-gradient-to-br from-zinc-900 via-zinc-900/90 to-zinc-800 p-10 text-center"
      >
        <Workflow className="mx-auto h-8 w-8 text-zinc-300" aria-hidden />
        <h2 className="mt-4 text-2xl font-semibold tracking-tight sm:text-3xl">
          Ready to route?
        </h2>
        <p className="mx-auto mt-3 max-w-xl text-muted-foreground">
          Self-serve signup. Manual approval. Operator-tier rate limits.
          Built for teams that need to move bytes without leaving a trail.
        </p>
        <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
          <Button asChild size="lg">
            <Link href="/signup" className="gap-2">
              Get access <ArrowRight className="h-4 w-4" />
            </Link>
          </Button>
          <Button asChild size="lg" variant="ghost">
            <Link href="/login">Existing operator</Link>
          </Button>
        </div>
      </motion.div>
    </section>
  );
}

export const Marketing = {
  Logo,
  BackgroundGrid,
  Hero,
  Features,
  HowItWorks,
  CTA,
};
