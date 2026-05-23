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
          Operator-grade secure connectivity
        </div>
        <h1 className="text-balance text-4xl font-semibold tracking-tight sm:text-6xl">
          A managed network for{" "}
          <span className="bg-gradient-to-r from-zinc-100 via-zinc-400 to-zinc-100 bg-clip-text text-transparent">
            unlinkable
          </span>{" "}
          connections.
        </h1>
        <p className="mt-6 max-w-2xl text-lg text-muted-foreground">
          Access keys are issued anonymously and verified without exposing the
          account behind them. Each connection routes through multiple
          distinct network points so no single point sees both your account
          and your destination.
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
    title: "Anonymous access keys",
    body: "Keys are generated using a cryptographic blind signature scheme. We count generations but never see the key itself, so your traffic stays unlinkable.",
  },
  {
    icon: Network,
    title: "Multi-layer connections",
    body: "Every connection routes through multiple distinct network points. The same point never serves two layers in one connection.",
  },
  {
    icon: Lock,
    title: "End-to-end encryption",
    body: "Ephemeral keys at every layer with fresh randomness per message. Session keys are wiped the moment a connection closes.",
  },
  {
    icon: ShieldCheck,
    title: "Residential outbound",
    body: "Outbound traffic flows through dedicated residential IPs. Destination ports are checked before any connection is opened.",
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
    body: "Create an account. We review every new account before connections are enabled.",
  },
  {
    k: "02",
    title: "Get activated",
    body: "Human review for fraud screening. Once activated, your account unlocks connection requests and key generation.",
  },
  {
    k: "03",
    title: "Generate access keys",
    body: "Generate anonymous access keys via the API. Use them to open connections without revealing your identity.",
  },
  {
    k: "04",
    title: "Connect",
    body: "Open a multi-layer connection, encrypt your payload, send it. We route the traffic and an outbound network point opens the destination.",
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
          Ready to connect?
        </h2>
        <p className="mx-auto mt-3 max-w-xl text-muted-foreground">
          Self-serve signup. Manual review. Operator-tier limits. Built for
          teams that need to move data without leaving a trail.
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
