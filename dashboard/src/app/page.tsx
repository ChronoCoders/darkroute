"use client";

import Link from "next/link";

import { Button } from "@/components/ui/button";
import { Marketing } from "@/components/marketing";

export default function LandingPage() {
  return (
    <div className="relative isolate min-h-screen overflow-hidden bg-background text-foreground">
      <Marketing.BackgroundGrid />
      <header className="relative z-10 mx-auto flex max-w-6xl items-center justify-between px-6 py-6">
        <Marketing.Logo />
        <nav className="flex items-center gap-2">
          <Button asChild variant="ghost" size="sm">
            <Link href="/login">Log in</Link>
          </Button>
          <Button asChild size="sm">
            <Link href="/signup">Get access</Link>
          </Button>
        </nav>
      </header>

      <main className="relative z-10 mx-auto max-w-6xl px-6">
        <Marketing.Hero />
        <Marketing.Features />
        <Marketing.HowItWorks />
        <Marketing.CTA />
      </main>

      <footer className="relative z-10 mx-auto max-w-6xl border-t border-border/60 px-6 py-8 text-sm text-muted-foreground">
        <div className="flex flex-col items-start gap-2 sm:flex-row sm:items-center sm:justify-between">
          <p>© darkroute. B2B onion routing infrastructure.</p>
          <p className="font-mono text-xs">guard · middle · exit</p>
        </div>
      </footer>
    </div>
  );
}
