"use client";

import { motion } from "framer-motion";
import type { ReactNode } from "react";

import { Marketing } from "@/components/marketing";
import { NetworkMesh } from "@/components/visuals/network-mesh";

export function AuthShell({
  title,
  subtitle,
  children,
  footer,
}: {
  title: string;
  subtitle: string;
  children: ReactNode;
  footer: ReactNode;
}) {
  return (
    <div className="relative isolate grid min-h-screen lg:grid-cols-[1fr_minmax(420px,520px)]">
      {/* Left side — branding */}
      <div className="relative hidden overflow-hidden border-r border-border/60 bg-background lg:block">
        <Marketing.BackgroundGrid />
        <NetworkMesh />
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_30%_40%,rgba(120,140,200,0.10),transparent_60%)]"
        />
        <div className="relative z-10 flex h-full flex-col p-10">
          <Marketing.Logo />
          <div className="mt-auto max-w-md">
            <blockquote className="text-2xl font-medium tracking-tight text-zinc-200">
              &ldquo;Nobody can trace a connection back to you. Not even
              us.&rdquo;
            </blockquote>
          </div>
        </div>
      </div>

      {/* Right side — form */}
      <div className="relative flex items-center justify-center bg-card/40 p-6 sm:p-12">
        <Marketing.BackgroundGrid />
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, ease: "easeOut" }}
          className="relative z-10 w-full max-w-sm"
        >
          <div className="mb-8 lg:hidden">
            <Marketing.Logo />
          </div>
          <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
          <p className="mt-2 text-sm text-muted-foreground">{subtitle}</p>
          <div className="mt-8">{children}</div>
          <div className="mt-6 text-sm text-muted-foreground">{footer}</div>
        </motion.div>
      </div>
    </div>
  );
}
