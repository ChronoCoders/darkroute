"use client";

import { useState, type ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ThemeProvider } from "next-themes";

import { TooltipProvider } from "@/components/ui/tooltip";
import { Toaster } from "@/components/ui/sonner";

export function Providers({ children }: { children: ReactNode }) {
  // One QueryClient per browser session. useState ensures we don't
  // re-create it on every render and don't accidentally share it across
  // SSR requests (Next.js 15 + React 19 server-component behaviour).
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            // The dashboard is read-mostly; 30 s of staleness is a
            // reasonable default for an authenticated control plane.
            staleTime: 30_000,
            // Auth errors shouldn't be silently retried — they mean the
            // user has to log in again.
            retry: (failureCount, error) => {
              if (
                error instanceof Error &&
                "status" in error &&
                typeof (error as { status: unknown }).status === "number" &&
                ((error as { status: number }).status === 401 ||
                  (error as { status: number }).status === 403)
              ) {
                return false;
              }
              return failureCount < 2;
            },
            refetchOnWindowFocus: false,
          },
          mutations: {
            retry: false,
          },
        },
      }),
  );

  return (
    <ThemeProvider
      attribute="class"
      defaultTheme="dark"
      enableSystem={false}
      disableTransitionOnChange
    >
      <QueryClientProvider client={queryClient}>
        <TooltipProvider delayDuration={200}>{children}</TooltipProvider>
        <Toaster richColors position="top-right" />
      </QueryClientProvider>
    </ThemeProvider>
  );
}
