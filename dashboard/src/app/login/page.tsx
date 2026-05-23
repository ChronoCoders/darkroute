"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import { ArrowRight, Loader2 } from "lucide-react";

import { AuthShell } from "@/components/auth-shell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useLogin } from "@/lib/queries";

export default function LoginPage() {
  const router = useRouter();
  const login = useLogin();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    login.mutate(
      { email: email.trim(), password },
      {
        onSuccess: () => {
          // Cookies are now set by the authority; router.push triggers a
          // navigation that the protected layout will validate via
          // /api/v1/account before rendering.
          router.push("/dashboard");
        },
        onError: () => {
          toast.error("Invalid email or password.");
        },
      },
    );
  }

  return (
    <AuthShell
      title="Welcome back"
      subtitle="Log in to manage your connections, access keys, and account."
      footer={
        <>
          Don&apos;t have an account?{" "}
          <Link
            href="/signup"
            className="font-medium text-foreground underline-offset-4 hover:underline"
          >
            Sign up
          </Link>
        </>
      }
    >
      <form onSubmit={onSubmit} className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="email">Email</Label>
          <Input
            id="email"
            name="email"
            type="email"
            autoComplete="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            disabled={login.isPending}
            placeholder="operator@company.com"
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="password">Password</Label>
          <Input
            id="password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
            minLength={16}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={login.isPending}
            placeholder="At least 16 characters"
          />
        </div>
        <Button type="submit" className="w-full gap-2" disabled={login.isPending}>
          {login.isPending ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <>
              Log in <ArrowRight className="h-4 w-4" />
            </>
          )}
        </Button>
      </form>
    </AuthShell>
  );
}
