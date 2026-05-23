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
import { HttpError } from "@/lib/api";
import { useLogin, useSignup } from "@/lib/queries";

export default function SignupPage() {
  const router = useRouter();
  const signup = useSignup();
  const login = useLogin();
  const [email, setEmail] = useState("");
  const [company, setCompany] = useState("");
  const [password, setPassword] = useState("");

  const pending = signup.isPending || login.isPending;

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (password.length < 16) {
      toast.error("Password must be at least 16 characters.");
      return;
    }
    signup.mutate(
      { email: email.trim(), password },
      {
        onSuccess: () => {
          // Sign up flow auto-logs the user in so they land on the
          // dashboard's pending-review surface immediately.
          login.mutate(
            { email: email.trim(), password },
            {
              onSuccess: () => {
                router.push("/dashboard");
              },
              onError: () => {
                router.push("/login");
              },
            },
          );
        },
        onError: (err) => {
          if (err instanceof HttpError && err.body?.error === "email_exists") {
            toast.error("That email is already registered.");
          } else if (
            err instanceof HttpError &&
            err.body?.error === "password_too_short"
          ) {
            toast.error("Password must be at least 16 characters.");
          } else if (
            err instanceof HttpError &&
            err.body?.error === "invalid_email"
          ) {
            toast.error("Please enter a valid email address.");
          } else {
            toast.error("Sign up failed. Please try again.");
          }
        },
      },
    );
  }

  return (
    <AuthShell
      title="Create your account"
      subtitle="Self-serve signup. Review is manual — we'll activate your account, typically within one business day."
      footer={
        <>
          Already have an account?{" "}
          <Link
            href="/login"
            className="font-medium text-foreground underline-offset-4 hover:underline"
          >
            Log in
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
            disabled={pending}
            placeholder="operator@company.com"
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="company">Company</Label>
          <Input
            id="company"
            name="company"
            type="text"
            autoComplete="organization"
            required
            value={company}
            onChange={(e) => setCompany(e.target.value)}
            disabled={pending}
            placeholder="Acme Inc."
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="password">Password</Label>
          <Input
            id="password"
            name="password"
            type="password"
            autoComplete="new-password"
            required
            minLength={16}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={pending}
            placeholder="At least 16 characters"
          />
        </div>
        <Button type="submit" className="w-full gap-2" disabled={pending}>
          {pending ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <>
              Create account <ArrowRight className="h-4 w-4" />
            </>
          )}
        </Button>
        <p className="text-xs text-muted-foreground">
          By signing up you agree that connections are gated on manual
          review. Your account stays{" "}
          <strong>under review</strong> until we activate it.
        </p>
      </form>
    </AuthShell>
  );
}
