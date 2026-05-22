"use client";

import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseQueryOptions,
} from "@tanstack/react-query";

import { apiGet, apiPost } from "./api";
import type {
  AccountResponse,
  AdminSubscribersResponse,
  CircuitListResponse,
  LoginResponse,
  TokenListResponse,
  UsageResponse,
} from "./types";

export const queryKeys = {
  account: ["account"] as const,
  usage: ["usage"] as const,
  tokens: ["tokens"] as const,
  circuits: ["circuits"] as const,
  adminSubscribers: ["admin", "subscribers"] as const,
} as const;

export function useAccount(
  options?: Omit<UseQueryOptions<AccountResponse>, "queryKey" | "queryFn">,
) {
  return useQuery<AccountResponse>({
    queryKey: queryKeys.account,
    queryFn: () => apiGet<AccountResponse>("/api/v1/account"),
    staleTime: 30_000,
    ...options,
  });
}

export function useUsage() {
  return useQuery<UsageResponse>({
    queryKey: queryKeys.usage,
    queryFn: () => apiGet<UsageResponse>("/api/v1/usage"),
    staleTime: 30_000,
  });
}

export function useTokens() {
  return useQuery<TokenListResponse>({
    queryKey: queryKeys.tokens,
    queryFn: () => apiGet<TokenListResponse>("/api/v1/tokens"),
    staleTime: 30_000,
  });
}

export function useCircuits() {
  return useQuery<CircuitListResponse>({
    queryKey: queryKeys.circuits,
    queryFn: () => apiGet<CircuitListResponse>("/api/v1/circuits"),
    staleTime: 30_000,
  });
}

export function useAdminSubscribers() {
  return useQuery<AdminSubscribersResponse>({
    queryKey: queryKeys.adminSubscribers,
    queryFn: () => apiGet<AdminSubscribersResponse>("/api/v1/admin/subscribers"),
    staleTime: 15_000,
  });
}

export interface LoginInput {
  email: string;
  password: string;
}

export interface SignupInput {
  email: string;
  password: string;
}

export function useLogin() {
  return useMutation<LoginResponse, Error, LoginInput>({
    mutationFn: (input) => apiPost<LoginResponse>("/api/v1/auth/login", input),
  });
}

export function useSignup() {
  return useMutation<{ id: string }, Error, SignupInput>({
    mutationFn: (input) => apiPost<{ id: string }>("/api/v1/auth/register", input),
  });
}

export function useLogout() {
  const qc = useQueryClient();
  return useMutation<void, Error, void>({
    mutationFn: () => apiPost<void>("/api/v1/auth/logout", {}),
    onSuccess: () => {
      qc.clear();
    },
  });
}

export interface ApproveInput {
  subscriberId: string;
}

export function useApproveSubscriber() {
  const qc = useQueryClient();
  return useMutation<{ id: string; status: string }, Error, ApproveInput>({
    mutationFn: ({ subscriberId }) =>
      apiPost<{ id: string; status: string }>(
        `/api/v1/admin/subscribers/${encodeURIComponent(subscriberId)}/approve`,
        {},
      ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.adminSubscribers });
    },
  });
}
