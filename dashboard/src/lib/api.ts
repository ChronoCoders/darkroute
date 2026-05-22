// Single fetch wrapper for every dashboard request to the authority.
// Always sends `credentials: "include"` so the HttpOnly session_id and
// jwt cookies set by the authority flow back with each call. The
// dashboard never reads or stores the token value itself — that
// remains in the cookie jar, inaccessible to JavaScript.

import type { ApiError } from "./types";

const JSON_HEADERS: HeadersInit = {
  "Content-Type": "application/json",
};

export class HttpError extends Error {
  readonly status: number;
  readonly body: ApiError | null;
  constructor(status: number, body: ApiError | null, message: string) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

export async function apiGet<T>(path: string, init?: RequestInit): Promise<T> {
  return apiRequest<T>("GET", path, undefined, init);
}

export async function apiPost<T>(
  path: string,
  body: unknown,
  init?: RequestInit,
): Promise<T> {
  return apiRequest<T>("POST", path, body, init);
}

async function apiRequest<T>(
  method: "GET" | "POST" | "PATCH" | "DELETE",
  path: string,
  body: unknown,
  init?: RequestInit,
): Promise<T> {
  const res = await fetch(path, {
    ...init,
    method,
    credentials: "include",
    headers: {
      ...JSON_HEADERS,
      ...(init?.headers ?? {}),
    },
    body: body === undefined ? null : JSON.stringify(body),
  });

  if (res.status === 204) {
    return undefined as T;
  }

  const text = await res.text();
  let parsed: unknown = null;
  if (text.length > 0) {
    try {
      parsed = JSON.parse(text);
    } catch {
      // Authority always returns JSON; a non-JSON response is itself
      // an error condition we surface to the caller.
      parsed = null;
    }
  }

  if (!res.ok) {
    const errBody =
      parsed !== null && typeof parsed === "object" && "error" in parsed
        ? (parsed as ApiError)
        : null;
    throw new HttpError(
      res.status,
      errBody,
      `${method} ${path} failed: ${res.status}${
        errBody ? ` ${errBody.error}` : ""
      }`,
    );
  }

  return parsed as T;
}

export function isUnauthorized(err: unknown): boolean {
  return err instanceof HttpError && err.status === 401;
}

export function isForbidden(err: unknown): boolean {
  return err instanceof HttpError && err.status === 403;
}
