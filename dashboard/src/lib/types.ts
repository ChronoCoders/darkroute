// Shared TypeScript types mirroring the authority's JSON response
// shapes. Any change to a handler's response struct in
// authority/internal/handlers/*.go must be reflected here.
//
// We deliberately use plain `interface` declarations rather than zod
// schemas: the dashboard treats the authority as the source of truth
// for every value it displays, so runtime validation of well-known
// shapes adds noise without adding safety. Form input (login, signup)
// is still validated with zod inside the page that owns the form.

export type SubscriptionStatus =
  | "pending_review"
  | "active"
  | "lapsed"
  | "cancelled";

export interface SubscriptionInfo {
  tier: string;
  status: SubscriptionStatus;
  tokens_issued: number;
  bandwidth_used: number;
  current_period_start: string;
  current_period_end: string;
}

export interface AccountResponse {
  id: string;
  email: string;
  role: "operator" | "admin" | string;
  created_at: string;
  subscription: SubscriptionInfo;
}

export interface RelayRoleCounts {
  guard: number;
  middle: number;
  exit: number;
}

export interface UsageResponse {
  tokens_issued: number;
  bandwidth_used: number;
  circuits_assigned: number;
  active_relays: RelayRoleCounts;
  current_period_start: string;
  current_period_end: string;
}

export interface TokenIssuance {
  id: string;
  issued_at: string;
}

export interface TokenListResponse {
  tokens_issued: number;
  recent: TokenIssuance[];
}

export interface CircuitListItem {
  id: string;
  guard_id: string;
  middle_id: string;
  exit_id: string;
  created_at: string;
}

export interface CircuitListResponse {
  recent: CircuitListItem[];
}

export interface AdminSubscriber {
  id: string;
  email: string;
  role: string;
  subscriber_created_at: string;
  tier: string;
  status: SubscriptionStatus;
  tokens_issued: number;
  bandwidth_used: number;
  current_period_start: string;
  current_period_end: string;
}

export interface AdminSubscribersResponse {
  subscribers: AdminSubscriber[];
}

export interface LoginResponse {
  // The dashboard does not read this value — auth flows through the
  // HttpOnly session_id and jwt cookies set by the authority. The
  // field is present in the response body for API clients that need
  // to attach the JWT as an Authorization header.
  token: string;
}

export interface ApiError {
  error: string;
}
