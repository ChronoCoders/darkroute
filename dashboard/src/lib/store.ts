"use client";

import { create } from "zustand";

// Zustand handles transient UI state only. Auth state lives in HttpOnly
// cookies + React Query's per-key cache; the dashboard never stores a
// session value in any client-side primitive (no localStorage, no
// sessionStorage, no in-memory token).

interface UIState {
  sidebarCollapsed: boolean;
  toggleSidebar: () => void;
  setSidebar: (collapsed: boolean) => void;
}

export const useUIStore = create<UIState>((set) => ({
  sidebarCollapsed: false,
  toggleSidebar: () =>
    set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
  setSidebar: (collapsed) => set({ sidebarCollapsed: collapsed }),
}));
