"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import { toParams, type Filters } from "@/lib/filters";
import type {
  DashboardSummary,
  DistributionItem,
  EventLocationList,
  EventPage,
  RegionItem,
  SecurityEvent,
  TimelinePoint,
} from "@/types/api";

export const PAGE_SIZE = 25;
// Everything shares the ["security"] prefix so a live event can invalidate it in one call.

export function useSummary(f: Filters, enabled: boolean) {
  return useQuery({
    queryKey: ["security", "summary", f],
    queryFn: () => api<DashboardSummary>(`/api/dashboard/summary?${toParams(f)}`),
    enabled,
  });
}

export function useLocations(f: Filters, enabled: boolean) {
  return useQuery({
    queryKey: ["security", "locations", f],
    queryFn: () => api<EventLocationList>(`/api/security-events/locations?${toParams(f)}`),
    enabled,
  });
}

export function useEvents(f: Filters, page: number, enabled: boolean) {
  return useQuery({
    queryKey: ["security", "events", f, page],
    queryFn: () => {
      const p = toParams(f);
      p.set("limit", String(PAGE_SIZE));
      p.set("offset", String(page * PAGE_SIZE));
      return api<EventPage>(`/api/security-events?${p}`);
    },
    placeholderData: keepPreviousData,
    enabled,
  });
}

export function useEvent(id: string | null) {
  return useQuery({
    queryKey: ["security", "event", id],
    queryFn: () => api<SecurityEvent>(`/api/security-events/${id}`),
    enabled: !!id,
  });
}

export function useRegions(enabled: boolean, f?: Filters) {
  return useQuery({
    queryKey: ["security", "regions", f],
    queryFn: () => api<RegionItem[]>(`/api/dashboard/regions${f ? `?${toParams(f)}` : ""}`),
    enabled,
  });
}

export function useSeverity(f: Filters, enabled: boolean) {
  return useQuery({
    queryKey: ["security", "severity", f],
    queryFn: () => api<DistributionItem[]>(`/api/dashboard/severity?${toParams(f)}`),
    enabled,
  });
}

export function useThreatTypes(f: Filters, enabled: boolean) {
  return useQuery({
    queryKey: ["security", "threat-types", f],
    queryFn: () => api<DistributionItem[]>(`/api/dashboard/threat-types?${toParams(f)}`),
    enabled,
  });
}

export function useTimeline(f: Filters, bucket: "hour" | "day", enabled: boolean) {
  return useQuery({
    queryKey: ["security", "timeline", bucket, f],
    queryFn: () => {
      const params = toParams(f);
      params.set("bucket", bucket);
      return api<TimelinePoint[]>(`/api/dashboard/timeline?${params}`);
    },
    enabled,
  });
}
