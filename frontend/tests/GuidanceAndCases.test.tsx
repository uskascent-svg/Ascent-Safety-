import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const { useEvents } = vi.hoisted(() => ({ useEvents: vi.fn() }));

vi.mock("@/components/AccessGate", () => ({ default: ({ children }: { children: React.ReactNode }) => children }));
vi.mock("@/hooks/useSecurityData", () => ({ PAGE_SIZE: 25, useEvents }));

import CaseStudies from "@/components/CaseStudies";
import GuidanceAssistant from "@/components/GuidanceAssistant";
import * as auth from "@/lib/auth";

function renderGuidance() {
  vi.spyOn(auth, "useAuth").mockReturnValue({
    status: "authed", user: { roles: ["SECURITY_ANALYST"] } as never, canViewPanel: true,
    isAdmin: false, isAnalyst: true, isAuthenticated: true, login: vi.fn(), register: vi.fn(), logout: vi.fn(),
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={queryClient}><GuidanceAssistant /></QueryClientProvider>);
}

describe("guidance assistant", () => {
  it("shows role-aware guidance prompts and keeps private-record access out of scope", () => {
    renderGuidance();

    expect(screen.getByText("Personal guidance assistant")).toBeInTheDocument();
    expect(screen.getByText("Guidance for security analysts")).toBeInTheDocument();
    expect(screen.getByText(/does not read private records/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /investigate a suspicious email safely/i })).toBeInTheDocument();
  });
});

describe("case studies", () => {
  beforeEach(() => useEvents.mockReset());

  it("shows an honest empty state when there are no resolved database events", () => {
    useEvents.mockReturnValue({ data: { items: [], total: 0 }, isPending: false, isError: false });
    render(<CaseStudies />);

    expect(screen.getByText("No resolved incidents yet")).toBeInTheDocument();
    expect(screen.getByText(/does not use sample or fictional cases/)).toBeInTheDocument();
  });

  it("renders resolved cases from the event API response", () => {
    useEvents.mockReturnValue({
      data: {
        total: 1,
        items: [{
          id: "case-1",
          source: "sensor-west",
          external_id: null,
          threat_type: "phishing",
          severity: "medium",
          status: "resolved",
          title: "Confirmed credential lure",
          description: "Resolved after the mail gateway removed the message.",
          source_ip: null,
          country: "US",
          region: "AMER",
          latitude: null,
          longitude: null,
          origin_latitude: null,
          origin_longitude: null,
          destination_latitude: null,
          destination_longitude: null,
          occurred_at: "2026-10-07T12:00:00Z",
        }],
      },
      isPending: false,
      isError: false,
    });
    render(<CaseStudies />);

    expect(screen.getByRole("button", { name: /confirmed credential lure/i })).toBeInTheDocument();
    expect(screen.getByText("AMER · US")).toBeInTheDocument();
  });
});
