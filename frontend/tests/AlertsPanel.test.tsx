import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import AlertsPanel from "@/components/AlertsPanel";

function renderPanel() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <AlertsPanel onSelect={() => {}} />
    </QueryClientProvider>,
  );
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
afterEach(() => vi.restoreAllMocks());

describe("AlertsPanel", () => {
  it("shows an honest empty state when there are no alerts", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      json({ items: [], total: 0, limit: 10, offset: 0 }),
    );
    renderPanel();
    expect(await screen.findByText("No open alerts")).toBeInTheDocument();
  });

  it("lists alerts from the API with text severity and actions", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      json({
        items: [
          {
            id: "a1",
            event_id: "e1",
            severity: "critical",
            title: "Backup deletion command executed",
            status: "open",
            created_at: new Date().toISOString(),
            acknowledged_at: null,
            resolved_at: null,
            resolution_note: null,
            threat_type: "malware_ransomware",
            source: "endpoint:branch-berlin-01",
            region: "EMEA",
            occurred_at: new Date().toISOString(),
          },
        ],
        total: 1,
        limit: 10,
        offset: 0,
      }),
    );
    renderPanel();
    expect(await screen.findByText("Backup deletion command executed")).toBeInTheDocument();
    expect(screen.getByText("Critical")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Acknowledge" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Resolve" })).toBeInTheDocument();
    expect(screen.getByText(/Open Alerts \(1\)/)).toBeInTheDocument();
  });

  it("shows an error state when the API fails", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(json({}, 500));
    renderPanel();
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not load alerts.");
  });
});
