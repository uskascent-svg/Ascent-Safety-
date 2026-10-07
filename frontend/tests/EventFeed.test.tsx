import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import EventFeed from "@/components/EventFeed";
import { defaultFilters } from "@/lib/filters";

function renderFeed() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <EventFeed
        filters={defaultFilters}
        page={0}
        onPage={() => {}}
        selectedId={null}
        onSelect={() => {}}
      />
    </QueryClientProvider>,
  );
}

afterEach(() => vi.restoreAllMocks());

describe("EventFeed", () => {
  it("shows an empty state (never placeholder events) when the API returns none", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ items: [], total: 0, limit: 25, offset: 0 }), { status: 200 }),
    );
    renderFeed();
    expect(await screen.findByText("No security events available")).toBeInTheDocument();
  });

  it("renders events returned by the API with a text severity label", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          items: [
            {
              id: "1",
              source: "s",
              external_id: null,
              threat_type: "phishing",
              severity: "critical",
              status: "open",
              title: "Credential harvest",
              description: null,
              source_ip: null,
              country: "Germany",
              region: "EMEA",
              latitude: null,
              longitude: null,
              occurred_at: new Date().toISOString(),
            },
          ],
          total: 1,
          limit: 25,
          offset: 0,
        }),
        { status: 200 },
      ),
    );
    renderFeed();
    expect(await screen.findByText("Credential harvest")).toBeInTheDocument();
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("shows an error state when the API fails", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 500 }));
    renderFeed();
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not load events.");
  });
});
