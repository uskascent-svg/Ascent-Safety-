import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SENSORS_CONFIG } from "@/components/SensorsAdmin";
import SourcesAdmin from "@/components/SourcesAdmin";
import * as auth from "@/lib/auth";

function renderAdmin(isAdmin = true) {
  vi.spyOn(auth, "useAuth").mockReturnValue({
    status: "authed",
    user: null,
    canViewPanel: true,
    isAdmin,
    isAnalyst: !isAdmin,
    isAuthenticated: true,
    login: vi.fn(),
    register: vi.fn(),
    logout: vi.fn(),
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <SourcesAdmin cfg={SENSORS_CONFIG} />
    </QueryClientProvider>,
  );
}

afterEach(() => vi.restoreAllMocks());

describe("SourcesAdmin (network sensors)", () => {
  it("states plainly that no sensor is included when none are registered", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("[]", { status: 200 }));
    renderAdmin();
    expect(await screen.findByText("No sensors registered")).toBeInTheDocument();
    expect(screen.getByText(/does not include a network sensor/)).toBeInTheDocument();
  });

  it("lists registered sensors without any key material beyond the prefix", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify([
          {
            id: "1",
            name: "hq-sensor",
            kind: "zeek",
            region: "EMEA",
            country: "Germany",
            key_prefix: "ascent_sn_2ZyF",
            is_active: true,
            last_seen_at: null,
          },
        ]),
        { status: 200 },
      ),
    );
    renderAdmin();
    expect(await screen.findByText("hq-sensor")).toBeInTheDocument();
    expect(screen.getByText(/key ascent_sn_2ZyF…/)).toBeInTheDocument();
    expect(screen.getByText(/no telemetry received yet/)).toBeInTheDocument();
  });

  it("blocks non-administrators", () => {
    renderAdmin(false);
    expect(screen.getByText("Only administrators can manage sensors.")).toBeInTheDocument();
  });
});
