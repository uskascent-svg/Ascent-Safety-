import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import PhishingResult from "@/components/PhishingResult";
import type { PhishingAnalysis } from "@/types/api";

const base: PhishingAnalysis = {
  id: "1",
  created_at: "2026-10-07T00:00:00Z",
  sender: null,
  subject: null,
  risk_score: 72,
  classification: "likely_phishing",
  reasons: ["A link points to a raw IP address instead of a domain name."],
  indicators: [
    {
      code: "URL_IP_HOST",
      category: "url",
      severity: "high",
      description: "x",
      evidence: ["hxxp://203[.]0[.]113[.]9/login"],
    },
  ],
  ml: { available: false, probability: null, model_version: null, top_terms: [] },
  recommended_action: "Do not click links.",
  link_count: 1,
  attachment_count: 0,
};

describe("PhishingResult", () => {
  it("explains the verdict with reasons, indicators and evidence", () => {
    render(<PhishingResult analysis={base} />);
    expect(screen.getByText("72/100")).toBeInTheDocument();
    expect(screen.getByText("Likely phishing")).toBeInTheDocument();
    expect(screen.getByText(/raw IP address/)).toBeInTheDocument();
    expect(screen.getByText("URL_IP_HOST")).toBeInTheDocument();
    expect(screen.getByText("hxxp://203[.]0[.]113[.]9/login")).toBeInTheDocument();
    expect(screen.getByText("Do not click links.")).toBeInTheDocument();
  });

  it("states honestly when ML is not enabled and when it is", () => {
    const { rerender } = render(<PhishingResult analysis={base} />);
    expect(
      screen.getByText(/not enabled; this result uses rule-based analysis only/),
    ).toBeInTheDocument();
    rerender(
      <PhishingResult
        analysis={{
          ...base,
          ml: { available: true, probability: 0.91, model_version: "v1", top_terms: [] },
        }}
      />,
    );
    expect(screen.getByText(/91% phishing probability/)).toBeInTheDocument();
  });
});
