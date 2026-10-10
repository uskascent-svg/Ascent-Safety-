import { redirect } from "next/navigation";

export const metadata = { title: "Threat Analyzer — Ascent Safety" };

export default function PhishingPage() {
  redirect("/threat-analyzer");
}
