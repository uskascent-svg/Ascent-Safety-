import SecurityPanel from "@/components/SecurityPanel";

export const metadata = { title: "Security Panel — Ascent Safety" };

export default function SecurityPanelPage() {
  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6">
      <SecurityPanel />
    </div>
  );
}
