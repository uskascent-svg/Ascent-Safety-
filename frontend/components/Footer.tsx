import Link from "next/link";

export default function Footer() {
  return (
    <footer className="mx-auto flex w-full max-w-[1480px] flex-col justify-between gap-3 border-t border-white/[0.06] px-4 py-5 text-[10px] text-slate-600 sm:flex-row sm:items-center sm:px-6 lg:px-9">
      <p>Ascent Safety · Security intelligence from connected sources.</p>
      <div className="flex items-center gap-4"><Link href="/legal-compliance" className="transition hover:text-slate-300">Legal &amp; compliance</Link><Link href="/guidance" className="transition hover:text-slate-300">Guidance</Link><Link href="/threat-analyzer" className="transition hover:text-slate-300">Threat Analyzer</Link></div>
    </footer>
  );
}
