"use client";

import {
  Activity,
  Bell,
  BellRing,
  BookOpen,
  Compass,
  FilePlus2,
  LayoutDashboard,
  LockKeyhole,
  LogOut,
  Mail,
  Menu,
  Network,
  Shield,
  Search,
  ScrollText,
  X,
} from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { useAuth } from "@/lib/auth";
import { api } from "@/lib/api";
import type { AlertPage, NotificationPage } from "@/types/api";

const CORE_NAV = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/security-panel", label: "Security", icon: Shield },
  { href: "/reports", label: "Report issue", icon: FilePlus2 },
  { href: "/case-studies", label: "Case studies", icon: BookOpen },
  { href: "/legal-compliance", label: "Legal & compliance", icon: ScrollText },
  { href: "/guidance", label: "Guidance assistant", icon: Compass },
  { href: "/phishing", label: "Phishing lab", icon: Mail },
];

function SystemStatus() {
  const [state, setState] = useState<"checking" | "online" | "offline">("checking");

  useEffect(() => {
    let active = true;
    const check = async () => {
      try {
        const response = await fetch("/api/health/ready", { cache: "no-store" });
        const body = (await response.json()) as { status?: string; database?: string };
        if (active) setState(response.ok && body.status === "ready" ? "online" : "offline");
      } catch {
        if (active) setState("offline");
      }
    };
    void check();
    const timer = window.setInterval(check, 30_000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);

  const online = state === "online";
  return (
    <span className="inline-flex items-center gap-2 rounded-full border border-white/[0.08] bg-white/[0.025] px-3 py-1.5 text-[11px] text-slate-300">
      <span
        aria-hidden="true"
        className={`h-1.5 w-1.5 rounded-full ${online ? "bg-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.55)]" : state === "offline" ? "bg-amber-400" : "bg-slate-500 animate-pulse"}`}
      />
      {state === "checking" ? "Checking systems" : online ? "Systems operational" : "Service degraded"}
    </span>
  );
}

export default function Header() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const { status, user, isAdmin, canViewPanel, logout } = useAuth();
  const pathname = usePathname();
  const router = useRouter();
  const alertSummary = useQuery({
    queryKey: ["security", "alert-summary"],
    queryFn: () => api<AlertPage>("/api/alerts?status=open&status=acknowledged&limit=1"),
    enabled: canViewPanel,
  });
  const client = useQueryClient();
  const notifications = useQuery({
    queryKey: ["notifications"],
    queryFn: () => api<NotificationPage>("/api/notifications?limit=10"),
    enabled: status === "authed",
    refetchInterval: 30_000,
  });
  const readNotification = useMutation({
    mutationFn: (id: string) => api(`/api/notifications/${id}/read`, { method: "POST" }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["notifications"] }),
  });
  const readAllNotifications = useMutation({
    mutationFn: () => api("/api/notifications/read-all", { method: "POST" }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["notifications"] }),
  });
  const navItems = [
    ...CORE_NAV,
    ...(canViewPanel ? [{ href: "/endpoints", label: "Defense center", icon: LockKeyhole }] : []),
    ...(isAdmin ? [{ href: "/sensors", label: "Network sensors", icon: Network }] : []),
  ];

  const navLink = (href: string, label: string, Icon: (typeof CORE_NAV)[number]["icon"]) => {
    const active = href === "/" ? pathname === href : pathname.startsWith(href);
    return (
      <Link
        key={href}
        href={href}
        onClick={() => setMobileOpen(false)}
        aria-current={active ? "page" : undefined}
        className={`group flex items-center gap-3 rounded-lg border px-3 py-2.5 text-sm transition duration-200 ${
          active
            ? "border-accent/20 bg-accent/[0.09] text-white shadow-[inset_2px_0_0_0_#00d9ff,0_8px_24px_-20px_rgba(0,217,255,0.65)]"
            : "border-transparent text-slate-400 hover:border-white/[0.06] hover:bg-white/[0.035] hover:text-slate-100"
        }`}
      >
        <Icon
          aria-hidden="true"
          className={`h-[18px] w-[18px] shrink-0 ${active ? "text-accent-strong" : "text-slate-500 group-hover:text-slate-300"}`}
        />
        {label}
      </Link>
    );
  };

  return (
    <>
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-[248px] flex-col border-r border-white/[0.07] bg-[#070b13]/95 px-4 py-5 backdrop-blur-xl lg:flex">
        <Link href="/" className="mb-9 flex items-center gap-3 px-2" aria-label="Ascent Safety overview">
          <span className="grid h-9 w-9 place-items-center rounded-xl border border-accent/30 bg-accent/[0.07] text-accent-strong">
            <Activity className="h-[18px] w-[18px]" aria-hidden="true" />
          </span>
          <span className="leading-tight">
            <span className="block text-[13px] font-semibold tracking-[0.14em] text-white">ASCENT</span>
            <span className="mt-1 block text-[10px] uppercase tracking-[0.2em] text-slate-500">Security intelligence</span>
          </span>
        </Link>

        <p className="eyebrow mb-2 px-3 text-[10px] text-slate-600">Workspace</p>
        <nav aria-label="Primary" className="flex flex-col gap-1">
          {navItems.map(({ href, label, icon }) => navLink(href, label, icon))}
        </nav>

        <div className="mt-auto border-t border-white/[0.07] pt-4">
          <div className="flex items-center gap-3 px-2 py-2">
            <div className="grid h-8 w-8 shrink-0 place-items-center rounded-full border border-slate-700 bg-slate-900 text-[11px] font-medium text-slate-300">
              {user?.full_name?.slice(0, 1).toUpperCase() ?? "A"}
            </div>
            <div className="min-w-0 flex-1">
              <p className="truncate text-[13px] font-medium text-slate-200">{user?.full_name ?? "Guest workspace"}</p>
              <p className="mt-0.5 truncate text-[11px] text-slate-500">
                {user?.roles.includes("ADMINISTRATOR") ? "Administrator" : user ? "Security workspace" : "Read-only preview"}
              </p>
            </div>
          </div>
          {status === "authed" ? (
            <button type="button" onClick={logout} className="btn-secondary mt-2 w-full !justify-start !border-transparent !bg-transparent !px-3 !py-2 text-xs text-slate-400 hover:!border-white/[0.06] hover:!bg-white/[0.035]">
              <LogOut className="h-4 w-4" aria-hidden="true" /> Sign out
            </button>
          ) : (
            <Link href="/login" className="btn-secondary mt-2 w-full !justify-start !border-transparent !bg-transparent !px-3 !py-2 text-xs text-slate-400">
              <LockKeyhole className="h-4 w-4" aria-hidden="true" /> Sign in
            </Link>
          )}
          <p className="mt-4 px-2 font-mono text-[10px] uppercase tracking-[0.12em] text-slate-600">Ascent Safety · Operations</p>
        </div>
      </aside>

      <header className="sticky top-0 z-30 border-b border-white/[0.07] bg-[#070b13]/90 backdrop-blur-xl lg:ml-[248px]">
        <div className="flex h-[60px] items-center justify-between gap-3 px-4 sm:px-6 lg:px-8">
          <div className="flex min-w-0 items-center gap-3">
            <button
              type="button"
              className="rounded-lg border border-white/[0.08] p-2 text-slate-300 lg:hidden"
              aria-expanded={mobileOpen}
              aria-controls="mobile-primary-navigation"
              aria-label={mobileOpen ? "Close navigation" : "Open navigation"}
              onClick={() => setMobileOpen((value) => !value)}
            >
              {mobileOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
            </button>
            <div className="min-w-0">
              <p className="truncate text-xs font-medium text-slate-200">{navItems.find((item) => item.href === pathname)?.label ?? "Ascent workspace"}</p>
              <p className="mt-0.5 hidden font-mono text-[9px] uppercase tracking-[0.16em] text-slate-600 sm:block">Threat intelligence workspace</p>
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-2 sm:gap-4">
            {canViewPanel && <>
              <form className="hidden w-48 items-center gap-2 rounded-lg border border-white/[0.08] bg-white/[0.025] px-2.5 lg:flex xl:w-64" role="search" onSubmit={(event) => { event.preventDefault(); const query = search.trim(); router.push(query ? `/security-panel?q=${encodeURIComponent(query)}` : "/security-panel"); }}>
                <Search className="h-3.5 w-3.5 shrink-0 text-slate-600" aria-hidden="true" />
                <input aria-label="Search security events" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search events" className="min-w-0 flex-1 bg-transparent py-2 text-[11px] text-slate-200 outline-none placeholder:text-slate-600" />
              </form>
            </>}
            {status === "authed" && <div className="relative">
                <button type="button" aria-label={`Notifications${notifications.data?.unread ? `, ${notifications.data.unread} unread` : ""}`} aria-expanded={notificationsOpen} onClick={() => setNotificationsOpen((open) => !open)} className="relative rounded-lg border border-white/[0.08] p-2 text-slate-400 transition hover:border-white/[0.16] hover:text-white">
                  <BellRing className="h-4 w-4" aria-hidden="true" />
                  {(notifications.data?.unread ?? 0) > 0 && <span className="absolute -right-1 -top-1 grid h-4 min-w-4 place-items-center rounded-full bg-accent px-1 text-[9px] font-semibold text-cyber-black">{notifications.data!.unread > 99 ? "99+" : notifications.data!.unread}</span>}
                </button>
                {notificationsOpen && <div className="absolute right-0 top-11 z-50 w-[min(22rem,calc(100vw-2rem))] overflow-hidden rounded-xl border border-white/[0.1] bg-[#0b1020] shadow-2xl" role="region" aria-label="Personal notifications">
                  <div className="flex items-center justify-between border-b border-white/[0.07] px-4 py-3"><div><p className="text-xs font-medium text-white">Security notifications</p><p className="mt-1 text-[10px] text-slate-500">{notifications.data?.unread ?? 0} unread</p></div><button type="button" disabled={!notifications.data?.unread || readAllNotifications.isPending} onClick={() => readAllNotifications.mutate()} className="text-[10px] text-accent-strong disabled:text-slate-600">Mark all read</button></div>
                  {notifications.isPending ? <p className="p-5 text-xs text-slate-500">Loading notifications…</p> : notifications.isError ? <p className="p-5 text-xs text-slate-400">Notifications are unavailable.</p> : notifications.data?.items.length ? <ul className="max-h-80 divide-y divide-white/[0.06] overflow-y-auto">{notifications.data.items.map((item) => <li key={item.id}><button type="button" onClick={() => { if (!item.read_at) readNotification.mutate(item.id); setNotificationsOpen(false); router.push(canViewPanel ? `/security-panel?event_id=${encodeURIComponent(item.event_id)}` : "/"); }} className="w-full px-4 py-3 text-left transition hover:bg-white/[0.04]"><span className="flex items-start gap-2"><span className={`mt-1 h-1.5 w-1.5 shrink-0 rounded-full ${item.read_at ? "bg-slate-700" : "bg-accent"}`} /><span><span className="block line-clamp-2 text-xs text-slate-200">{item.title}</span><span className="mt-1 block text-[10px] text-slate-600">{new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(item.created_at))}</span></span></span></button></li>)}</ul> : <p className="p-5 text-xs text-slate-500">No security notifications yet.</p>}
                  {canViewPanel && <Link href="/security-panel#alerts-list" onClick={() => setNotificationsOpen(false)} className="block border-t border-white/[0.07] px-4 py-3 text-[10px] text-accent-strong hover:bg-white/[0.025]">Open alert queue</Link>}
                </div>}
              </div>}
            {canViewPanel && <Link href="/security-panel#alerts-list" aria-label={`Open alerts${alertSummary.data?.total ? `, ${alertSummary.data.total} open` : ""}`} className="relative rounded-lg border border-white/[0.08] p-2 text-slate-400 transition hover:border-white/[0.16] hover:text-white">
                <Bell className="h-4 w-4" aria-hidden="true" />
                {(alertSummary.data?.total ?? 0) > 0 && <span className="absolute -right-1 -top-1 grid h-4 min-w-4 place-items-center rounded-full bg-accent px-1 text-[9px] font-semibold text-cyber-black">{alertSummary.data!.total > 99 ? "99+" : alertSummary.data!.total}</span>}
              </Link>}
            <SystemStatus />
            {user && <span className="hidden max-w-36 truncate text-xs text-slate-400 sm:block">{user.full_name}</span>}
            {!user && status !== "loading" && <Link href="/login" className="text-xs font-medium text-accent-strong hover:text-white">Sign in</Link>}
          </div>
        </div>
        {mobileOpen && (
          <nav id="mobile-primary-navigation" aria-label="Mobile primary" className="border-t border-white/[0.07] bg-[#070b13] px-4 py-3 lg:hidden">
            <div className="flex flex-col gap-1">{navItems.map(({ href, label, icon }) => navLink(href, label, icon))}</div>
            {user && <button type="button" onClick={logout} className="btn-secondary mt-3 w-full"><LogOut className="h-4 w-4" /> Sign out</button>}
          </nav>
        )}
      </header>
    </>
  );
}
