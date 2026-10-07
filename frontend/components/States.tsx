import { AlertCircle, Inbox } from "lucide-react";

export function Skeleton({ className = "" }: { className?: string }) {
  return <div aria-hidden="true" className={`animate-pulse rounded-lg bg-white/10 ${className}`} />;
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center gap-2 px-4 py-8 text-center" role="status">
      <Inbox className="h-6 w-6 text-slate-500" aria-hidden="true" />
      <p className="text-sm font-medium text-slate-200">{title}</p>
      {hint && <p className="text-xs text-slate-400">{hint}</p>}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center gap-2 px-4 py-8 text-center" role="alert">
      <AlertCircle className="h-6 w-6 text-sev-high" aria-hidden="true" />
      <p className="text-sm text-slate-200">{message}</p>
      {onRetry && (
        <button type="button" onClick={onRetry} className="btn-secondary">
          Try again
        </button>
      )}
    </div>
  );
}
