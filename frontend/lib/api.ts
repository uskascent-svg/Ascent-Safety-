// Use the same-origin Next.js `/api` rewrite by default. A direct origin is optional for local
// development setups that run the frontend and API on separate origins.
export const API_URL = process.env.NEXT_PUBLIC_API_URL?.trim() ?? "";

// The access token lives in memory only. The refresh token is an httpOnly cookie set by the API.
let accessToken: string | null = null;
let inflightRefresh: Promise<boolean> | null = null;

export const getAccessToken = () => accessToken;
export const setAccessToken = (token: string | null) => {
  accessToken = token;
};

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

/** Refresh calls are de-duplicated: the API rotates refresh tokens, so concurrent calls would race. */
export function refreshAccessToken(): Promise<boolean> {
  inflightRefresh ??= (async () => {
    try {
      const res = await fetch(`${API_URL}/api/auth/refresh`, {
        method: "POST",
        credentials: "include",
      });
      if (!res.ok) {
        accessToken = null;
        return false;
      }
      accessToken = ((await res.json()) as { access_token: string }).access_token;
      return true;
    } catch {
      return false;
    } finally {
      inflightRefresh = null;
    }
  })();
  return inflightRefresh;
}

async function errorMessage(res: Response): Promise<string> {
  try {
    const body = await res.json();
    if (typeof body.detail === "string") return body.detail;
    if (Array.isArray(body.detail) && body.detail[0]?.msg) return String(body.detail[0].msg);
  } catch {
    /* fall through */
  }
  return `Request failed (${res.status})`;
}

export async function api<T>(path: string, init: RequestInit = {}, retry = true): Promise<T> {
  const headers = new Headers(init.headers);
  if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
  if (init.body) headers.set("Content-Type", "application/json");
  const res = await fetch(`${API_URL}${path}`, { ...init, headers, credentials: "include" });
  if (res.status === 401 && retry && (await refreshAccessToken())) {
    return api<T>(path, init, false);
  }
  if (!res.ok) throw new ApiError(res.status, await errorMessage(res));
  return res.status === 204 ? (undefined as T) : ((await res.json()) as T);
}
