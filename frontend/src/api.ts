export async function api<T = any>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const response = await fetch(`/api${path}`, {
    credentials: "include",
    ...options,
    headers:
      options.body instanceof FormData
        ? options.headers
        : { "Content-Type": "application/json", ...options.headers },
  });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    if (
      response.status === 401 &&
      path !== "/auth/login" &&
      path !== "/auth/me"
    )
      window.dispatchEvent(new Event("session-expired"));
    throw new Error(
      data.error?.message || `Request failed (${response.status})`,
    );
  }
  return response.json();
}
export const send = (path: string, body: any, method = "POST") =>
  api(path, { method, body: JSON.stringify(body) });
export function download(format: string, ip?: string) {
  window.location.href = `/api/reports/export?format=${format}${ip ? `&ip=${encodeURIComponent(ip)}` : ""}`;
}
export type SecurityEvent = {
  id: number;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  category: string;
  origin: string;
  severity: string;
  risk: number;
  rule: string;
  evidence: string[];
  action: string;
  status: string;
  ml_score: number | null;
  confidence: number | null;
  detection_source: string;
  features: Record<string, number>;
};
