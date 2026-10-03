import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../services/api";

export function useWorkspace(auth) {
  const [data, setData] = useState({
    sent: [],
    received: [],
    users: [],
    events: [],
    stats: { total: 0, by_type: {}, by_severity: {} },
    audit: [],
    config: {},
    summary: { sent: 0, received: 0, completed: 0, pending: 0 },
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const generation = useRef(0);
  const refresh = useCallback(async () => {
    if (!auth) return;
    const current = ++generation.current;
    try {
      const paths = [
        "/transfers/sent",
        "/transfers/received",
        "/users",
        "/security/events",
        "/security/stats",
        "/audit",
        "/security/config",
        "/transfers/stats",
      ];
      const result = await Promise.all(
        paths.map((path) => api(path, { token: auth.token })),
      );
      if (current !== generation.current) return;
      setData(
        Object.fromEntries(
          [
            "sent",
            "received",
            "users",
            "events",
            "stats",
            "audit",
            "config",
            "summary",
          ].map((key, index) => [key, result[index]]),
        ),
      );
      setError(null);
    } catch (failure) {
      if (current === generation.current) setError(failure);
    } finally {
      if (current === generation.current) setLoading(false);
    }
  }, [auth]);
  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 6000);
    return () => clearInterval(interval);
  }, [refresh]);
  return { ...data, loading, error, refresh };
}
