import { useMemo, useSyncExternalStore } from "react";
import { USER_KEY } from "./api";

export type StoredUser = {
  name: string;
  email: string;
  role: string;
};

// The browser only fires "storage" for other tabs, so writes made through
// setStoredItem announce themselves with this event for the current tab.
const LOCAL_CHANGE_EVENT = "secure-gateway-storage";

function subscribe(onChange: () => void) {
  window.addEventListener("storage", onChange);
  window.addEventListener(LOCAL_CHANGE_EVENT, onChange);
  return () => {
    window.removeEventListener("storage", onChange);
    window.removeEventListener(LOCAL_CHANGE_EVENT, onChange);
  };
}

/** Reads a localStorage key; returns null during server rendering. */
export function useStoredItem(key: string): string | null {
  return useSyncExternalStore(
    subscribe,
    () => window.localStorage.getItem(key),
    () => null,
  );
}

export function setStoredItem(key: string, value: string) {
  window.localStorage.setItem(key, value);
  window.dispatchEvent(new Event(LOCAL_CHANGE_EVENT));
}

export function useStoredUser(): StoredUser | null {
  const raw = useStoredItem(USER_KEY);
  return useMemo(() => {
    if (!raw) return null;
    try {
      return JSON.parse(raw) as StoredUser;
    } catch {
      return null;
    }
  }, [raw]);
}
