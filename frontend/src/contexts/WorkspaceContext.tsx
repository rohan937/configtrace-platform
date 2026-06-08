"use client";

/**
 * WorkspaceContext — M50
 *
 * Manages the selected workspace for the app shell.  The selected workspace ID
 * is persisted to localStorage so it survives page refreshes.
 *
 * All data-fetching pages (integrations, resources, timeline, changes) should
 * read selectedWorkspace from this context and pass its id as workspace_id to
 * API calls that support workspace scoping.
 */

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import { useAuth } from "@clerk/nextjs";
import type { Workspace, WorkspaceRole } from "@/types";
import { getWorkspaces, getMyWorkspaceMembership } from "@/lib/api";

const STORAGE_KEY = "ct_workspace_id";

interface WorkspaceContextValue {
  /** All workspaces the current user is a member of. */
  workspaces: Workspace[];
  /** Currently selected workspace.  Null while loading or if no workspaces exist. */
  selectedWorkspace: Workspace | null;
  /** Whether the initial workspace list load is in progress. */
  loading: boolean;
  /** Current user's role in the selected workspace (M63.5). Null until resolved. */
  role: WorkspaceRole | null;
  /** True once the role lookup has completed (success or failure). */
  roleLoaded: boolean;
  /** Convenience: role is admin or owner. */
  isAdmin: boolean;
  /** Select a workspace by ID and persist the choice. */
  selectWorkspace: (id: string) => void;
  /** Re-fetch the workspace list (call after create/join/rename). */
  refreshWorkspaces: () => Promise<void>;
}

const WorkspaceContext = createContext<WorkspaceContextValue>({
  workspaces: [],
  selectedWorkspace: null,
  loading: true,
  role: null,
  roleLoaded: false,
  isAdmin: false,
  selectWorkspace: () => undefined,
  refreshWorkspaces: async () => undefined,
});

export function WorkspaceProvider({ children }: { children: React.ReactNode }) {
  const { getToken, isSignedIn, isLoaded } = useAuth();
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [role, setRole] = useState<WorkspaceRole | null>(null);
  const [roleLoaded, setRoleLoaded] = useState(false);

  const loadWorkspaces = useCallback(async () => {
    if (!isLoaded || !isSignedIn) return;
    try {
      const token = await getToken();
      const resp = await getWorkspaces(token);
      setWorkspaces(resp.workspaces);

      // Restore persisted selection, or fall back to the first workspace.
      const stored = localStorage.getItem(STORAGE_KEY);
      const valid = resp.workspaces.find((w) => w.id === stored);
      if (valid) {
        setSelectedId(valid.id);
      } else if (resp.workspaces.length > 0) {
        setSelectedId(resp.workspaces[0].id);
      }
    } catch {
      // Workspace load failure is non-fatal — app still renders.
    } finally {
      setLoading(false);
    }
  }, [isLoaded, isSignedIn, getToken]);

  useEffect(() => {
    loadWorkspaces();
  }, [loadWorkspaces]);

  const selectWorkspace = useCallback((id: string) => {
    setSelectedId(id);
    localStorage.setItem(STORAGE_KEY, id);
  }, []);

  const selectedWorkspace =
    workspaces.find((w) => w.id === selectedId) ?? null;

  // M63.5: resolve the current user's role in the selected workspace so the UI
  // can disable high-impact Security Exposure actions for non-admins.
  useEffect(() => {
    let cancelled = false;
    if (!isLoaded || !isSignedIn || !selectedId) {
      setRole(null);
      setRoleLoaded(false);
      return;
    }
    setRoleLoaded(false);
    (async () => {
      try {
        const token = await getToken();
        const m = await getMyWorkspaceMembership(selectedId, token);
        if (!cancelled) setRole(m.role);
      } catch {
        // Non-fatal: leave role null (high-impact actions fail safe to disabled).
        if (!cancelled) setRole(null);
      } finally {
        if (!cancelled) setRoleLoaded(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [isLoaded, isSignedIn, selectedId, getToken]);

  const isAdmin = role === "admin" || role === "owner";

  return (
    <WorkspaceContext.Provider
      value={{
        workspaces,
        selectedWorkspace,
        loading,
        role,
        roleLoaded,
        isAdmin,
        selectWorkspace,
        refreshWorkspaces: loadWorkspaces,
      }}
    >
      {children}
    </WorkspaceContext.Provider>
  );
}

export function useWorkspace(): WorkspaceContextValue {
  return useContext(WorkspaceContext);
}
