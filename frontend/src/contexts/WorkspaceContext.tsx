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
import type { Workspace } from "@/types";
import { getWorkspaces } from "@/lib/api";

const STORAGE_KEY = "ct_workspace_id";

interface WorkspaceContextValue {
  /** All workspaces the current user is a member of. */
  workspaces: Workspace[];
  /** Currently selected workspace.  Null while loading or if no workspaces exist. */
  selectedWorkspace: Workspace | null;
  /** Whether the initial workspace list load is in progress. */
  loading: boolean;
  /** Select a workspace by ID and persist the choice. */
  selectWorkspace: (id: string) => void;
  /** Re-fetch the workspace list (call after create/join/rename). */
  refreshWorkspaces: () => Promise<void>;
}

const WorkspaceContext = createContext<WorkspaceContextValue>({
  workspaces: [],
  selectedWorkspace: null,
  loading: true,
  selectWorkspace: () => undefined,
  refreshWorkspaces: async () => undefined,
});

export function WorkspaceProvider({ children }: { children: React.ReactNode }) {
  const { getToken, isSignedIn, isLoaded } = useAuth();
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

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

  return (
    <WorkspaceContext.Provider
      value={{
        workspaces,
        selectedWorkspace,
        loading,
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
