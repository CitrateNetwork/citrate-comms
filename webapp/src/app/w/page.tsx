import { redirect } from "next/navigation";
import { serverOwner } from "@/lib/auth/server";
import { workspacesForUser } from "@/lib/domain/workspaces";
import { WorkspacePicker } from "./WorkspacePicker";

/**
 * Workspace switcher / first-run. Server component: resolves the session, lists the
 * user's workspaces, and hands them to the client picker. Unauthenticated → sign-in.
 */
export const dynamic = "force-dynamic";

export default async function WorkspaceHome() {
  const sub = await serverOwner();
  if (!sub) redirect("/auth?returnTo=/w");

  const workspaces = await workspacesForUser(sub);
  return <WorkspacePicker workspaces={workspaces} />;
}
