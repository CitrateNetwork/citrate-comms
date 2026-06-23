import { redirect } from "next/navigation";
import { serverSession } from "@/lib/auth/server";

/**
 * Landing. Authenticated users go to the workspace switcher (/w); everyone else to
 * the sign-in front door.
 */
export default async function Home() {
  const session = await serverSession();
  if (session.authenticated) redirect("/w");
  redirect("/auth");
}
