/**
 * Pure grouping for the notification inbox (MEN-2 / task_assigned). Groups pings by
 * their conversation — one group per channel/DM, plus a single "Tasks" group for
 * assignments — so the bell tray renders a collapsible, per-conversation list rather
 * than one flat stream. No React here → unit-testable.
 */
export interface NotifItem {
  id: string;
  kind: string;
  actorName: string | null;
  channelId: string | null;
  channelName: string | null;
  taskId: string | null;
  read: boolean;
  createdAt: string;
}

export interface NotifGroup {
  key: string;
  name: string;
  icon: "hash" | "projects";
  items: NotifItem[];
  unread: number;
}

export function groupNotifs(items: NotifItem[]): NotifGroup[] {
  const map = new Map<string, NotifGroup>();
  for (const n of items) {
    const isTask = n.kind === "task_assigned";
    const key = isTask ? "tasks" : n.channelId ?? "other";
    const name = isTask ? "Tasks" : n.channelName ?? "Conversation";
    let g = map.get(key);
    if (!g) {
      g = { key, name, icon: isTask ? "projects" : "hash", items: [], unread: 0 };
      map.set(key, g);
    }
    g.items.push(n);
    if (!n.read) g.unread++;
  }
  return [...map.values()];
}
