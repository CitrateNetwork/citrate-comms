"use client";

/**
 * Generic kanban board with native HTML5 drag-and-drop. Reused by the CRM deals
 * pipeline and the PM task board. `onMove` persists the column change; cards render
 * via a caller-supplied function so each surface keeps its own card shape.
 */
import { useState, type ReactNode } from "react";
import styles from "./Kanban.module.css";

export interface KanbanColumn {
  key: string;
  label: string;
  accent?: string; // css var or color for the column dot
}

export interface KanbanItem {
  id: string;
  column: string;
}

export function Kanban<T extends KanbanItem>({
  columns,
  items,
  renderCard,
  onMove,
  emptyHint,
}: {
  columns: KanbanColumn[];
  items: T[];
  renderCard: (item: T) => ReactNode;
  onMove: (itemId: string, toColumn: string) => void | Promise<void>;
  emptyHint?: string;
}) {
  const [dragId, setDragId] = useState<string | null>(null);
  const [overCol, setOverCol] = useState<string | null>(null);

  return (
    <div className={styles.board}>
      {columns.map((col) => {
        const colItems = items.filter((i) => i.column === col.key);
        return (
          <div
            key={col.key}
            className={`${styles.col} ${overCol === col.key ? styles.colOver : ""}`}
            onDragOver={(e) => {
              e.preventDefault();
              setOverCol(col.key);
            }}
            onDragLeave={() => setOverCol((c) => (c === col.key ? null : c))}
            onDrop={() => {
              if (dragId) {
                const moving = items.find((i) => i.id === dragId);
                if (moving && moving.column !== col.key) onMove(dragId, col.key);
              }
              setDragId(null);
              setOverCol(null);
            }}
          >
            <div className={styles.colHead}>
              <span className={styles.colDot} style={col.accent ? { background: col.accent } : undefined} />
              <span className={styles.colLabel}>{col.label}</span>
              <span className={styles.colCount}>{colItems.length}</span>
            </div>
            <div className={styles.colBody}>
              {colItems.length === 0 && emptyHint && <div className={styles.colEmpty}>{emptyHint}</div>}
              {colItems.map((item) => (
                <div
                  key={item.id}
                  className={`${styles.card} ${dragId === item.id ? styles.dragging : ""}`}
                  draggable
                  onDragStart={() => setDragId(item.id)}
                  onDragEnd={() => {
                    setDragId(null);
                    setOverCol(null);
                  }}
                >
                  {renderCard(item)}
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}
