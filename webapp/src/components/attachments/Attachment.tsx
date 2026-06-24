"use client";

/**
 * Shared attachment renderer (ATT) — reused on record files, channels/forums, and agent
 * chat. Images render inline, video plays in a <video>, everything else is a labeled
 * download. Every item is downloadable by anyone who can see it (members + admins),
 * and the original lives at an unguessable Blob URL (trusted-tier, not E2E).
 */
import { Icon } from "@/components/primitives";
import { kindOf } from "@/lib/attachments";
import styles from "./Attachment.module.css";

export interface AttachmentItem {
  id?: string;
  name: string;
  mime?: string | null;
  /** Direct (unguessable) Blob URL — used for inline image/video display, not audited. */
  url: string;
  /** Audited download-proxy URL — used by the explicit download action (logs each download). */
  downloadUrl?: string;
}

export function Attachment({ item, compact = false }: { item: AttachmentItem; compact?: boolean }) {
  const kind = kindOf(item.name, item.mime);
  const dl = item.downloadUrl ?? item.url; // explicit downloads go through the audited proxy

  // Generated/text-only docs have no original file to download.
  if (!item.url) {
    return (
      <span className={styles.doc}>
        <Icon name="paperclip" size={14} />
        <span className={styles.name}>{item.name}</span>
        <span className={styles.mime}>text</span>
      </span>
    );
  }

  if (kind === "image" && item.url) {
    return (
      <figure className={`${styles.fig} ${compact ? styles.compact : ""}`}>
        <img src={item.url} alt={item.name} className={styles.img} loading="lazy" />
        <figcaption className={styles.cap}>
          <span className={styles.name}>{item.name}</span>
          <a href={dl} download={item.name} target="_blank" rel="noreferrer" className={styles.dl}><Icon name="download" size={12} /></a>
        </figcaption>
      </figure>
    );
  }

  if (kind === "video" && item.url) {
    return (
      <figure className={`${styles.fig} ${compact ? styles.compact : ""}`}>
        <video src={item.url} controls preload="metadata" className={styles.video} />
        <figcaption className={styles.cap}>
          <span className={styles.name}>{item.name}</span>
          <a href={dl} download={item.name} target="_blank" rel="noreferrer" className={styles.dl}><Icon name="download" size={12} /></a>
        </figcaption>
      </figure>
    );
  }

  // Documents + everything else → labeled download chip.
  return (
    <a href={dl} download={item.name} target="_blank" rel="noreferrer" className={styles.doc}>
      <Icon name="paperclip" size={14} />
      <span className={styles.name}>{item.name}</span>
      {item.mime && <span className={styles.mime}>{item.mime.split("/").pop()}</span>}
      <Icon name="download" size={12} />
    </a>
  );
}
