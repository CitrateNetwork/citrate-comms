/**
 * Icon system — single-stroke, 24×24, currentColor (maps 1:1 to the native kit's
 * AppIcon). Subset of the design package's glyphs; add names as screens need them.
 */
import type { CSSProperties } from "react";

const PATHS: Record<string, string> = {
  hash: "M5 9h14M5 15h14M9 4L7 20M17 4l-2 16",
  forum: "M4 5h16v10H9l-4 4V5z",
  dm: "M4 5h16v12H8l-4 3V5z",
  crm: "M4 6h16v12H4zM4 10h16",
  projects: "M4 5h7v6H4zM13 5h7v4h-7zM13 13h7v6h-7zM4 15h7v4H4z",
  agents: "M12 3a4 4 0 014 4v2a4 4 0 01-8 0V7a4 4 0 014-4zM5 21v-1a7 7 0 0114 0v1",
  audit: "M6 3h9l3 3v15H6zM9 12h6M9 16h6M9 8h3",
  settings: "M12 8a4 4 0 100 8 4 4 0 000-8zM12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2",
  security: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z",
  plus: "M12 5v14M5 12h14",
  search: "M11 4a7 7 0 100 14 7 7 0 000-14zM20 20l-4-4",
  chevR: "M9 6l6 6-6 6",
  chevD: "M6 9l6 6 6-6",
  lock: "M6 11h12v9H6zM8 11V8a4 4 0 018 0v3",
  send: "M4 12l16-8-6 16-3-6-7-2z",
  at: "M12 8a4 4 0 100 8 4 4 0 000-8zM16 12v1a3 3 0 006 0 9 9 0 10-3 6.7",
  link: "M9 15l6-6M8 12l-2 2a3 3 0 004 4l2-2M16 12l2-2a3 3 0 00-4-4l-2 2",
  paperclip: "M21 11l-9 9a5 5 0 01-7-7l9-9a3 3 0 014 4l-9 9a1 1 0 01-2-2l8-8",
  info: "M12 8h.01M11 12h1v5h1M12 3a9 9 0 100 18 9 9 0 000-18z",
  copy: "M9 9h11v11H9zM5 15H4V4h11v1",
  check: "M5 12l5 5 9-11",
  dots: "M5 12h.01M12 12h.01M19 12h.01",
  bell: "M6 16V10a6 6 0 1112 0v6l2 2H4zM10 20a2 2 0 004 0",
  filter: "M4 5h16l-6 8v5l-4 2v-7z",
  download: "M12 4v11M7 11l5 5 5-5M5 20h14",
  x: "M6 6l12 12M18 6L6 18",
  star: "M12 4l2.5 5 5.5.8-4 4 1 5.5-5-2.7-5 2.7 1-5.5-4-4 5.5-.8z",
  pause: "M8 5v14M16 5v14",
  play: "M7 5l12 7-12 7z",
  shield: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z",
  key: "M14 7a4 4 0 11-3.5 6L4 19v-3h3v-3l3.5-3.5A4 4 0 0114 7z",
  refresh: "M4 12a8 8 0 0114-5l2 2M20 12a8 8 0 01-14 5l-2-2M18 4v5h-5M6 20v-5h5",
  anchor: "M12 7a2 2 0 100-4 2 2 0 000 4zM12 7v13M5 13a7 7 0 0014 0M5 13H3M19 13h2",
  device: "M5 4h14v12H5zM9 20h6",
  globe: "M12 3a9 9 0 100 18 9 9 0 000-18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18",
  clock: "M12 7v5l3 2M12 3a9 9 0 100 18 9 9 0 000-18z",
  wallet: "M4 7h16v11H4zM4 7l2-3h12l2 3M16 12h2",
  logout: "M14 4h5v16h-5M14 12H4M7 9l-3 3 3 3",
  user: "M12 3a4 4 0 100 8 4 4 0 000-8zM5 21v-1a7 7 0 0114 0v1",
};

export type IconName = keyof typeof PATHS | string;

export function Icon({
  name,
  size = 18,
  stroke = 1.6,
  style,
}: {
  name: IconName;
  size?: number;
  stroke?: number;
  style?: CSSProperties;
}) {
  const d = PATHS[name] ?? PATHS.info!;
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={stroke}
      strokeLinecap="round"
      strokeLinejoin="round"
      style={style}
      aria-hidden="true"
    >
      <path d={d} />
    </svg>
  );
}
