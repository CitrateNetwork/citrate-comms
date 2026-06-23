/**
 * Primitive component kit — React ports of the native @citrate-ui-kit primitives,
 * emitting the class names already defined in styles/app.css (carried verbatim from
 * the design package). Reusing the design CSS keeps the web app brand-exact and the
 * mapping to Slint mechanical. No raw hex anywhere — styling lives in app.css.
 */
import type { ButtonHTMLAttributes, CSSProperties, ReactNode } from "react";
import { Icon, type IconName } from "./icons";
import type { Role } from "@/lib/rbac/matrix";
import { ROLE_SUMMARY } from "@/lib/rbac/matrix";

export { Icon };
export type { IconName };

type BtnVariant = "primary" | "ghost" | "quiet" | "danger" | "danger-solid" | "ghost-dark";
type BtnSize = "sm" | "md" | "lg";

export function Btn({
  variant = "ghost",
  size = "md",
  icon,
  iconR,
  children,
  className = "",
  ...rest
}: {
  variant?: BtnVariant;
  size?: BtnSize;
  icon?: IconName;
  iconR?: IconName;
  children?: ReactNode;
} & ButtonHTMLAttributes<HTMLButtonElement>) {
  const cls = ["btn", `btn-${variant}`, size !== "md" ? size : "", className].filter(Boolean).join(" ");
  return (
    <button className={cls} {...rest}>
      {icon && <Icon name={icon} size={16} />}
      {children}
      {iconR && <Icon name={iconR} size={16} />}
    </button>
  );
}

export function IconBtn({
  name,
  size = 18,
  onDark = false,
  className = "",
  ...rest
}: { name: IconName; size?: number; onDark?: boolean } & ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button className={`icon-btn${onDark ? " on-dark" : ""} ${className}`.trim()} {...rest}>
      <Icon name={name} size={size} />
    </button>
  );
}

export function Card({
  lifted = false,
  className = "",
  style,
  children,
}: {
  lifted?: boolean;
  className?: string;
  style?: CSSProperties;
  children: ReactNode;
}) {
  return (
    <div className={`card${lifted ? " lifted" : ""} ${className}`.trim()} style={style}>
      {children}
    </div>
  );
}

export function Eyebrow({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`eyebrow ${className}`.trim()}>{children}</div>;
}

export function Mono({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <span className={`mono ${className}`.trim()}>{children}</span>;
}

const ROLE_ABBR: Record<Role, string> = {
  Owner: "OW",
  Admin: "AD",
  Member: "ME",
  Partner: "PT",
  Guest: "GU",
  Agent: "AG",
};

export function RoleGlyph({ role }: { role: Role }) {
  return (
    <span className={`role-glyph ${role.toLowerCase()}`} title={`${role} — ${ROLE_SUMMARY[role]}`}>
      {ROLE_ABBR[role]}
    </span>
  );
}

export function DataChip({
  children,
  variant,
  dot = false,
}: {
  children: ReactNode;
  variant?: "accent" | "external";
  dot?: boolean;
}) {
  return (
    <span className={`data-chip${variant ? ` ${variant}` : ""}`}>
      {dot && <span className="chip-dot" />}
      {children}
    </span>
  );
}

export function SurfBadge({
  children,
  variant,
}: {
  children: ReactNode;
  variant?: "e2e" | "agent" | "onprem" | "outline" | "on-dark";
}) {
  return <span className={`surf-badge${variant ? ` ${variant}` : ""}`}>{children}</span>;
}

export function RiskBadge({ level, children }: { level: "low" | "medium" | "high" | "critical"; children?: ReactNode }) {
  return (
    <span className={`risk-badge ${level}`}>
      <span className="risk-dot" />
      {children ?? level}
    </span>
  );
}

export function SevDot({
  level = "idle",
  pulse = false,
}: {
  level?: "pass" | "warn" | "block" | "idle";
  pulse?: boolean;
}) {
  return <span className={`sev-dot sev-${level}${pulse ? " sev-pulse" : ""}`} />;
}

export function AnchorMark({ children }: { children: ReactNode }) {
  return (
    <span className="anchor-mark">
      <Icon name="anchor" size={14} />
      <Mono>{children}</Mono>
    </span>
  );
}

/** Deterministic warm avatar color from an identity string (no random in render). */
function avatarColor(seed: string): string {
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0;
  const hue = h % 360;
  return `hsl(${hue} 38% 62%)`;
}

export function Avatar({
  name,
  size = "md",
  isAgent = false,
}: {
  name: string;
  size?: "sm" | "md" | "lg" | "xl";
  isAgent?: boolean;
}) {
  const initials = name
    .split(/\s+/)
    .map((w) => w[0])
    .filter(Boolean)
    .slice(0, 2)
    .join("")
    .toUpperCase();
  const cls = ["avatar", size !== "md" ? size : "", isAgent ? "agent" : ""].filter(Boolean).join(" ");
  return (
    <span className={cls} style={isAgent ? undefined : { background: avatarColor(name) }} title={name}>
      {isAgent ? "◇" : initials}
    </span>
  );
}
