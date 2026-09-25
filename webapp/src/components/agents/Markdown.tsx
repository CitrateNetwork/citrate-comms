"use client";

/**
 * Sanitized markdown renderer for agent output (RR-0). Markdown + GFM (tables, task
 * lists, strikethrough), safe links, and code blocks with a copy button. Streaming-safe
 * (partial markdown renders without throwing). NO raw HTML — rehype-sanitize strips it;
 * we only re-allow `className` on `code` so fenced-language blocks (e.g. ```mermaid)
 * stay detectable for RR-1/RR-2.
 */
import { memo, useEffect, useRef, useState, type ReactNode } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import rehypeSanitize, { defaultSchema } from "rehype-sanitize";
import { parseChartSpec } from "@/lib/ai/chart-spec";
import { CitrateLoader } from "./CitrateLoader";
import styles from "./Markdown.module.css";

/** The await-state shown while a diagram/chart renders (no code-flash). */
function LoaderBox() {
  return (
    <div className={styles.loaderBox}>
      <CitrateLoader size={56} />
    </div>
  );
}

/** How long a block can fail to render before we give up and show its code. */
const RENDER_SETTLE_MS = 1000;

const schema = {
  ...defaultSchema,
  attributes: {
    ...defaultSchema.attributes,
    code: [...(defaultSchema.attributes?.code ?? []), "className"],
  },
};

/** Recursively flatten a React node to plain text (for the copy button). */
function nodeText(node: ReactNode): string {
  if (node == null || typeof node === "boolean") return "";
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(nodeText).join("");
  if (typeof node === "object" && "props" in node) return nodeText((node as { props?: { children?: ReactNode } }).props?.children);
  return "";
}

// Lazy singleton mermaid (heavy; only loaded when a diagram appears).
let mermaidP: Promise<typeof import("mermaid").default> | null = null;
function getMermaid() {
  if (!mermaidP) {
    mermaidP = import("mermaid").then((m) => {
      m.default.initialize({ startOnLoad: false, securityLevel: "strict", theme: "neutral" });
      return m.default;
    });
  }
  return mermaidP;
}

let mermaidSeq = 0;

/** Render a ```mermaid block to SVG (sanitized, strict). Renders only when the block
 *  parses — during streaming or on a parse error it falls back to showing the code. */
function MermaidBlock({ code }: { code: string }) {
  const [svg, setSvg] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  const idRef = useRef(`mmd-${++mermaidSeq}`);
  useEffect(() => {
    let cancelled = false;
    let settle: ReturnType<typeof setTimeout> | undefined;
    const t = setTimeout(async () => {
      try {
        const mermaid = await getMermaid();
        await mermaid.parse(code); // throws on incomplete/invalid → keep awaiting
        const out = await mermaid.render(idRef.current, code);
        if (!cancelled) {
          setSvg(out.svg);
          setFailed(false);
        }
      } catch {
        // Don't flash code: only declare failure if the block stops changing + stays bad.
        settle = setTimeout(() => {
          if (!cancelled) setFailed(true);
        }, RENDER_SETTLE_MS);
      }
    }, 150); // debounce while streaming
    return () => {
      cancelled = true;
      clearTimeout(t);
      if (settle) clearTimeout(settle);
    };
  }, [code]);

  // Keep the last good diagram while re-rendering; loader until first success; code only
  // once it has definitively failed and never rendered.
  if (svg) return <div className={styles.mermaid} dangerouslySetInnerHTML={{ __html: svg }} />;
  if (failed) return <CodeBlock text={code} className="language-mermaid" />;
  return <LoaderBox />;
}

const blocked = () => Promise.reject(new Error("remote resources are disabled in chat charts"));
const BLOCKING_LOADER = { load: blocked, sanitize: blocked, http: blocked, file: blocked };

/** Render a ```chart block (Vega-Lite, inline data only) via lazy-loaded vega-embed.
 *  Container stays mounted so it recovers as the spec completes during streaming; on any
 *  parse/render failure it shows the code instead. */
function ChartBlock({ src }: { src: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const [state, setState] = useState<"loading" | "ok" | "error">("loading");
  useEffect(() => {
    let cancelled = false;
    let view: { finalize?: () => void } | undefined;
    let settle: ReturnType<typeof setTimeout> | undefined;
    const fail = () => {
      settle = setTimeout(() => {
        if (!cancelled) setState((s) => (s === "ok" ? s : "error"));
      }, RENDER_SETTLE_MS);
    };
    const t = setTimeout(async () => {
      const parsed = parseChartSpec(src);
      if (!parsed.ok) return fail(); // likely still streaming → keep the loader
      try {
        const embed = (await import("vega-embed")).default;
        if (cancelled || !ref.current) return;
        // Defense in depth behind parseChartSpec (PBA-L3c-021): a loader that refuses every
        // fetch/sanitize, so no chart can load a remote resource or link out. `ast: true`
        // runs expressions through vega's interpreter — no eval, so the CSP needs no
        // 'unsafe-eval' (PBA-L3c-008).
        const res = await embed(ref.current, parsed.spec as never, { actions: false, renderer: "svg", loader: BLOCKING_LOADER as never, ast: true });
        view = res.view;
        if (!cancelled) setState("ok");
      } catch {
        fail();
      }
    }, 150);
    return () => {
      cancelled = true;
      clearTimeout(t);
      if (settle) clearTimeout(settle);
      try {
        view?.finalize?.();
      } catch {
        /* ignore */
      }
    };
  }, [src]);

  // Container stays mounted (vega needs the element). Loader until first render; code
  // only after it has definitively failed.
  return (
    <>
      <div ref={ref} className={styles.chart} hidden={state !== "ok"} />
      {state === "loading" && <LoaderBox />}
      {state === "error" && <CodeBlock text={src} className="language-chart" />}
    </>
  );
}

function CodeBlock({ text, className }: { text: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  const lang = /language-(\w+)/.exec(className ?? "")?.[1];
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* clipboard blocked — ignore */
    }
  }
  return (
    <div className={styles.codeWrap}>
      <div className={styles.codeBar}>
        <span className={styles.lang}>{lang ?? "code"}</span>
        <button className={styles.copy} onClick={copy} type="button">{copied ? "copied" : "copy"}</button>
      </div>
      <pre className={styles.pre}>
        <code className={className}>{text}</code>
      </pre>
    </div>
  );
}

export const Markdown = memo(function Markdown({ children }: { children: string }) {
  return (
    <div className={styles.md}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        rehypePlugins={[[rehypeSanitize, schema]]}
        components={{
          a: ({ children, href }) => (
            <a href={href} target="_blank" rel="noreferrer noopener">
              {children}
            </a>
          ),
          table: ({ children }) => (
            <div className={styles.tableWrap}>
              <table>{children}</table>
            </div>
          ),
          pre: ({ children }) => <>{children}</>,
          code: ({ className, children }) => {
            const text = nodeText(children).replace(/\n$/, "");
            const lang = /language-(\w+)/.exec(className ?? "")?.[1];
            const isBlock = (className ?? "").startsWith("language-") || text.includes("\n");
            if (isBlock && lang === "mermaid") return <MermaidBlock code={text} />;
            if (isBlock && lang === "chart") return <ChartBlock src={text} />;
            return isBlock ? <CodeBlock text={text} className={className} /> : <code className={styles.inlineCode}>{children}</code>;
          },
        }}
      >
        {children}
      </ReactMarkdown>
    </div>
  );
});
