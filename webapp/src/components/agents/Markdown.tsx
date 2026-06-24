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
import styles from "./Markdown.module.css";

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
  const idRef = useRef(`mmd-${++mermaidSeq}`);
  useEffect(() => {
    let cancelled = false;
    const t = setTimeout(async () => {
      try {
        const mermaid = await getMermaid();
        await mermaid.parse(code); // throws on incomplete/invalid → keep showing code
        const { svg } = await mermaid.render(idRef.current, code);
        if (!cancelled) setSvg(svg);
      } catch {
        if (!cancelled) setSvg(null);
      }
    }, 150); // debounce while streaming
    return () => {
      cancelled = true;
      clearTimeout(t);
    };
  }, [code]);

  if (svg) return <div className={styles.mermaid} dangerouslySetInnerHTML={{ __html: svg }} />;
  return <CodeBlock text={code} className="language-mermaid" />;
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
            return isBlock ? <CodeBlock text={text} className={className} /> : <code className={styles.inlineCode}>{children}</code>;
          },
        }}
      >
        {children}
      </ReactMarkdown>
    </div>
  );
});
