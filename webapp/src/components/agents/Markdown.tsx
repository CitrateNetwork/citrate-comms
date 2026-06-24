"use client";

/**
 * Sanitized markdown renderer for agent output (RR-0). Markdown + GFM (tables, task
 * lists, strikethrough), safe links, and code blocks with a copy button. Streaming-safe
 * (partial markdown renders without throwing). NO raw HTML — rehype-sanitize strips it;
 * we only re-allow `className` on `code` so fenced-language blocks (e.g. ```mermaid)
 * stay detectable for RR-1/RR-2.
 */
import { memo, useState, type ReactNode } from "react";
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
            const isBlock = (className ?? "").startsWith("language-") || text.includes("\n");
            return isBlock ? <CodeBlock text={text} className={className} /> : <code className={styles.inlineCode}>{children}</code>;
          },
        }}
      >
        {children}
      </ReactMarkdown>
    </div>
  );
});
