// Safe markdown subset for coach/AAR text — React-nodes only. NOTHING here
// ever becomes raw HTML: the parser returns element trees, React escapes all
// text, so scripts, event handlers, javascript: URLs and injected HTML are
// structurally impossible (proven in browser acceptance). Supported: headings,
// bold, italic, `code`, fenced code blocks, - lists, numbered lists, links
// (http/https only), and #<event_id> evidence citations — every other
// construct renders as literal text, never interpreted.
//
// Citation links are an ALLOW-LIST decision (independent review finding 8):
// a #id becomes an ACTIVE evidence link ONLY when it is in the caller's
// per-message approved set (the server-validated citations / the report's
// approved_citation_ids). Everything else stays visible verbatim but renders
// as an honest UNVERIFIED label — a rejected or never-approved reference is
// never presented as linked, verified evidence.
import React, { Fragment } from "react";

function safeUrl(u) {
  try {
    const x = new URL(u, "https://invalid.invalid");
    return x.protocol === "https:" || x.protocol === "http:" ? x.href : null;
  } catch { return null; }
}

function citeNode(id, citeSet) {
  if (!citeSet.has(String(id))) {
    return <span className="md-cite-unverified" data-cite={id}
                  title="citation not in the approved evidence list — not a verified link">#{id}</span>;
  }
  return <a className="md-cite" href={`?tab=activity&event=${id}`}
            title={`evidence event #${id}`}>#{id}</a>;
}

// inline tokenizer: code spans first, then links, bold, italic, citations
function inline(text, keyp, citeSet) {
  const out = [];
  let rest = text || "";
  let k = 0;
  const push = (node) => { if (node !== null && node !== undefined) out.push(<Fragment key={`${keyp}-${k++}`}>{node}</Fragment>); };
  while (rest) {
    let m;
    if ((m = rest.match(/^`([^`]+)`/))) {
      push(<code className="md-code">{m[1]}</code>); rest = rest.slice(m[0].length); continue;
    }
    if ((m = rest.match(/^\[([^\]]+)\]\((\S+)\)/))) {
      const href = safeUrl(m[2]);
      push(href ? <a href={href} target="_blank" rel="noopener noreferrer nofollow">{m[1]}</a>
                : <span>{m[1]} ({m[2]})</span>);
      rest = rest.slice(m[0].length); continue;
    }
    if ((m = rest.match(/^\*\*([^*]+)\*\*/))) {
      push(<strong>{inline(m[1], `${keyp}b${k}`, citeSet)}</strong>); rest = rest.slice(m[0].length); continue;
    }
    if ((m = rest.match(/^\*([^*]+)\*/))) {
      push(<em>{inline(m[1], `${keyp}i${k}`, citeSet)}</em>); rest = rest.slice(m[0].length); continue;
    }
    if ((m = rest.match(/^#(\d+)\b/))) {
      push(citeNode(m[1], citeSet));
      rest = rest.slice(m[0].length); continue;
    }
    // plain run until just before the next potential token
    const next = rest.slice(1).search(/[`*[#]/);
    if (next === -1) { push(rest); rest = ""; }
    else { push(rest.slice(0, next + 1)); rest = rest.slice(next + 1); }
  }
  return out;
}

export function renderMarkdown(src, citations) {
  const lines = String(src || "").split(/\r?\n/);
  const blocks = [];
  // Fail-closed allow-list (finding 8): ONLY ids in this array render as
  // active evidence links; a missing/empty list links nothing.
  const citeSet = new Set(Array.isArray(citations) ? citations.map(String) : []);
  let i = 0, key = 0;
  while (i < lines.length) {
    const ln = lines[i];
    if (/^```/.test(ln)) {
      const code = [];
      i += 1;
      while (i < lines.length && !/^```/.test(lines[i])) { code.push(lines[i]); i += 1; }
      i += 1;
      blocks.push(<pre key={key++} className="md-pre"><code>{code.join("\n")}</code></pre>);
      continue;
    }
    if (/^###\s+/.test(ln)) { blocks.push(<h4 key={key++}>{inline(ln.slice(4), key, citeSet)}</h4>); i += 1; continue; }
    if (/^##\s+/.test(ln)) { blocks.push(<h3 key={key++}>{inline(ln.slice(3), key, citeSet)}</h3>); i += 1; continue; }
    if (/^#\s+/.test(ln)) { blocks.push(<h2 key={key++}>{inline(ln.slice(2), key, citeSet)}</h2>); i += 1; continue; }
    if (/^\s*[-*]\s+/.test(ln)) {
      const items = [];
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) {
        items.push(<li key={key + "-" + items.length}>{inline(lines[i].replace(/^\s*[-*]\s+/, ""), `${key}l${items.length}`, citeSet)}</li>);
        i += 1;
      }
      blocks.push(<ul key={key++}>{items}</ul>);
      continue;
    }
    if (/^\s*\d+\.\s+/.test(ln)) {
      const items = [];
      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
        items.push(<li key={key + "-" + items.length}>{inline(lines[i].replace(/^\s*\d+\.\s+/, ""), `${key}n${items.length}`, citeSet)}</li>);
        i += 1;
      }
      blocks.push(<ol key={key++}>{items}</ol>);
      continue;
    }
    if (/^\s*>/.test(ln)) {
      const quote = [];
      while (i < lines.length && /^\s*>/.test(lines[i])) { quote.push(lines[i].replace(/^\s*>\s?/, "")); i += 1; }
      blocks.push(<blockquote key={key++}>{inline(quote.join(" "), key, citeSet)}</blockquote>);
      continue;
    }
    if (ln.trim() === "") { i += 1; continue; }
    const para = [];
    while (i < lines.length && lines[i].trim() !== "" &&
           !/^(```|#{1,3}\s|\s*[-*]\s|\s*\d+\.\s|\s*>)/.test(lines[i])) {
      para.push(lines[i]); i += 1;
    }
    blocks.push(<p key={key++}>{inline(para.join(" "), key, citeSet)}</p>);
  }
  return blocks;
}

export function Md({ text, className, citations }) {
  return <div className={className || "md"}>{renderMarkdown(text, citations)}</div>;
}
