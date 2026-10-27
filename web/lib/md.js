// Safe markdown subset for coach/AAR text — React-nodes only. NOTHING here
// ever becomes raw HTML: the parser returns element trees, React escapes all
// text, so scripts, event handlers, javascript: URLs and injected HTML are
// structurally impossible (proven in browser acceptance). Supported: headings,
// bold, italic, `code`, fenced code blocks, - lists, numbered lists, links
// (http/https only), and #<event_id> evidence citations — every other
// construct renders as literal text, never interpreted.
import React, { Fragment } from "react";

const EVENT_CITE = /^#(\d+)$/;

function safeUrl(u) {
  try {
    const x = new URL(u, "https://invalid.invalid");
    return x.protocol === "https:" || x.protocol === "http:" ? x.href : null;
  } catch { return null; }
}

// inline tokenizer: code spans first, then links, bold, italic, citations
function inline(text, keyp) {
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
      push(<strong>{inline(m[1], `${keyp}b${k}`)}</strong>); rest = rest.slice(m[0].length); continue;
    }
    if ((m = rest.match(/^\*([^*]+)\*/))) {
      push(<em>{inline(m[1], `${keyp}i${k}`)}</em>); rest = rest.slice(m[0].length); continue;
    }
    if ((m = rest.match(/^#(\d+)\b/))) {
      push(<a className="md-cite" href={`?tab=activity&event=${m[1]}`}
              title={`evidence event #${m[1]}`}>#{m[1]}</a>);
      rest = rest.slice(m[0].length); continue;
    }
    // plain run until just before the next potential token
    const next = rest.slice(1).search(/[`*[#]/);
    if (next === -1) { push(rest); rest = ""; }
    else { push(rest.slice(0, next + 1)); rest = rest.slice(next + 1); }
  }
  return out;
}

export function renderMarkdown(src) {
  const lines = String(src || "").split(/\r?\n/);
  const blocks = [];
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
    if (/^###\s+/.test(ln)) { blocks.push(<h4 key={key++}>{inline(ln.slice(4), key)}</h4>); i += 1; continue; }
    if (/^##\s+/.test(ln)) { blocks.push(<h3 key={key++}>{inline(ln.slice(3), key)}</h3>); i += 1; continue; }
    if (/^#\s+/.test(ln)) { blocks.push(<h2 key={key++}>{inline(ln.slice(2), key)}</h2>); i += 1; continue; }
    if (/^\s*[-*]\s+/.test(ln)) {
      const items = [];
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) {
        items.push(<li key={key + "-" + items.length}>{inline(lines[i].replace(/^\s*[-*]\s+/, ""), `${key}l${items.length}`)}</li>);
        i += 1;
      }
      blocks.push(<ul key={key++}>{items}</ul>);
      continue;
    }
    if (/^\s*\d+\.\s+/.test(ln)) {
      const items = [];
      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
        items.push(<li key={key + "-" + items.length}>{inline(lines[i].replace(/^\s*\d+\.\s+/, ""), `${key}n${items.length}`)}</li>);
        i += 1;
      }
      blocks.push(<ol key={key++}>{items}</ol>);
      continue;
    }
    if (/^\s*>/.test(ln)) {
      const quote = [];
      while (i < lines.length && /^\s*>/.test(lines[i])) { quote.push(lines[i].replace(/^\s*>\s?/, "")); i += 1; }
      blocks.push(<blockquote key={key++}>{inline(quote.join(" "), key)}</blockquote>);
      continue;
    }
    if (ln.trim() === "") { i += 1; continue; }
    const para = [];
    while (i < lines.length && lines[i].trim() !== "" &&
           !/^(```|#{1,3}\s|\s*[-*]\s|\s*\d+\.\s|\s*>)/.test(lines[i])) {
      para.push(lines[i]); i += 1;
    }
    blocks.push(<p key={key++}>{inline(para.join(" "), key)}</p>);
  }
  return blocks;
}

export function Md({ text, className }) {
  return <div className={className || "md"}>{renderMarkdown(text)}</div>;
}
