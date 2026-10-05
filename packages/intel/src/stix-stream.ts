import { z } from "zod";
/** Incrementally parse a STIX bundle's objects array. Only one bounded object is held at a time. */
export async function* streamStixObjects(
  stream: ReadableStream<Uint8Array>,
  maxObjectBytes = 8 * 1024 * 1024,
): AsyncGenerator<unknown> {
  const reader = stream.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
  let prefix = "";
  let started = false;
  let ended = false;
  let rootClosed = false;
  let current = "";
  let depth = 0;
  let quoted = false;
  let escaped = false;
  let expectingObject = true;
  let sawObject = false;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      let chunk = decoder.decode(result.value, { stream: true });
      if (!started) {
        prefix += chunk;
        const match = /"objects"\s*:\s*\[/.exec(prefix);
        if (!match) {
          if (prefix.length > 65536)
            throw new Error("STIX header exceeds size limit");
          continue;
        }
        const start = match.index + match[0].length;
        const header = JSON.parse(
          prefix.slice(0, start - 1) + "[]}",
        ) as unknown;
        z.object({
          type: z.literal("bundle"),
          objects: z.array(z.unknown()),
        }).parse(header);
        chunk = prefix.slice(start);
        prefix = "";
        started = true;
      }
      let fragmentStart = 0;
      for (let i = 0; i < chunk.length; i++) {
        const char = chunk[i]!;
        if (ended) {
          if (char === "}" && !rootClosed) {
            rootClosed = true;
            continue;
          }
          if (!/\s/.test(char))
            throw new Error("Unexpected trailing STIX content");
          continue;
        }
        if (depth === 0) {
          if (/\s/.test(char)) continue;
          if (char === "]") {
            if (sawObject && expectingObject)
              throw new Error("Trailing STIX comma");
            ended = true;
            continue;
          }
          if (char === "," && !expectingObject) {
            expectingObject = true;
            continue;
          }
          if (char !== "{" || !expectingObject)
            throw new Error("STIX objects must be JSON objects");
          sawObject = true;
          depth = 1;
          quoted = false;
          escaped = false;
          current = "";
          fragmentStart = i;
          expectingObject = false;
          continue;
        }
        if (quoted) {
          if (escaped) escaped = false;
          else if (char === "\\") escaped = true;
          else if (char === '"') quoted = false;
        } else if (char === '"') quoted = true;
        else if (char === "{" || char === "[") depth++;
        else if (char === "}" || char === "]") depth--;
        if (depth === 0) {
          current += chunk.slice(fragmentStart, i + 1);
          if (current.length > maxObjectBytes)
            throw new Error("STIX object exceeds size limit");
          yield JSON.parse(current) as unknown;
          current = "";
          fragmentStart = i + 1;
        }
      }
      if (depth > 0) {
        current += chunk.slice(fragmentStart);
        if (current.length > maxObjectBytes)
          throw new Error("STIX object exceeds size limit");
      }
    }
    if (!started || !ended || !rootClosed || depth !== 0)
      throw new Error("Incomplete STIX bundle");
  } finally {
    await reader.cancel();
    reader.releaseLock();
  }
}
