import { it, expect } from "vitest";
import { streamStixObjects } from "../packages/intel/src/stix-stream";
function stream(text: string, size = 3) {
  const bytes = new TextEncoder().encode(text);
  let i = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (i >= bytes.length) {
        controller.close();
        return;
      }
      controller.enqueue(bytes.slice(i, i + size));
      i += size;
    },
  });
}
it("streams Unicode, nested JSON and escaped braces across arbitrary byte boundaries", async () => {
  const objects = [
    {
      id: "a",
      description: 'Quoted "strings", } [ braces and ünicode.',
      nested: { values: [1, 2, { safe: true }] },
    },
    { id: "b", type: "malware" },
  ];
  const result = [];
  for await (const object of streamStixObjects(
    stream(JSON.stringify({ type: "bundle", id: "bundle--test", objects })),
  ))
    result.push(object);
  expect(result).toEqual(objects);
});
it("rejects truncated, malformed and oversized stream objects", async () => {
  const collect = async (text: string, limit?: number) => {
    for await (const _object of streamStixObjects(stream(text), limit)) {
      /* Drain bounded test stream. */
    }
  };
  await expect(
    collect('{"type":"bundle","objects":[{"id":"a"}'),
  ).rejects.toThrow("Incomplete");
  await expect(
    collect('{"type":"bundle","objects":[{"id":"a"}{"id":"b"}]}'),
  ).rejects.toThrow("JSON objects");
  await expect(
    collect(
      JSON.stringify({
        type: "bundle",
        objects: [{ id: "a", description: "x".repeat(100) }],
      }),
      20,
    ),
  ).rejects.toThrow("size limit");
});
