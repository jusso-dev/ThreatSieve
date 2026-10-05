import { it, expect } from "vitest";
import { Miniflare } from "miniflare";
import { archiveStream } from "../packages/intel/src/archive-stream";
it("archives unknown-length responses in bounded multipart chunks and aborts oversize uploads", async () => {
  const mf = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: "2026-08-06",
    r2Buckets: ["ARCHIVE"],
  });
  try {
    const bucket = await mf.getR2Bucket("ARCHIVE");
    const bytes = new Uint8Array(6 * 1024 * 1024 + 321).fill(93);
    let offset = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (offset === bytes.length) {
          controller.close();
          return;
        }
        const end = Math.min(offset + 8193, bytes.length);
        controller.enqueue(bytes.slice(offset, end));
        offset = end;
      },
    });
    expect(await archiveStream(bucket, "raw/test.json", body)).toBe(
      bytes.length,
    );
    const saved = await bucket.get("raw/test.json");
    expect(saved?.size).toBe(bytes.length);
    expect(
      Buffer.compare(
        Buffer.from(await saved!.arrayBuffer()),
        Buffer.from(bytes),
      ),
    ).toBe(0);
    const large = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(new Uint8Array(20));
        c.close();
      },
    });
    await expect(
      archiveStream(bucket, "raw/rejected.json", large, 10),
    ).rejects.toThrow("byte limit");
    expect(await bucket.get("raw/rejected.json")).toBeNull();
  } finally {
    await mf.dispose();
  }
}, 20000);
