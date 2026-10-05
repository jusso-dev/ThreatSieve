/** Minimal multipart port works with both Worker bindings and Miniflare's RPC objects. */
export interface ArchiveBucket {
  createMultipartUpload(
    key: string,
    options: { httpMetadata: { contentType: string } },
  ): Promise<{
    uploadPart(partNumber: number, value: Uint8Array): Promise<R2UploadedPart>;
    complete(parts: R2UploadedPart[]): Promise<unknown>;
    abort(): Promise<void>;
  }>;
}
/** R2 multipart upload keeps memory bounded and supports responses without Content-Length. */
export async function archiveStream(
  bucket: ArchiveBucket,
  key: string,
  stream: ReadableStream<Uint8Array>,
  maxBytes = 96 * 1024 * 1024,
) {
  const upload = await bucket.createMultipartUpload(key, {
    httpMetadata: { contentType: "application/stix+json" },
  });
  const reader = stream.getReader();
  const parts: R2UploadedPart[] = [];
  const size = 5 * 1024 * 1024;
  let buffer = new Uint8Array(size);
  let used = 0,
    total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) throw new Error("Archive exceeds byte limit");
      let offset = 0;
      while (offset < value.byteLength) {
        const length = Math.min(size - used, value.byteLength - offset);
        buffer.set(value.subarray(offset, offset + length), used);
        offset += length;
        used += length;
        if (used === size) {
          parts.push(await upload.uploadPart(parts.length + 1, buffer));
          buffer = new Uint8Array(size);
          used = 0;
        }
      }
    }
    if (used || parts.length === 0)
      parts.push(
        await upload.uploadPart(parts.length + 1, buffer.subarray(0, used)),
      );
    await upload.complete(parts);
    return total;
  } catch (error) {
    await upload.abort();
    throw error;
  } finally {
    await reader.cancel();
    reader.releaseLock();
  }
}
