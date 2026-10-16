export const BULK_ARCHIVE_PAGE_SIZE = 1000;
/** Stable keys make partition writes safe to repeat before publishing a job. */
export const archivePageKey = (key: string, offset: number) =>
  key + "/pages/" + offset + ".json";

export async function partitionArchive(
  archive: { put(key: string, body: string): Promise<unknown> },
  key: string,
  records: unknown[],
  size: number,
) {
  for (let offset = 0; offset < records.length; offset += size)
    await archive.put(
      archivePageKey(key, offset),
      JSON.stringify(records.slice(offset, offset + size)),
    );
  // Empty uploads still have one readable page.
  if (!records.length) await archive.put(archivePageKey(key, 0), "[]");
}
