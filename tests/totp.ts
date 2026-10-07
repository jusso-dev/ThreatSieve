import { createHmac } from "node:crypto";
/** RFC 6238 test-side generator; never used by the production verifier. */
export function authenticatorCode(base32: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bits = [...base32.replace(/=+$/, "").toUpperCase()]
    .map((c) => {
      const index = alphabet.indexOf(c);
      if (index < 0) throw new Error("Invalid test TOTP secret");
      return index.toString(2).padStart(5, "0");
    })
    .join("");
  const secret = Buffer.from(
    (bits.match(/.{8}/g) ?? []).map((b) => parseInt(b, 2)),
  );
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const mac = createHmac("sha1", secret).update(counter).digest();
  const offset = mac[mac.length - 1]! & 15;
  return ((mac.readUInt32BE(offset) & 0x7fffffff) % 1000000)
    .toString()
    .padStart(6, "0");
}
