// The loops' working state lives in the shared R2 working-state bucket under one prefix per register.
// A register is the current reading; a record is a dated copy kept when a reading changed.
export const PREFIX = "registers/earning-loops";
export const RECORDS = "records/earning-loops";

export const read = async (bucket, key) => (await bucket.get(key))?.json() ?? null;
export const put = (bucket, key, value) =>
  bucket.put(key, JSON.stringify(value), { httpMetadata: { contentType: "application/json" } });
export const register = (name) => `${PREFIX}/${name}.json`;
export const record = (name, at) => `${RECORDS}/${name}/${at}.json`;
