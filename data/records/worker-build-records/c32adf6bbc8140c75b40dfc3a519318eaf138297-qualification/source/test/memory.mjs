// An in-memory stand-in for the R2 bindings the Worker uses: get/put/list with prefix and cursor.
export function bucket(initial = {}) {
  const store = new Map(Object.entries(initial).map(([k, v]) => [k, JSON.stringify(v)]));
  return {
    store,
    async get(key) { return store.has(key) ? { json: async () => JSON.parse(store.get(key)) } : null; },
    async put(key, value) { store.set(key, value); },
    async list({ prefix = "", cursor, limit = 1000 } = {}) {
      const keys = [...store.keys()].filter(k => k.startsWith(prefix)).sort();
      const offset = cursor ? Number(cursor) : 0, end = Math.min(keys.length, offset + limit);
      return { objects: keys.slice(offset, end).map(key => ({ key })), truncated: end < keys.length, cursor: end < keys.length ? String(end) : undefined };
    },
  };
}
