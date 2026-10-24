// An in-memory stand-in for the R2 bindings the Worker uses: get/put/list with prefix and cursor.
export function bucket(initial = {}) {
  const store = new Map(Object.entries(initial).map(([k, v]) => [k, JSON.stringify(v)]));
  return {
    store,
    async get(key) { return store.has(key) ? { json: async () => JSON.parse(store.get(key)) } : null; },
    async put(key, value) { store.set(key, value); },
    async list({ prefix = "" } = {}) { return { objects: [...store.keys()].filter((k) => k.startsWith(prefix)).map((key) => ({ key })), truncated: false }; },
  };
}
