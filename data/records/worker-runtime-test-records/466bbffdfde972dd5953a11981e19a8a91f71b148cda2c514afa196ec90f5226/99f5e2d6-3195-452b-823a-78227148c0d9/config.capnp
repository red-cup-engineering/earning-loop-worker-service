using Workerd = import "/workerd/workerd.capnp";
const tests :Workerd.Config = (services = [
 (name = "loop", worker = .loop), (name = "market", worker = .market),
 (name = "main", worker = .driver), (name = "internet", network = (allow = [])), (name = "sqlite", disk = (path = "/home/emsenn/bare-cedar-fog/lib/phezi-ochage/services/561-group/services/engineering-services-section/services/computer-engineering-services-section/services/computer-systems-engineering-services-section/services/computer-economic-systems-engineering-services-section/services/computer-business-systems-engineering-services-section/services/earning-loop-worker-service/data/logs/worker-runtime-test-logs/466bbffdfde972dd5953a11981e19a8a91f71b148cda2c514afa196ec90f5226/99f5e2d6-3195-452b-823a-78227148c0d9", writable = true))
]);
const loop :Workerd.Worker = (
 modules = [(name = "worker", esModule = embed "loop.mjs")],
 compatibilityDate = "2026-09-01", compatibilityFlags = ["nodejs_compat"],
 durableObjectNamespaces = [(className = "EarningClock", uniqueKey = "issuer-cache-receiving", enableSql = true)],
 durableObjectStorage = (localDisk = "sqlite")
);
const market :Workerd.Worker = (
 modules = [(name = "worker", esModule = embed "market.mjs")],
 compatibilityDate = "2026-09-01", compatibilityFlags = ["nodejs_compat"],
 bindings = [(name = "ISSUER_EVIDENCE_CLOCK", durableObjectNamespace = (className = "EarningClock", serviceName = "loop"))]
);
const driver :Workerd.Worker = (
 modules = [(name = "worker", esModule = embed "driver.mjs")],
 compatibilityDate = "2026-09-01", compatibilityFlags = ["nodejs_compat"],
 bindings = [(name = "CLOCK", durableObjectNamespace = (className = "EarningClock", serviceName = "loop")), (name = "MARKET", service = "market")]
);
