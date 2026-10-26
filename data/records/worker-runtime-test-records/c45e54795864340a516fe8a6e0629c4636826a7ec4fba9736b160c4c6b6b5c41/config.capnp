using Workerd = import "/workerd/workerd.capnp";
const tests :Workerd.Config = (services = [
 (name = "loop", worker = .loop), (name = "market", worker = .market),
 (name = "main", worker = .driver), (name = "internet", network = (allow = [])), (name = "sqlite", disk = (path = "/home/emsenn/bare-cedar-fog/lib/phezi-ochage/services/561-group/services/engineering-services-section/services/computer-engineering-services-section/services/computer-systems-engineering-services-section/services/computer-economic-systems-engineering-services-section/services/computer-business-systems-engineering-services-section/services/earning-loop-worker-service/data/logs/worker-runtime-test-logs/c45e54795864340a516fe8a6e0629c4636826a7ec4fba9736b160c4c6b6b5c41/a3e6ff90-63d2-4620-b915-9ae16a4c62b7", writable = true))
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
