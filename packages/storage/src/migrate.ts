import { PolicyRepository, createSharedDatabase, getSharedDatabasePath } from "./index.js";

const dbPath = getSharedDatabasePath();
const db = createSharedDatabase(dbPath);
new PolicyRepository(db);
db.close();

console.log(`database ready: ${dbPath}`);
