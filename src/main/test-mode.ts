/**
 * Test-mode helpers. When RUD1_TEST_MODE is truthy the desktop app points at a
 * local rud1-es (default http://localhost:3000) instead of production. With the
 * var absent, every consumer keeps its production default — no behavior change.
 *
 * RUD1_TEST_HOST selects the LAN IP/host of the dev machine running rud1-es
 * (default "localhost"), so the desktop on one machine can reach rud1-es on
 * another.
 *
 * Each helper takes an `env` arg (defaulting to process.env) so it stays a pure,
 * unit-testable function.
 */
type Env = NodeJS.ProcessEnv;

export function isTestMode(env: Env = process.env): boolean {
  const v = env.RUD1_TEST_MODE;
  return v === "1" || v?.toLowerCase() === "true";
}

export function testHost(env: Env = process.env): string {
  const v = env.RUD1_TEST_HOST?.trim();
  return v && v.length > 0 ? v : "localhost";
}

export function testBaseUrl(env: Env = process.env): string {
  return `http://${testHost(env)}:3000`;
}
