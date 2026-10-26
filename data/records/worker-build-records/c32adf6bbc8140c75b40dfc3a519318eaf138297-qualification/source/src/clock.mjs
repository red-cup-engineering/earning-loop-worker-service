// The loops' own clock, for accounts whose cron-trigger allowance is spent (the Workers Free plan allows five per
// account): a Durable Object whose alarm runs the due loops and re-arms itself for the next quarter hour. Arming
// it once (GET /clock) is enough; a failed run still re-arms, so the clock never stops on an error.
export const TICK_MS = 15 * 60_000;

// A five-field cron matcher for the forms the operation uses: "*", "*/n", "n" and "a,b" (minute hour dom month dow), UTC.
export function matches(cron, date) {
  const fields = cron.trim().split(/\s+/);
  const values = [date.getUTCMinutes(), date.getUTCHours(), date.getUTCDate(), date.getUTCMonth() + 1, date.getUTCDay()];
  return fields.length === 5 && fields.every((field, i) => field.split(",").some((part) => {
    if (part === "*") return true;
    const step = part.match(/^\*\/(\d+)$/);
    return step ? values[i] % Number(step[1]) === 0 : Number(part) === values[i];
  }));
}

export const dueCrons = (crons, date) => Object.values(crons).filter((cron) => matches(cron, date));
export const nextTick = (now) => Math.floor(now / TICK_MS) * TICK_MS + TICK_MS;
