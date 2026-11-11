// The loops' own clock, for accounts whose cron-trigger allowance is spent (the Workers Free plan allows five per
// account): a Durable Object whose alarm runs the due loops and re-arms itself for the next quarter hour. Arming
// it once (GET /clock) starts the clock. Failed runs try to retain its next alarm;
// if alarm writes also fail, recovery still needs an independently received alarm.
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

// Protect the whole alarm turn, including planning reads and final scheduling.
// The fallback needs no reads, so an exhausted rows_read allowance does not
// prevent attempting the next ordinary maintenance tick. Preserve a successfully
// selected research/acquisition deadline and keep the original failure visible.
export async function withAlarmRecovery(storage, work) {
  let rearmed = false;
  try {
    return await work(async (at) => {
      await storage.setAlarm(at);
      rearmed = true;
    });
  } catch (error) {
    if (!rearmed) {
      try {
        await storage.setAlarm(nextTick(Date.now()));
      } catch (recoveryError) {
        throw new AggregateError([error, recoveryError], 'Earning clock failed and its next alarm could not be restored');
      }
    }
    throw error;
  }
}
