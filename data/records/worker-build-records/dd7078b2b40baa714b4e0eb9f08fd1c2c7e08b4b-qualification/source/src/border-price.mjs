// Border price relation, revived from the Executive Office finance-and-market section
// (lib/legacy/2026-07-25-finance-and-market-services-section/src/border-price.mjs, discoverBorderPrice):
// a price forms only at a border, between one seller's ask and one buyer's bid. Here the ask is an
// offer's listed price and the bids are revealed by what buyers did at that ask.
//
// - crossed-range: buyers kept paying the ask, so their bids sat at or above it; the seller may requote up.
// - exact-match:   some buyers paid; the ask is inside the range buyers accept.
// - open-gap:      the offer was healthy and listed and nobody paid; either bids sit below the ask or there is
//                  no buyer yet. The relation alone cannot say which, so it never justifies a cut by itself.
// - unobserved:    the offer was not healthy or not listed long enough to reveal anything.
export const CROSSED_SALES = 20;

export function revealedBorder({ healthyDays, listedDays, outsideSales }) {
  if (healthyDays < 14 || listedDays < 14) return outsideSales > 0 ? "exact-match" : "unobserved";
  if (outsideSales >= CROSSED_SALES) return "crossed-range";
  if (outsideSales > 0) return "exact-match";
  return "open-gap";
}
