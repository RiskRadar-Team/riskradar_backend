export function normailiseDomian(domain) {
  const normalisedDomain = domain
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .replace(/\/$/, "");
  return normalisedDomain;
}
