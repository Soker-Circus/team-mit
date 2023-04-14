
et = 1590033386;
function f0(d) {
  return (
    TAD.ld[d.getUTCDay()] +
    ", " +
    TAD.lm[d.getUTCMonth()] +
    " " +
    d.getUTCDate() +
    ", " +
    d.getUTCFullYear() +
    " at " +
    (((d.getUTCHours() + 11) % 12) + 1) +
    ":" +
    p2(d.getUTCMinutes()) +
    ":" +
    p2(d.getUTCSeconds()) +
    " " +
    _ap(d)
  );
}
function f1(d) {
  return (
    TAD.ld[d.getUTCDay()] +
    ", " +
    TAD.lm[d.getUTCMonth()] +
    " " +
    d.getUTCDate() +
    ", " +
    d.getUTCFullYear() +
    " at " +
    p2(d.getUTCHours()) +
    ":" +
    p2(d.getUTCMinutes()) +
    ":" +
    p2(d.getUTCSeconds())
  );
}
function f2(d) {
  return (
    TAD.sd1[d.getDay()] +
    ", " +
    TAD.sm[d.getMonth()] +
    " " +
    d.getDate() +
    ", " +
    d.getFullYear() +
    " at " +
    p2(d.getHours()) +
    ":" +
    p2(d.getMinutes()) +
    ":" +
    p2(d.getSeconds()) +
    "." +
    pf(d.getMilliseconds(), 3)
  );
}
cks = { timelog: { t: [{ o: 0, a: "UTC" }], f: f2 } };
TAD = window.TAD || {};
TAD.lm = [];
TAD.lm[4] = "May";
TAD.sm = [];
TAD.sm[4] = "May";
TAD.ld = [];
TAD.ld[2] = "Tuesday";
TAD.ld[3] = "Wednesday";
TAD.ld[4] = "Thursday";
TAD.sd1 = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
function _ap(d) {
  var t = Math.floor(d.getTime() / 1e3 + 8640000000) % 86400;
  if (t === 0) {
    return "midnight";
  }
  if (t == 43200) {
    return "noon";
  }
  if (t < 43200) {
    return "am";
  }
  return "pm";
}
