/* Reader-local timestamps for the update-log placeholder.
 *
 * A post may write [DATE] (or the whole Google+ phrase "[DATE] at [LOCAL USER
 * TIME ZONE]"); the server resolves it while it renders the page
 * (src/worker.py), but it can only answer in UTC, because only the browser knows
 * which zone the reader is actually in. The resolved stamp therefore arrives as
 * a <time class="log-time"> carrying the true UTC instant in data-log-time, and
 * this file restates that instant on the reader's own clock.
 *
 * Only the time is restated - the zone is not printed. The stamp is already
 * unambiguous to the person reading it, and a name like "America/Chicago" says
 * more about their settings than about the post.
 *
 * Nothing here is needed for the page to make sense. Without JavaScript the
 * stamp still reads correctly, just as UTC, which is how every other date on
 * this site is shown. The <time datetime> attribute keeps the true UTC value
 * either way, so the markup stays machine-readable.
 */
(function () {
  'use strict';

  function pad(value) {
    return (value < 10 ? '0' : '') + value;
  }

  function stamp(date) {
    var hour = date.getHours();
    var half = hour < 12 ? 'am' : 'pm';
    return date.getFullYear() + '-' + pad(date.getMonth() + 1) + '-' + pad(date.getDate())
      + ' ' + (hour % 12 || 12) + ':' + pad(date.getMinutes()) + ' ' + half;
  }

  var nodes = document.querySelectorAll('.log-time[data-log-time]');
  for (var i = 0; i < nodes.length; i++) {
    var date = new Date(nodes[i].getAttribute('data-log-time'));
    if (isNaN(date.getTime())) {
      continue;   // an unparseable stamp keeps the UTC text it was rendered with
    }
    nodes[i].textContent = stamp(date);
  }
})();
