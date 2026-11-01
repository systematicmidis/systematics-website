/* Google+ revival: the three bits of behaviour that need JavaScript.
 *
 * Each one is an enhancement, never the only way to do the thing:
 *   - the stream's "Older posts" link works when this file never loads;
 *   - every photo is a plain link to the image;
 *   - every name is a plain link to the profile.
 * Written as one deferred script so the pages stay server-rendered.
 */
(function () {
  'use strict';

  /* Infinite scroll ---------------------------------------------------------
   * Google+ loaded the next page as you neared the bottom. The link is the
   * contract: it already points at the same address this script fetches, and
   * fetching it gets a full page whose cards can be lifted out.
   */
  function initInfiniteScroll() {
    var link = document.querySelector('[data-infinite-next]');
    if (!link || !('IntersectionObserver' in window)) return;

    var loading = false;

    function loadNext() {
      if (loading || !link || !link.getAttribute('href')) return;
      loading = true;
      link.setAttribute('aria-busy', 'true');
      link.textContent = 'Loading...';

      fetch(link.getAttribute('href'), { credentials: 'same-origin' })
        .then(function (response) {
          if (!response.ok) throw new Error('HTTP ' + response.status);
          return response.text();
        })
        .then(function (html) {
          var parsed = new DOMParser().parseFromString(html, 'text/html');
          var cards = parsed.querySelectorAll('.feed .post-card');
          var feed = link.parentNode;
          for (var i = 0; i < cards.length; i++) {
            var card = document.importNode(cards[i], true);
            feed.insertBefore(card, link);
          }
          var next = parsed.querySelector('[data-infinite-next]');
          if (next && next.getAttribute('href')) {
            link.setAttribute('href', next.getAttribute('href'));
            link.setAttribute('data-infinite-next', next.getAttribute('href'));
            link.removeAttribute('aria-busy');
            link.textContent = 'Older posts →';
          } else {
            link.parentNode.removeChild(link);
            link = null;
          }
        })
        .catch(function () {
          /* Offline or refused: put the plain link back so it can be clicked. */
          if (link) {
            link.removeAttribute('aria-busy');
            link.textContent = 'Older posts →';
          }
        })
        .then(function () { loading = false; });
    }

    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) loadNext();
      });
    }, { rootMargin: '600px 0px' });
    observer.observe(link);

    /* A keyboard user tabbing onto the link should still get a normal click. */
    link.addEventListener('click', function (event) {
      if (event.metaKey || event.ctrlKey || event.shiftKey) return;
      event.preventDefault();
      loadNext();
    });
  }

  /* Lightbox ----------------------------------------------------------------
   * One overlay for a group of photos, with arrow keys and a close button. The
   * anchors keep their href, so grouping and opening in a new tab still work.
   */
  function initLightbox() {
    var overlay = null;
    var items = [];
    var index = 0;

    function close() {
      if (overlay) overlay.remove();
      overlay = null;
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = '';
    }

    function show(position) {
      if (!overlay || !items.length) return;
      index = (position + items.length) % items.length;
      var image = overlay.querySelector('img');
      image.src = items[index].getAttribute('href');
      image.alt = items[index].getAttribute('title') || '';
      var counter = overlay.querySelector('.lightbox-count');
      if (counter) counter.textContent = (index + 1) + ' / ' + items.length;
    }

    function onKey(event) {
      if (event.key === 'Escape') close();
      if (event.key === 'ArrowRight') show(index + 1);
      if (event.key === 'ArrowLeft') show(index - 1);
    }

    document.addEventListener('click', function (event) {
      var link = event.target.closest('[data-lightbox]');
      if (!link) return;
      event.preventDefault();
      items = Array.prototype.slice.call(
        document.querySelectorAll('[data-lightbox="' + link.getAttribute('data-lightbox') + '"]')
      );
      index = Math.max(0, items.indexOf(link));

      overlay = document.createElement('div');
      overlay.className = 'lightbox';
      overlay.setAttribute('role', 'dialog');
      overlay.setAttribute('aria-modal', 'true');
      overlay.innerHTML =
        '<button class="lightbox-close" type="button" aria-label="Close">×</button>' +
        '<button class="lightbox-nav prev" type="button" aria-label="Previous photo">‹</button>' +
        '<img alt="">' +
        '<button class="lightbox-nav next" type="button" aria-label="Next photo">›</button>' +
        '<span class="lightbox-count" style="position:absolute;bottom:18px;color:#fff;font-size:12px"></span>';
      document.body.appendChild(overlay);
      document.body.style.overflow = 'hidden';

      overlay.querySelector('.lightbox-close').addEventListener('click', close);
      overlay.querySelector('.prev').addEventListener('click', function () { show(index - 1); });
      overlay.querySelector('.next').addEventListener('click', function () { show(index + 1); });
      overlay.addEventListener('click', function (clickEvent) {
        if (clickEvent.target === overlay) close();
      });
      document.addEventListener('keydown', onKey);
      show(index);
    });
  }

  /* Hover cards -------------------------------------------------------------
   * A small profile card beside a name, fetched from /hover/<username> - the
   * same fragment the server renders, so it cannot disagree with the profile.
   */
  function initHovercards() {
    var card = null;
    var hideTimer = null;
    var showTimer = null;
    var current = null;

    function remove() {
      if (card) { card.classList.remove('is-open'); }
      current = null;
    }

    function place(anchor) {
      var rect = anchor.getBoundingClientRect();
      card.style.left = Math.min(window.innerWidth - 296, Math.max(8, rect.left)) + 'px';
      var below = rect.bottom + 8;
      card.style.top = (below + 240 > window.innerHeight
        ? Math.max(8, rect.top - 250)
        : below) + 'px';
    }

    function open(anchor) {
      var url = anchor.getAttribute('data-hovercard');
      if (!url) return;
      clearTimeout(hideTimer);
      clearTimeout(showTimer);
      current = anchor;
      showTimer = setTimeout(function () {
        if (!card) {
          card = document.createElement('div');
          card.className = 'hovercard';
          document.body.appendChild(card);
          card.addEventListener('mouseenter', function () { clearTimeout(hideTimer); });
          card.addEventListener('mouseleave', function () { hideTimer = setTimeout(remove, 180); });
        }
        fetch(url, { credentials: 'same-origin' })
          .then(function (response) {
            if (!response.ok) throw new Error('HTTP ' + response.status);
            return response.text();
          })
          .then(function (html) {
            if (current !== anchor) return;
            card.innerHTML = html;
            place(anchor);
            card.classList.add('is-open');
          })
          .catch(function () { /* no card is fine; the link still works */ });
      }, 220);
    }

    document.addEventListener('mouseover', function (event) {
      var anchor = event.target.closest('[data-hovercard]');
      if (anchor) open(anchor);
      else if (card && !event.target.closest('.hovercard')) {
        clearTimeout(hideTimer);
        hideTimer = setTimeout(remove, 220);
      }
    });
    document.addEventListener('focusin', function (event) {
      var anchor = event.target.closest('[data-hovercard]');
      if (anchor) open(anchor);
    });
    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape') remove();
    });
  }

  function ready() {
    initInfiniteScroll();
    initLightbox();
    initHovercards();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', ready);
  } else {
    ready();
  }
})();
