// ============================================================================
// CognitiveCTI — Static Search (lunr.js)
// ============================================================================
(function () {
  'use strict';

  var searchInput = document.getElementById('search-input');
  var searchResults = document.getElementById('search-results');
  var searchInfo = document.getElementById('search-info');
  var index = null;
  var store = null;

  var categoryClasses = {
    daily: 'category-badge--daily',
    weekly: 'category-badge--weekly',
    monthly: 'category-badge--monthly',
    analysis: 'category-badge--analysis'
  };

  var severityClasses = {
    critical: 'severity-badge--critical',
    high: 'severity-badge--high',
    medium: 'severity-badge--medium',
    low: 'severity-badge--low',
    info: 'severity-badge--info'
  };

  function escapeHtml(text) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(text));
    return div.innerHTML;
  }

  function loadIndex() {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', window.__searchJsonUrl || '/search.json', true);
    xhr.onreadystatechange = function () {
      if (xhr.readyState !== 4) return;
      if (xhr.status !== 200) {
        searchInfo.textContent = 'Failed to load search index.';
        return;
      }

      try {
        var data = JSON.parse(xhr.responseText);
        store = {};

        index = lunr(function () {
          this.ref('url');
          this.field('title', { boost: 10 });
          this.field('description', { boost: 5 });
          this.field('tags', { boost: 5 });
          this.field('category', { boost: 2 });
          this.field('severity', { boost: 2 });
          this.field('content');

          for (var i = 0; i < data.length; i++) {
            var entry = data[i];
            var indexEntry = {
              url: entry.url,
              title: entry.title,
              description: entry.description,
              tags: Array.isArray(entry.tags) ? entry.tags.join(' ') : '',
              category: entry.category,
              severity: entry.severity,
              content: entry.content
            };
            this.add(indexEntry);
            store[entry.url] = entry;
          }
        });

        searchInfo.textContent = data.length + ' posts indexed.';

        var params = new URLSearchParams(window.location.search);
        var q = params.get('q');
        if (q) {
          searchInput.value = q;
          performSearch(q);
        }
      } catch (e) {
        searchInfo.textContent = 'Error building search index.';
      }
    };
    xhr.send();
  }

  function performSearch(query) {
    if (!index || !query || query.trim().length < 2) {
      searchResults.innerHTML = '';
      if (store) {
        searchInfo.textContent = Object.keys(store).length + ' posts indexed.';
      }
      return;
    }

    var results;
    try {
      results = index.search(query);
      if (results.length === 0) {
        results = index.search(query + '*');
      }
    } catch (e) {
      try {
        results = index.search(query.replace(/[:\-~^+]/g, ' '));
      } catch (e2) {
        results = [];
      }
    }

    if (results.length === 0) {
      searchResults.innerHTML = '';
      searchInfo.textContent = 'No results for \u201c' + escapeHtml(query) + '\u201d.';
      return;
    }

    searchInfo.textContent = results.length + ' result' + (results.length === 1 ? '' : 's') + ' for \u201c' + escapeHtml(query) + '\u201d.';

    var html = '';
    for (var i = 0; i < results.length; i++) {
      var item = store[results[i].ref];
      if (!item) continue;

      var catClass = categoryClasses[item.category] || 'category-badge--daily';
      var sevBadge = '';
      if (item.severity && severityClasses[item.severity]) {
        sevBadge = '<span class="severity-badge ' + severityClasses[item.severity] + '">' + escapeHtml(item.severity) + '</span>';
      }

      var tagHtml = '';
      if (item.tags && item.tags.length) {
        tagHtml = '<div class="post-tags">';
        for (var t = 0; t < item.tags.length; t++) {
          tagHtml += '<span class="post-tag">' + escapeHtml(item.tags[t]) + '</span>';
        }
        tagHtml += '</div>';
      }

      var excerpt = item.description || item.content;
      if (excerpt && excerpt.length > 160) {
        excerpt = excerpt.substring(0, 160) + '\u2026';
      }

      html += '<li class="post-list__item">' +
        '<a class="post-card" href="' + escapeHtml(item.url) + '">' +
          '<div class="post-card__meta">' +
            '<time class="post-card__date">' + escapeHtml(item.date) + '</time>' +
            '<span class="category-badge ' + catClass + '">' + escapeHtml(item.category) + '</span>' +
            sevBadge +
          '</div>' +
          tagHtml +
          '<h2 class="post-card__title">' + escapeHtml(item.title) + '</h2>' +
          '<p class="post-card__excerpt">' + escapeHtml(excerpt) + '</p>' +
        '</a>' +
      '</li>';
    }

    searchResults.innerHTML = html;
  }

  var debounceTimer;
  function debounce(fn, delay) {
    return function () {
      var args = arguments;
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(function () { fn.apply(null, args); }, delay);
    };
  }

  if (searchInput) {
    searchInput.addEventListener('input', debounce(function () {
      var q = searchInput.value.trim();
      performSearch(q);

      var url = new URL(window.location);
      if (q) {
        url.searchParams.set('q', q);
      } else {
        url.searchParams.delete('q');
      }
      history.replaceState(null, '', url);
    }, 200));
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', loadIndex);
  } else {
    loadIndex();
  }
})();