---
layout: default
title: Search
permalink: /search/
---

<header class="page-header">
  <h1 class="page-header__title">Search Intelligence</h1>
</header>

<div class="search-container">
  <div class="search-input-wrap">
    <svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/>
    </svg>
    <input
      type="search"
      id="search-input"
      class="search-input"
      placeholder="Search by CVE, threat actor, malware, keyword..."
      autocomplete="off"
      autofocus
    >
  </div>
  <p id="search-info" class="search-info"></p>
  <ul id="search-results" class="post-list"></ul>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/lunr.js/2.3.9/lunr.min.js"></script>
<script>window.__searchJsonUrl = "{{ '/search.json' | relative_url }}";</script>
<script src="{{ '/assets/js/search.js' | relative_url }}" defer></script>
