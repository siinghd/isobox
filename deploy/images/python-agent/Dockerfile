# isobox python-agent image — batteries-included Python for AI-agent workloads:
# HTTP clients, HTML/XML scraping, data wrangling, parsing. All wheels are
# arm64/amd64 manylinux so the build needs no compiler. Libs are baked in so they
# work even with the sandbox network OFF (compute); turn network ON to fetch.
# Base pinned by digest (THREAT_MODEL control #13): a floating :3-slim tag could
# silently swap in unvetted code under the trust base of every sandbox run.
# Update the digest deliberately (re-resolve with `docker inspect`), not implicitly.
FROM python:3-slim@sha256:c845af9399020c7e562969a13689e929074a10fd057acd1b1fad06a2fb068e97

# Runtime libs some wheels dlopen (lxml/pillow) + a real shell toolbelt so the
# interpreter can act like an OS: curl/wget for HTTP, jq for JSON, git, ripgrep,
# unzip, ca-certificates for TLS. These power bash/sh code cells, not just Python.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libxml2 libxslt1.1 ca-certificates \
      curl wget jq git ripgrep unzip procps less nano \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
      requests httpx[http2] aiohttp urllib3 \
      beautifulsoup4 lxml html5lib parsel selectolax \
      pandas numpy pyarrow \
      orjson regex python-dateutil pytz \
      openpyxl feedparser markdownify pillow \
      tenacity rich

# Sanity: importable at build time.
RUN python -c "import requests, httpx, aiohttp, bs4, lxml, parsel, pandas, numpy, pyarrow, orjson, PIL, feedparser; print('python-agent libs OK')"

# Drop privileges by default (the executor also forces --user, this is belt-and-suspenders).
USER 65534:65534
