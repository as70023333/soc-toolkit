"""Thin clients for Microsoft Graph, the Defender for Endpoint API and Log Analytics."""

from __future__ import annotations

import urllib.parse
from typing import Any, Mapping

from soc_toolkit.common.auth import GRAPH_SCOPE, LOG_ANALYTICS_SCOPE, MDE_SCOPE, TokenCredential
from soc_toolkit.common.http import HttpClient, HttpError, Response


class AzureApi:
    """Bearer-token JSON API with OData paging (``@odata.nextLink``)."""

    def __init__(self, http: HttpClient, credential: TokenCredential, base: str, scope: str) -> None:
        self.http = http
        self.credential = credential
        self.base = base.rstrip("/")
        self.scope = scope
        self._host = urllib.parse.urlsplit(self.base).netloc.lower()

    def url(self, path: str) -> str:
        if path.startswith("https://"):
            return path
        return f"{self.base}/{path.lstrip('/')}"

    def _headers(self, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {self.credential.get_token(self.scope)}"}
        if extra:
            headers.update(extra)
        return headers

    def _check_host(self, url: str) -> None:
        # Never send the bearer token to a host other than the API it was issued for,
        # even if a paging link points somewhere else.
        host = urllib.parse.urlsplit(url).netloc.lower()
        if host != self._host:
            raise HttpError(0, f"refusing to follow a link to another host ({host})")

    def get(self, path: str, params: Mapping[str, Any] | None = None, *,
            headers: Mapping[str, str] | None = None, allow: tuple[int, ...] = ()) -> Response:
        url = self.url(path)
        self._check_host(url)
        return self.http.request("GET", url, params=params, headers=self._headers(headers), ok=(200,), allow=allow)

    def get_json(self, path: str, params: Mapping[str, Any] | None = None) -> Any:
        return self.get(path, params).json()

    def get_all(self, path: str, params: Mapping[str, Any] | None = None, *,
                headers: Mapping[str, str] | None = None, max_items: int | None = None) -> list[dict]:
        items: list[dict] = []
        url: str | None = self.url(path)
        query: Mapping[str, Any] | None = params
        while url:
            self._check_host(url)
            data = self.http.request("GET", url, params=query, headers=self._headers(headers), ok=(200,)).json() or {}
            items.extend(data.get("value", []))
            if max_items is not None and len(items) >= max_items:
                return items[:max_items]
            url = data.get("@odata.nextLink")
            query = None  # the next link already carries the query
        return items

    def post_json(self, path: str, body: Any, *, headers: Mapping[str, str] | None = None) -> Any:
        url = self.url(path)
        self._check_host(url)
        return self.http.request("POST", url, json_body=body, headers=self._headers(headers), ok=(200, 201)).json()


class GraphApi(AzureApi):
    def __init__(self, http: HttpClient, credential: TokenCredential,
                 base: str = "https://graph.microsoft.com") -> None:
        super().__init__(http, credential, base, GRAPH_SCOPE)


class DefenderApi(AzureApi):
    """Defender for Endpoint API. The token scope is the same for api.security.microsoft.com."""

    def __init__(self, http: HttpClient, credential: TokenCredential,
                 base: str = "https://api.securitycenter.microsoft.com") -> None:
        super().__init__(http, credential, base, MDE_SCOPE)

    def run_hunting(self, query: str) -> list[dict]:
        data = self.post_json("/api/advancedqueries/run", {"Query": query}) or {}
        return list(data.get("Results", []))


class LogAnalyticsApi(AzureApi):
    def __init__(self, http: HttpClient, credential: TokenCredential,
                 base: str = "https://api.loganalytics.io") -> None:
        super().__init__(http, credential, base, LOG_ANALYTICS_SCOPE)

    def query(self, workspace_id: str, kql: str) -> list[dict]:
        data = self.post_json(f"/v1/workspaces/{workspace_id}/query", {"query": kql}) or {}
        tables = data.get("tables") or []
        if not tables:
            return []
        columns = [c["name"] for c in tables[0].get("columns", [])]
        return [dict(zip(columns, row)) for row in tables[0].get("rows", [])]
