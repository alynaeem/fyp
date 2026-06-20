@app.get("/seo/analyze")
async def analyze_seo(url: str):
    """
    Analyzes a website URL using Google PageSpeed Insights (SEO category).
    Returns structured audit data and a calculated grade.
    """
    try:
        import time
        import asyncio
        
        # Ensure URL has protocol
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        _, requested_host = _validate_seo_target(url)
            
        log.info(f"SEO analysis requested for: {url}")
        
        loop = asyncio.get_running_loop()
        data = await loop.run_in_executor(None, _local_seo_audit, url)
        scan_source = data.get("provider", "dual_mode_local")
        scan_message = "Analysis complete."
        
        if "error" in data:
            error_message = str(data.get("error") or "")
            response_preview = str(data.get("response") or "")
            quota_hit = (
                "429" in error_message
                or "quota" in response_preview.lower()
                or "rate limit" in response_preview.lower()
                or "daily limit" in response_preview.lower()
            )
            if quota_hit:
                log.warning(f"SEO upstream quota unavailable for {url}; using local dual-mode audit.")
                data = await loop.run_in_executor(None, _local_seo_audit, url)
                scan_source = data.get("provider", "dual_mode_local")
                scan_message = "Upstream SEO provider was unavailable, so DarkPulse used the local dual-mode audit."
            else:
                log.error(f"SEO analysis failed for {url}: {data['error']}")
                return {"status": "error", "message": data["error"]}
        
        audits = data.get("audits", {})
        final_report_host = urlparse(str(data.get("url") or url)).hostname
        if final_report_host and not _same_requested_host(requested_host, final_report_host):
            raise SEOScanError(
                (
                    f"'{requested_host}' redirects to a different domain "
                    f"'{final_report_host}'. No SEO report was generated for the requested host."
                ),
                kind="cross_domain_redirect",
                details={"requested_host": requested_host, "final_host": final_report_host, "final_url": data.get("url")},
            )
        score = data.get("seoScore", 0)
        seo_health_grade = data.get("seoHealthGrade") or calculate_seo_grade(score)
        scan_confidence_grade = data.get("scanConfidenceGrade") or _scan_confidence_grade((data.get("crawlerVisibility") or {}).get("level", "medium"))
        if data.get("confidence") == "limited_html":
            scan_message = "Analysis complete with limited crawler-visible HTML. Grade is approximate for JavaScript-heavy, access-gated, or bot-protected pages."
        ai_suggestions = ""
        ai_status = "fallback"
        ai_message = ""
        failing_audits = []
        for audit in audits.values():
            score_value = audit.get("score")
            if not isinstance(score_value, (int, float)) or score_value >= 0.85:
                continue
            failing_audits.append({
                "title": audit.get("title") or "SEO audit",
                "score": score_value,
                "evidence": audit.get("evidence") or audit.get("description") or "",
                "recommendation": audit.get("recommendation") or "",
            })

        openrouter_key = os.getenv("OPENROUTER_API_KEY", "").strip()
        use_openrouter_seo = os.getenv("USE_OPENROUTER_SEO", "").lower() in {"1", "true", "yes"}
        if use_openrouter_seo and openrouter_key and failing_audits:
            try:
                audits_text = "\n".join(
                    f"- {item['title']} (score {item['score']}): {item['evidence']} Suggested action: {item['recommendation'] or 'prioritize a direct fix.'}"
                    for item in failing_audits[:8]
                )
                technical = data.get("technical") or {}
                prompt = f"""
                You are a senior SEO expert and web performance consultant.
                Website: {data.get("url") or url}
                Scan source: {scan_source}
                Confidence: {data.get("confidence", "normal")}
                Technical context: {json.dumps(technical, ensure_ascii=False)}
                Only use the following observed audit evidence. Do not invent issues that are not listed.
                Findings:
                {audits_text}
                
                Provide 3-4 professional, actionable, concise bullet points.
                Prioritize the lowest-score/highest-impact findings and mention specific observed evidence when useful.
                If crawler visibility is limited, say the grade is approximate and recommend verification with Search Console or PageSpeed.
                Do not use markdown formatting like bold or headers; just return a plain text list of bullet points starting with '-'.
                """

                ai_raw = await loop.run_in_executor(None, lambda: _openrouter_recommendations(prompt, temperature=0.3))
                ai_suggestions = _normalize_ai_bullets(ai_raw)
                if not ai_suggestions:
                    ai_suggestions = _build_seo_fallback_suggestions(url, audits)
                    ai_status = "fallback_format"
                    ai_message = "DARKPULSE AI generated recommendations from the audit findings."
                else:
                    ai_status = "openrouter"
                    ai_message = "Recommendations generated by DARKPULSE AI."
            except Exception as ai_err:
                log.warning(f"AI Suggestions failed: {ai_err}")
                ai_suggestions = _build_seo_fallback_suggestions(url, audits)
                error_text = str(ai_err)
                if "RESOURCE_EXHAUSTED" in error_text or "429" in error_text:
                    ai_status = "fallback_quota"
                    ai_message = "DARKPULSE AI generated recommendations from the audit findings."
                else:
                    ai_status = "fallback_error"
                    ai_message = "DARKPULSE AI generated recommendations from the audit findings."
        elif failing_audits:
            ai_suggestions = _build_seo_fallback_suggestions(url, audits)
            ai_status = "local_evidence"
            ai_message = "DARKPULSE AI generated recommendations from the audit findings."
        else:
            ai_suggestions = "- Core SEO checks passed for this scan.\n- Keep monitoring titles, crawlability, and metadata after future content changes."
            ai_status = "no_findings"
            ai_message = "No major failing SEO audits were detected in this run."

        return {
            "status": "ok",
            "url": data.get("url"),
            "score": score,
            "grade": seo_health_grade,
            "seoHealthScore": data.get("seoHealthScore", score),
            "seoHealthGrade": seo_health_grade,
            "scanConfidenceGrade": scan_confidence_grade,
            "scanModeUsed": data.get("scanModeUsed", "raw_html"),
            "rawScanAvailable": data.get("rawScanAvailable", False),
            "renderedScanAvailable": data.get("renderedScanAvailable", False),
            "crawlerVisibility": data.get("crawlerVisibility", {}),
            "rawScan": data.get("rawScan"),
            "renderedScan": data.get("renderedScan"),
            "renderedScanError": data.get("renderedScanError"),
            "audits": audits,
            "ai_suggestions": ai_suggestions.strip(),
            "ai_status": ai_status,
            "ai_message": ai_message,
            "scan_source": scan_source,
            "scan_message": scan_message,
            "confidence": data.get("confidence", "normal"),
            "technical": data.get("technical", {}),
            "timestamp": time.strftime("%B %d, %Y")
        }
    except SEOScanError as e:
        log.warning("SEO scan rejected: %s", e)
        return {
            "status": "error",
            "message": str(e),
            "error_type": e.kind,
            "details": e.details,
        }
    except Exception as e:
        log.error(f"SEO analysis exception: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/playstore/scan")
async def playstore_scan(req: PlaystoreRequest):
    """
    Search Playstore URL for cracked/modded third-party APK references.
    """
    try:
        import time

        log.info(f"Playstore scan requested for: {req.url}")

        scan = await _collect_apk_reference_results(req.url)
        results = scan["results"]

        return {
            "status": "ok",
            "query": req.url,
            "playstore_url": scan["playstore_url"],
            "package_id": scan["package_id"],
            "app_name": scan["app_name"],
            "queries": scan["queries"],
            "sources": scan["sources"],
            "search_errors": scan["search_errors"],
            "count": len(results),
            "results": results,
            "message": f"Searched {scan['package_id']} ({scan['app_name']}) across web and intelligence sources.",
            "timestamp": time.strftime("%B %d, %Y")
        }

    except Exception as e:
        log.error(f"Playstore scan failed: {e}")
        return {"status": "error", "message": f"Scan failed: {str(e)}"}


def _parse_github_repo_url(repo_url: str) -> tuple[str, str, str] | None:
    text = str(repo_url or "").strip()
    if not text:
        return None

    if re.fullmatch(r"[\w.-]+/[\w.-]+", text):
        owner, repo = text.split("/", 1)
        repo = repo.removesuffix(".git")
        return owner, repo, f"https://github.com/{owner}/{repo}"

    parsed = urlparse(text if "://" in text else f"https://{text}")
    host = parsed.netloc.lower().replace("www.", "")
    if host != "github.com":
        return None

    parts = [unquote(part) for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1].removesuffix(".git")
    if not owner or not repo:
        return None
    return owner, repo, f"https://github.com/{owner}/{repo}"


def _github_api_headers(token: str) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "DarkPulse-Repository-Scanner",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _github_api_get(path: str, token: str, *, timeout: int = 20) -> tuple[int, dict[str, Any], dict[str, str]]:
    import requests

    response = requests.get(
        f"https://api.github.com{path}",
        headers=_github_api_headers(token),
        timeout=timeout,
    )
    try:
        payload = response.json()
    except ValueError:
        payload = {"message": response.text.strip()}
    return response.status_code, payload, dict(response.headers)


def _github_error_message(status_code: int, payload: dict[str, Any], headers: dict[str, str]) -> str:
    message = str(payload.get("message") or "").lower()
    remaining = headers.get("x-ratelimit-remaining")
    if status_code == 401 or "bad credentials" in message:
        return "GitHub token is invalid or expired. Please update GITHUB_TOKEN in .env and restart the server."
    if status_code == 403 and remaining == "0":
        return "GitHub API rate limit reached. Try again later or use a valid token."
    if status_code == 403:
        return "GitHub token does not have permission to access this repository or API endpoint."
    if status_code == 404:
        return "Repository is private or not accessible with the current token."
    return f"GitHub API request failed with status {status_code}: {payload.get('message') or 'Unknown error'}"


async def _inspect_github_repository(owner: str, repo: str, token: str) -> dict[str, Any]:
    loop = asyncio.get_running_loop()
    repo_path = f"/repos/{owner}/{repo}"
    status_code, repo_payload, headers = await loop.run_in_executor(
        None,
        lambda: _github_api_get(repo_path, token),
    )
    log.info("GitHub API repo status for %s/%s: %s", owner, repo, status_code)
    effective_token = token
    authenticated = bool(token)
    if status_code == 404 and token:
        public_status, public_payload, public_headers = await loop.run_in_executor(
            None,
            lambda: _github_api_get(repo_path, ""),
        )
        log.info("GitHub public API repo status for %s/%s: %s", owner, repo, public_status)
        if public_status == 200:
            status_code, repo_payload, headers = public_status, public_payload, public_headers
            effective_token = ""
            authenticated = False
    if status_code != 200:
        raise ValueError(_github_error_message(status_code, repo_payload, headers))

    default_branch = str(repo_payload.get("default_branch") or "HEAD")
    contents_to_check = [
        "package.json",
        "package-lock.json",
        "requirements.txt",
        "Dockerfile",
        "docker-compose.yml",
        ".env.example",
        ".github/workflows",
    ]
    discovered_files: list[str] = []
    inaccessible_paths: list[str] = []

    async def check_content_path(path: str) -> tuple[str, int, Any]:
        api_path = f"/repos/{owner}/{repo}/contents/{quote(path)}?ref={quote(default_branch)}"
        status, payload, _headers = await loop.run_in_executor(
            None,
            lambda api_path=api_path: _github_api_get(api_path, effective_token, timeout=12),
        )
        log.info("GitHub API content status for %s/%s %s: %s", owner, repo, path, status)
        return path, status, payload

    for path, status, payload in await asyncio.gather(*(check_content_path(path) for path in contents_to_check)):
        if status == 200:
            if isinstance(payload, list):
                discovered_files.extend(item.get("path", path) for item in payload if isinstance(item, dict))
            else:
                discovered_files.append(str(payload.get("path") or path))
        elif status not in (404,):
            inaccessible_paths.append(f"{path}: {status}")

    return {
        "owner": owner,
        "repo": repo,
        "full_name": repo_payload.get("full_name") or f"{owner}/{repo}",
        "html_url": repo_payload.get("html_url") or f"https://github.com/{owner}/{repo}",
        "default_branch": default_branch,
        "private": bool(repo_payload.get("private")),
        "archived": bool(repo_payload.get("archived")),
        "pushed_at": repo_payload.get("pushed_at"),
        "language": repo_payload.get("language"),
        "open_issues_count": repo_payload.get("open_issues_count", 0),
        "authenticated": authenticated,
        "discovered_files": sorted(set(discovered_files))[:20],
        "inaccessible_paths": inaccessible_paths[:10],
    }


async def _build_repo_ai_recommendations(
    repo_name: str,
    summary_data: dict[str, Any],
    vulnerabilities: list[dict[str, Any]],
    secrets: list[dict[str, Any]],
    misconfigs: list[dict[str, Any]],
) -> tuple[list[str], str, str]:
    fallback = list(summary_data.get("recommendations") or [])[:5]
    if not os.getenv("OPENROUTER_API_KEY", "").strip():
        return fallback, "fallback_no_key", "DARKPULSE AI used local repository recommendations."

    def compact_findings(items: list[dict[str, Any]], label: str) -> str:
        lines = []
        for item in items[:5]:
            lines.append(
                f"{label}: {item.get('severity', 'UNKNOWN')} {item.get('id', '')} - {item.get('title', '')}"
            )
        return "\n".join(lines)

    counts = summary_data.get("counts", {}) or {}
    coverage = summary_data.get("coverage", {}) or {}
    prompt = f"""
    You are a senior application security engineer reviewing a GitHub repository scan.
    Repository: {repo_name}
    Grade: {summary_data.get("grade", "N/A")}
    Risk score: {summary_data.get("risk_score", 0)}
    Posture: {summary_data.get("posture_label", "Scan")}
    Finding counts: {json.dumps(counts, ensure_ascii=False)}
    Coverage: supported targets={coverage.get("supported_target_count", 0)}, manifests={coverage.get("manifest_count", 0)}, configs={coverage.get("config_count", 0)}

    Top findings:
    {compact_findings(secrets, "Secret")}
    {compact_findings(vulnerabilities, "Vulnerability")}
    {compact_findings(misconfigs, "Misconfiguration")}

    Provide exactly 4-5 professional, prioritized recommendations for improving this repository's security grade.
    Start each recommendation with '-'. Keep each bullet under 28 words. Do not use markdown headings.
    """

    try:
        loop = asyncio.get_running_loop()
        ai_raw = await loop.run_in_executor(None, lambda: _openrouter_recommendations(prompt, temperature=0.2))
        bullet_text = _normalize_ai_bullets(ai_raw)
        recommendations = [
            line.removeprefix("- ").strip()
            for line in bullet_text.splitlines()
            if line.strip()
        ][:5]
        if recommendations:
            return recommendations, "openrouter", "Repository recommendations generated by DARKPULSE AI."
        return fallback, "fallback_format", "DARKPULSE AI used local repository recommendations."
    except Exception as exc:
        log.warning("Repository AI recommendations failed for %s: %s", repo_name, exc)
        return fallback, "fallback_error", "DARKPULSE AI used local repository recommendations."


