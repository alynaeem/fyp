@app.post("/confidential/analyze")
async def confidential_data_analyze(file: UploadFile = File(...)):
    """Analyse one local user-uploaded file and return/store masked findings only.

    Security controls:
    - allowlisted file extensions only
    - upload size limit
    - in-memory runtime processing
    - no raw PAN/CVV/password/token values returned, logged, or persisted
    - Mongo stores masked values and detection metadata only
    """
    file_name = pathlib.Path(file.filename or "").name.strip()
    if not file_name:
        raise HTTPException(status_code=400, detail="A file name is required")

    suffix = pathlib.Path(file_name).suffix.lower()
    if suffix not in CONFIDENTIAL_ALLOWED_EXTS:
        raise HTTPException(status_code=400, detail="Unsupported file type. Upload .txt, .csv, .json, or .log files only.")

    content = await file.read(CONFIDENTIAL_MAX_UPLOAD_BYTES + 1)
    await file.close()
    if len(content) > CONFIDENTIAL_MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"File is too large. Maximum allowed size is {CONFIDENTIAL_MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")

    try:
        text = content.decode("utf-8", errors="replace")
        start = time.perf_counter()
        findings = _analyse_confidential_text(file_name, text)
        analysis_id = hashlib.sha256(f"{file_name}:{time.time()}:{len(content)}".encode()).hexdigest()[:18]
        docs = [{**item, "analysis_id": analysis_id} for item in findings]
        if docs:
            await confidential_analysis_col.insert_many(docs, ordered=False)
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        type_counts: dict[str, int] = {}
        risk_counts: dict[str, int] = {}
        for item in findings:
            type_counts[item["detected_type"]] = type_counts.get(item["detected_type"], 0) + 1
            risk_counts[item["risk_level"]] = risk_counts.get(item["risk_level"], 0) + 1
        return {
            "status": "ok",
            "analysis_id": analysis_id,
            "source_file_name": file_name,
            "file_size_bytes": len(content),
            "count": len(findings),
            "truncated": len(findings) >= CONFIDENTIAL_MAX_FINDINGS,
            "elapsed_ms": elapsed_ms,
            "type_counts": type_counts,
            "risk_counts": risk_counts,
            "results": findings,
            "message": (
                f"{len(findings)} masked potential exposure finding(s) detected. Analyst verification is required."
                if findings else "No payment-card-like or credential-indicator patterns were detected."
            ),
            "disclaimer": "This tool is for authorised defensive analysis only. Sensitive values are masked and raw secrets are never displayed or stored.",
        }
    except HTTPException:
        raise
    except Exception as exc:
        log.error("Confidential data analysis failed for uploaded file %s: %s", file_name, exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Analysis failed. Raw uploaded data was not stored.") from exc
