@app.get("/credentials/datasets")
async def credential_checker_datasets():
    try:
        summary = await _sync_credential_datasets(force=False)
        datasets = summary.get("datasets", [])
        return {
            "status": "ok",
            "count": len(datasets),
            "datasets": datasets,
            "message": (
                f"{len(datasets)} backend dataset file(s) are saved on disk and synced to Mongo."
                if datasets
                else "No stealer-log JSON files are saved on disk yet, so Mongo has nothing to load."
            ),
        }
    except Exception as exc:
        log.error(f"Credential dataset listing failed: {exc}", exc_info=True)
        return {"status": "error", "message": f"Dataset listing failed: {str(exc)}"}


@app.post("/credentials/upload")
async def credential_checker_upload(files: list[UploadFile] = File(...)):
    if not files:
        raise HTTPException(status_code=400, detail="At least one file is required")

    try:
        from api_collector.stealer_log_scan import credential_data_dir

        base_dir = credential_data_dir()
        saved: list[str] = []
        allowed_exts = {".json", ".jsonl", ".ndjson"}
        max_upload_bytes = max(1, cfg.credential_upload_max_bytes)

        for upload in files:
            file_name = pathlib.Path(upload.filename or "").name.strip()
            if not file_name:
                continue

            suffix = pathlib.Path(file_name).suffix.lower()
            if suffix not in allowed_exts:
                raise HTTPException(status_code=400, detail=f"Unsupported file type for {file_name}")

            destination = base_dir / file_name
            content = await upload.read(max_upload_bytes + 1)
            if len(content) > max_upload_bytes:
                raise HTTPException(
                    status_code=413,
                    detail=f"{file_name} is too large. Maximum allowed size is {max_upload_bytes // (1024 * 1024)} MB.",
                )
            destination.write_bytes(content)
            saved.append(file_name)
            await upload.close()

        summary = await _sync_credential_datasets(force=True)
        datasets = summary.get("datasets", [])
        log.info(f"Credential dataset upload complete: {saved}")
        return {
            "status": "ok",
            "saved": saved,
            "datasets": datasets,
            "message": f"Saved {len(saved)} dataset file(s) to disk and synced them to Mongo.",
        }
    except HTTPException:
        raise
    except Exception as exc:
        log.error(f"Credential dataset upload failed: {exc}", exc_info=True)
        return {"status": "error", "message": f"Upload failed: {str(exc)}"}


CONFIDENTIAL_ALLOWED_EXTS = {".txt", ".csv", ".json", ".log"}
CONFIDENTIAL_MAX_UPLOAD_BYTES = 25 * 1024 * 1024
CONFIDENTIAL_MAX_FINDINGS = 1000
_CARD_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_CVV_RE = re.compile(r"\b(?:cvv|cvc|cvn|security\s*code)\s*[:=,-]?\s*(\d{3,4})\b", re.IGNORECASE)
_PASSWORD_RE = re.compile(r"\b(?:password|passwd|pwd|pass)\s*[:=]\s*([^\s,;|]{3,80})", re.IGNORECASE)
_TOKEN_RE = re.compile(r"\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|secret|bearer|token|cookie)\s*[:=]\s*([A-Za-z0-9._~+/=-]{12,220})", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d\s().-]{7,}\d)(?!\w)")
_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


def _luhn_valid(value: str) -> bool:
    digits = [int(char) for char in re.sub(r"\D", "", value or "")]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _card_brand_guess(digits: str) -> str:
    if not digits:
        return "Unknown"
    if digits.startswith("4"):
        return "Visa"
    if re.match(r"^(5[1-5]|2[2-7])", digits):
        return "Mastercard"
    if re.match(r"^3[47]", digits):
        return "American Express"
    if re.match(r"^(6011|65|64[4-9])", digits):
        return "Discover"
    if re.match(r"^35", digits):
        return "JCB"
    if re.match(r"^3(?:0[0-5]|[68])", digits):
        return "Diners Club"
    return "Unknown"


def _mask_card(value: str) -> str:
    digits = re.sub(r"\D", "", str(value or ""))
    if len(digits) <= 2:
        return "#" * len(digits)
    return f"{digits[0]}{'#' * (len(digits) - 2)}{digits[-1]}"


def _mask_password(value: str) -> str:
    text = str(value or "")
    if not text:
        return ""
    return f"{text[0]}{'#' * (len(text) - 1)}"


def _mask_token(value: str) -> str:
    text = str(value or "")
    if len(text) <= 6:
        return "#" * len(text)
    return f"{text[:3]}{'#' * (len(text) - 6)}{text[-3:]}"


def _mask_email(value: str) -> str:
    text = str(value or "").strip()
    if "@" not in text:
        return _mask_password(text)
    local, domain = text.split("@", 1)
    if not local:
        return f"*@{domain}"
    return f"{local[0]}{'*' * max(len(local) - 1, 1)}@{domain}"


def _mask_phone(value: str) -> str:
    digits = re.sub(r"\D", "", str(value or ""))
    if len(digits) <= 4:
        return "#" * len(digits)
    return f"{digits[:2]}{'#' * (len(digits) - 4)}{digits[-2:]}"


def _mask_ip(value: str) -> str:
    parts = str(value or "").strip().split(".")
    if len(parts) != 4:
        return "#.#.#.#"
    return f"{parts[0]}.{parts[1]}.#.#"


def _mask_user_agent(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "N/A"
    return re.sub(r"\d{4,}", lambda match: "#" * len(match.group(0)), text)

def _safe_field(value: str) -> str:
    text = str(value or "").strip()
    return text if text else "N/A"


def _blank_parsed_fields() -> dict[str, str]:
    return {
        "masked_card_number": "N/A",
        "expiry_date": "N/A",
        "cvv": "N/A",
        "cardholder_name": "N/A",
        "address_line_1": "N/A",
        "address_line_2": "N/A",
        "city": "N/A",
        "state_region": "N/A",
        "postal_code": "N/A",
        "country": "N/A",
        "masked_phone": "N/A",
        "masked_email": "N/A",
        "extra_field": "N/A",
        "masked_ip_address": "N/A",
        "masked_user_agent": "N/A",
    }


def _parse_pipe_payment_record(line_text: str) -> dict[str, Any] | None:
    if "|" not in line_text:
        return None
    parts = [part.strip() for part in line_text.split("|")]
    if not parts:
        return None
    card_digits = re.sub(r"\D", "", parts[0])
    if not (13 <= len(card_digits) <= 19 and _luhn_valid(card_digits)):
        return None

    def at(index: int) -> str:
        return parts[index] if index < len(parts) else ""

    parsed = _blank_parsed_fields()
    parsed.update({
        "masked_card_number": _mask_card(card_digits),
        "expiry_date": _safe_field(at(1)),
        "cvv": "[REDACTED]" if at(2) else "N/A",
        "cardholder_name": _safe_field(at(3)),
        "address_line_1": _safe_field(at(4)),
        "address_line_2": _safe_field(at(5)),
        "city": _safe_field(at(6)),
        "state_region": _safe_field(at(7)),
        "postal_code": _safe_field(at(8)),
        "country": _safe_field(at(9)),
        "masked_phone": _mask_phone(at(10)) if at(10) else "N/A",
        "masked_email": _mask_email(at(11)) if at(11) else "N/A",
        "extra_field": _safe_field(at(12)),
        "masked_ip_address": _mask_ip(at(13)) if at(13) else "N/A",
        "masked_user_agent": _mask_user_agent(at(14)) if at(14) else "N/A",
    })
    return {
        "masked_value": parsed["masked_card_number"],
        "card_brand": _card_brand_guess(card_digits),
        "parsed_fields": parsed,
    }


def _risk_for_type(detected_type: str, confidence: str) -> str:
    if detected_type in {"Payment Card", "Payment Card Exposure", "CVV"}:
        return "High" if confidence in {"High", "Medium"} else "Medium"
    if detected_type in {"Password", "API Key / Token"}:
        return "High"
    if detected_type in {"Email Address", "Phone Number", "IP Address"}:
        return "Medium"
    return "Low"


def _replace_all(text: str, replacements: list[tuple[str, str]]) -> str:
    masked = text
    for raw, safe in sorted(replacements, key=lambda pair: len(pair[0]), reverse=True):
        if raw:
            masked = masked.replace(raw, safe)
    return masked


def _analyse_confidential_text(file_name: str, text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    timestamp = datetime.now(timezone.utc).isoformat()

    def add_finding(
        *,
        detected_type: str,
        masked_value: str,
        line_number: int,
        line_text: str,
        raw_replacements: list[tuple[str, str]],
        confidence: str,
        reason: str,
        card_brand: str = "",
        parsed_fields: dict[str, str] | None = None,
        context_override: str | None = None,
    ) -> None:
        if len(findings) >= CONFIDENTIAL_MAX_FINDINGS:
            return
        context = context_override if context_override is not None else _replace_all(line_text, raw_replacements)
        context = context[:360]
        record_id = hashlib.sha256(f"{file_name}:{line_number}:{detected_type}:{masked_value}:{len(findings)}".encode()).hexdigest()[:16]
        findings.append({
            "record_id": record_id,
            "source_file_name": file_name,
            "detected_type": detected_type,
            "masked_value": masked_value,
            "card_brand_guess": card_brand or "N/A",
            "location": f"line {line_number}",
            "context_snippet": context,
            "parsed_fields": parsed_fields or _blank_parsed_fields(),
            "detection_confidence": confidence,
            "risk_level": _risk_for_type(detected_type, confidence),
            "reason_for_detection": reason,
            "timestamp_of_analysis": timestamp,
            "analyst_notes": "",
            "status": "New",
        })

    lines = text.splitlines() or [text]
    for line_number, line in enumerate(lines, 1):
        if len(findings) >= CONFIDENTIAL_MAX_FINDINGS:
            break
        line_text = line[:5000]
        replacements: list[tuple[str, str]] = []
        pipe_payment_record = _parse_pipe_payment_record(line_text)

        # Build a complete per-line masking map before creating any finding.
        # This prevents an earlier finding's context snippet from exposing a
        # later CVV/password/token that appears on the same line.
        for match in _CARD_CANDIDATE_RE.finditer(line_text):
            raw = match.group(0)
            digits = re.sub(r"\D", "", raw)
            if 13 <= len(digits) <= 19 and _luhn_valid(digits):
                replacements.append((raw, _mask_card(digits)))
        for regex, detected_type, masker, confidence, reason in (
            (_CVV_RE, "CVV", lambda value: "[REDACTED]", "Medium", "CVV/CVC keyword followed by a 3-4 digit value."),
            (_PASSWORD_RE, "Password", _mask_password, "Medium", "Password-like key/value pattern detected."),
            (_TOKEN_RE, "API Key / Token", _mask_token, "Medium", "Token, cookie, API key, bearer, or secret-like key/value pattern detected."),
        ):
            for match in regex.finditer(line_text):
                replacements.append((match.group(1), masker(match.group(1))))
        for match in _EMAIL_RE.finditer(line_text):
            replacements.append((match.group(0), _mask_email(match.group(0))))
        for match in _IP_RE.finditer(line_text):
            replacements.append((match.group(0), _mask_ip(match.group(0))))
        for match in _PHONE_RE.finditer(line_text):
            raw = match.group(0)
            digits = re.sub(r"\D", "", raw)
            if 13 <= len(digits) <= 19 and _luhn_valid(digits):
                continue
            if 8 <= len(digits) <= 15:
                replacements.append((raw, _mask_phone(raw)))

        if pipe_payment_record:
            add_finding(
                detected_type="Payment Card Exposure",
                masked_value=pipe_payment_record["masked_value"],
                line_number=line_number,
                line_text=line_text,
                raw_replacements=replacements,
                confidence="High",
                reason="Card-like value detected, passed Luhn validation, and pipe-separated exposure fields were safely parsed and masked.",
                card_brand=pipe_payment_record["card_brand"],
                parsed_fields=pipe_payment_record["parsed_fields"],
                context_override="Structured pipe-delimited record parsed. Masked field values are shown in the detail view.",
            )
            continue

        for match in _CARD_CANDIDATE_RE.finditer(line_text):
            raw = match.group(0)
            digits = re.sub(r"\D", "", raw)
            if not 13 <= len(digits) <= 19:
                continue
            luhn_ok = _luhn_valid(digits)
            if not luhn_ok:
                continue
            masked = _mask_card(digits)
            add_finding(
                detected_type="Payment Card",
                masked_value=masked,
                line_number=line_number,
                line_text=line_text,
                raw_replacements=replacements,
                confidence="High",
                reason="13-19 digit payment-card-like value matched and passed Luhn validation.",
                card_brand=_card_brand_guess(digits),
            )

        for regex, detected_type, masker, confidence, reason in (
            (_CVV_RE, "CVV", lambda value: "[REDACTED]", "Medium", "CVV/CVC keyword followed by a 3-4 digit value."),
            (_PASSWORD_RE, "Password", _mask_password, "Medium", "Password-like key/value pattern detected."),
            (_TOKEN_RE, "API Key / Token", _mask_token, "Medium", "Token, cookie, API key, bearer, or secret-like key/value pattern detected."),
        ):
            for match in regex.finditer(line_text):
                raw_value = match.group(1)
                masked = masker(raw_value)
                add_finding(
                    detected_type=detected_type,
                    masked_value=masked,
                    line_number=line_number,
                    line_text=line_text,
                    raw_replacements=replacements,
                    confidence=confidence,
                    reason=reason,
                )

        for match in _EMAIL_RE.finditer(line_text):
            raw = match.group(0)
            masked = _mask_email(raw)
            add_finding(
                detected_type="Email Address",
                masked_value=masked,
                line_number=line_number,
                line_text=line_text,
                raw_replacements=replacements,
                confidence="Medium",
                reason="Email-address pattern detected near possible exposure data.",
            )

        for match in _IP_RE.finditer(line_text):
            raw = match.group(0)
            masked = _mask_ip(raw)
            add_finding(
                detected_type="IP Address",
                masked_value=masked,
                line_number=line_number,
                line_text=line_text,
                raw_replacements=replacements,
                confidence="Medium",
                reason="IPv4 address pattern detected in uploaded local file.",
            )

        for match in _PHONE_RE.finditer(line_text):
            raw = match.group(0)
            digits = re.sub(r"\D", "", raw)
            if 13 <= len(digits) <= 19 and _luhn_valid(digits):
                continue
            if 8 <= len(digits) <= 15:
                masked = _mask_phone(raw)
                add_finding(
                    detected_type="Phone Number",
                    masked_value=masked,
                    line_number=line_number,
                    line_text=line_text,
                    raw_replacements=replacements,
                    confidence="Low",
                    reason="Phone-like numeric pattern detected; analyst verification required.",
                )

    return findings


