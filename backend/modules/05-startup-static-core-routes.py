@app.post("/healing/discover", dependencies=[Depends(admin_required)])
async def healing_discover():
    result = await _run_healing_discovery()
    return {
        "status": "ok",
        "message": f"Discovered {result.get('discovered', 0)} monitor targets.",
        **result,
    }


@app.post("/healing/run", dependencies=[Depends(admin_required)])
async def healing_run(request: Request):
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    limit = int(body.get("limit") or cfg.healing_monitor_target_limit or 12)
    result = await _run_healing_monitor(limit=limit)
    return {
        "status": "ok",
        "message": f"Healing scan finished for {result.get('target_count', 0)} targets.",
        **result,
    }


@app.post("/healing/run/{target_key}", dependencies=[Depends(admin_required)])
async def healing_run_target(target_key: str):
    result = await _run_healing_monitor(target_key=target_key, limit=1)
    return {
        "status": "ok",
        "message": f"Healing check finished for {target_key}.",
        **result,
    }

@app.get("/style.css")
def serve_css():
    return FileResponse(_STATIC_DIR / "style.css", media_type="text/css")


@app.get("/app.js")
def serve_js():
    return FileResponse(_STATIC_DIR / "app.js", media_type="application/javascript")

@app.get("/health")
async def health():
    """Public health check — pings MongoDB."""
    try:
        await client.admin.command('ping')
        mongo_ok = True
    except Exception as e:
        mongo_ok = False
        log.error(f"MongoDB health check failed: {e}")
    return {
        "status": "ok" if mongo_ok else "degraded",
        "database": "mongodb connected" if mongo_ok else "unreachable",
    }


# ── Authentication Endpoints ────────────────────────────────────────────────
@app.post("/auth/login")
async def login(request: Request):
    body = await request.json()
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    
    user = await users_col.find_one({"username": username})
    if not user or not verify_password(password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    if user.get("status") != "approved":
        raise HTTPException(status_code=403, detail="Account pending approval")

    if user.get("two_factor_enabled"):
        challenge_token = create_access_token(
            data={
                "sub": user["username"],
                "role": user.get("role", "user"),
                "token_type": "mfa_challenge",
                "purpose": "otp_login",
            },
            expires_delta=MFA_CHALLENGE_EXPIRE_MINUTES,
        )
        return {
            "mfa_required": True,
            "challenge_type": "otp",
            "challenge_token": challenge_token,
            "username": user["username"],
        }

    pending_secret = user.get("two_factor_pending_secret")
    if pending_secret:
        otpauth_url = _two_factor_uri(user["username"], pending_secret)
        challenge_token = create_access_token(
            data={
                "sub": user["username"],
                "role": user.get("role", "user"),
                "token_type": "mfa_challenge",
                "purpose": "otp_setup",
            },
            expires_delta=MFA_CHALLENGE_EXPIRE_MINUTES,
        )
        return {
            "mfa_required": True,
            "setup_required": True,
            "challenge_type": "setup",
            "challenge_token": challenge_token,
            "username": user["username"],
            "qr_code_url": _two_factor_qr_image_url(otpauth_url),
            "otpauth_url": otpauth_url,
            "manual_secret": pending_secret,
            "issuer": TWO_FACTOR_ISSUER,
        }

    access_token = create_access_token(data={"sub": user["username"], "role": user.get("role", "user")})
    return {"access_token": access_token, "token_type": "bearer", "role": user.get("role", "user")}


@app.post("/auth/login/verify-otp")
async def verify_login_otp(request: Request):
    body = await request.json()
    challenge_token = (body.get("challenge_token") or "").strip()
    otp_code = re.sub(r"\s+", "", str(body.get("otp") or ""))

    if not challenge_token:
        raise HTTPException(status_code=400, detail="Challenge token is required")
    if not re.fullmatch(rf"\d{{{TWO_FACTOR_DIGITS}}}", otp_code):
        raise HTTPException(status_code=400, detail="Enter a valid 6-digit OTP code")

    try:
        payload = jwt.decode(challenge_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("token_type") != "mfa_challenge":
            raise HTTPException(status_code=401, detail="Invalid 2FA challenge")
    except JWTError:
        raise HTTPException(status_code=401, detail="2FA session expired. Sign in again.")

    username = payload.get("sub")
    purpose = payload.get("purpose")
    if not username or purpose not in {"otp_login", "otp_setup"}:
        raise HTTPException(status_code=401, detail="Invalid 2FA challenge")

    user = await users_col.find_one({"username": username})
    if not user or user.get("status") != "approved":
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    secret = user.get("two_factor_secret") if purpose == "otp_login" else user.get("two_factor_pending_secret")
    if not secret:
        raise HTTPException(status_code=400, detail="2FA setup is not available. Sign in again.")

    verify_window = TWO_FACTOR_SETUP_WINDOW if purpose == "otp_setup" else TWO_FACTOR_LOGIN_WINDOW
    if not _verify_totp_token(secret, otp_code, window=verify_window):
        raise HTTPException(
            status_code=401,
            detail="Invalid OTP code. If it just refreshed, try the newest code and make sure your authenticator time is synced.",
        )

    if purpose == "otp_setup":
        await users_col.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "two_factor_enabled": True,
                    "two_factor_secret": secret,
                    "two_factor_enabled_at": datetime.utcnow().isoformat(),
                },
                "$unset": {
                    "two_factor_pending_secret": "",
                    "two_factor_requested_at": "",
                },
            },
        )

    access_token = create_access_token(data={"sub": user["username"], "role": user.get("role", "user")})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": user.get("role", "user"),
    }


@app.post("/auth/register")
async def register(request: Request):
    body = await request.json()
    username = body.get("username", "").strip()
    password = body.get("password", "")
    email = body.get("email", "").strip()
    name = body.get("name", "").strip()
    
    if not username or not password or not email:
        raise HTTPException(status_code=400, detail="Username, password, and email are required")
        
    if " " in username:
        raise HTTPException(status_code=400, detail="Username cannot contain spaces")
        
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long")
        
    if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
        raise HTTPException(status_code=400, detail="Invalid email format")
        
    existing = await users_col.find_one({"$or": [{"username": username}, {"email": email}]})
    if existing:
        raise HTTPException(status_code=400, detail="Username or Email already registered")
        
    hashed = get_password_hash(password)
    user_doc = {
        "username": username,
        "password": hashed,
        "email": email,
        "name": name or username,
        "status": "pending",
        "role": "user",
        "created_at": datetime.utcnow().isoformat(),
        "two_factor_enabled": False,
    }
    await users_col.insert_one(user_doc)
    return {"status": "ok", "message": "Registration successful. Please wait for admin approval."}


@app.post("/auth/password-reset-request")
async def password_reset_request(request: Request):
    body = await request.json()
    identity = (body.get("identity") or "").strip()
    message = (body.get("message") or "").strip()

    if not identity:
        raise HTTPException(status_code=400, detail="Username or email is required")

    user = await users_col.find_one(
        {
            "$or": [
                {"username": identity},
                {"email": identity},
            ]
        },
        {"password": 0},
    )

    if user:
        await password_reset_requests_col.insert_one(
            {
                "username": user.get("username"),
                "email": user.get("email"),
                "name": user.get("name") or user.get("username"),
                "identity": identity,
                "message": message,
                "status": "pending",
                "created_at": datetime.utcnow().isoformat(),
            }
        )

    return {
        "status": "ok",
        "message": "Reset request recorded. If the account exists, an administrator can now review the recovery request.",
    }


@app.get("/auth/2fa/status")
async def two_factor_status(current_user: dict = Depends(get_current_user)):
    return _two_factor_payload(current_user)


@app.post("/auth/2fa/enable")
async def enable_two_factor(current_user: dict = Depends(get_current_user)):
    if current_user.get("two_factor_enabled"):
        return {
            "status": "ok",
            "message": "2FA is already enabled for this account.",
            **_two_factor_payload(current_user),
        }

    secret = _totp_secret()
    await users_col.update_one(
        {"_id": current_user["_id"]},
        {
            "$set": {
                "two_factor_enabled": False,
                "two_factor_pending_secret": secret,
                "two_factor_requested_at": datetime.utcnow().isoformat(),
            },
            "$unset": {"two_factor_secret": ""},
        },
    )
    return {
        "status": "ok",
        "message": "2FA setup started. Sign in again to scan the QR code and verify your OTP.",
        "enabled": False,
        "setup_pending": True,
    }


@app.post("/auth/2fa/disable")
async def disable_two_factor(current_user: dict = Depends(get_current_user)):
    await users_col.update_one(
        {"_id": current_user["_id"]},
        {
            "$set": {
                "two_factor_enabled": False,
                "two_factor_disabled_at": datetime.utcnow().isoformat(),
            },
            "$unset": {
                "two_factor_secret": "",
                "two_factor_pending_secret": "",
                "two_factor_enabled_at": "",
                "two_factor_requested_at": "",
            },
        },
    )
    return {
        "status": "ok",
        "message": "2FA disabled.",
        "enabled": False,
        "setup_pending": False,
    }


# ── Admin User Management ──────────────────────────────────────────────────
@app.get("/admin/users", dependencies=[Depends(admin_required)])
async def list_users():
    cursor = users_col.find({}, {"password": 0})
    users = await cursor.to_list(length=100)
    for user in users:
        if "_id" in user:
            user["_id"] = str(user["_id"])
    return {"users": users}


@app.get("/admin/password-reset-requests", dependencies=[Depends(admin_required)])
async def list_password_reset_requests():
    cursor = password_reset_requests_col.find({}).sort("created_at", -1)
    requests = await cursor.to_list(length=200)
    for item in requests:
        if "_id" in item:
            item["_id"] = str(item["_id"])
    return {"requests": requests}


@app.post("/admin/password-reset-requests/{request_id}/resolve", dependencies=[Depends(admin_required)])
async def resolve_password_reset_request(request_id: str):
    from bson import ObjectId

    try:
        object_id = ObjectId(request_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid request id") from exc

    result = await password_reset_requests_col.update_one(
        {"_id": object_id},
        {
            "$set": {
                "status": "reviewed",
                "reviewed_at": datetime.utcnow().isoformat(),
            }
        },
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Recovery request not found")
    return {"status": "ok", "message": "Recovery request marked as reviewed"}


@app.post("/admin/users/{username}/approve", dependencies=[Depends(admin_required)])
async def approve_user(username: str):
    result = await users_col.update_one({"username": username}, {"$set": {"status": "approved"}})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"status": "ok", "message": f"User {username} approved"}


@app.post("/admin/users/{username}/reject")
async def reject_user(username: str, current_user: dict = Depends(admin_required)):
    current_username = str(current_user.get("username") or "").strip().lower()
    if username.strip().lower() == current_username:
        raise HTTPException(status_code=400, detail="You cannot reject or delete your own admin account.")
    result = await users_col.delete_one({"username": username})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"status": "ok", "message": f"User {username} rejected/deleted"}


@app.post("/admin/users", dependencies=[Depends(admin_required)])
async def admin_create_user(request: Request):
    body = await request.json()
    username = body.get("username", "").strip()
    password = body.get("password", "")
    email = body.get("email", "").strip()
    name = body.get("name", "").strip()
    role = body.get("role", "user")
    
    if not username or not password or not email:
        raise HTTPException(status_code=400, detail="Username, password, and email are required")
        
    if " " in username:
        raise HTTPException(status_code=400, detail="Username cannot contain spaces")
        
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long")
        
    if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
        raise HTTPException(status_code=400, detail="Invalid email format")
        
    existing = await users_col.find_one({"$or": [{"username": username}, {"email": email}]})
    if existing:
        raise HTTPException(status_code=400, detail="Username or Email already exists")
        
    hashed = get_password_hash(password)
    user_doc = {
        "username": username,
        "password": hashed,
        "email": email,
        "name": name or username,
        "status": "approved",
        "role": role,
        "created_at": datetime.utcnow().isoformat(),
        "two_factor_enabled": False,
    }
    await users_col.insert_one(user_doc)
    return {"status": "ok", "message": "User created successfully"}

