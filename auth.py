from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.responses import RedirectResponse, JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_
from datetime import timedelta, datetime
from typing import Optional
from pydantic import BaseModel
from models import User, LoginAttempt, ActiveSession, RegisteredUser, ResetPasswordUser
from database import get_db, create_access_token, oauth2_scheme, ACCESS_TOKEN_EXPIRE_MINUTES
import json
from dotenv import load_dotenv
import os
import uuid
from jose import JWTError, jwt
import requests

load_dotenv()

SESSION_EXPIRE_MINUTES = int(os.getenv("SESSION_EXPIRE_MINUTES", "15"))
MAX_LOGIN_PER_DAY = int(os.getenv("MAX_LOGIN_PER_DAY", "5"))
VIP_USERS = os.getenv("VIP_USERS", "").split(",")
MAX_ACTIVE_USERS = int(os.getenv("MAX_ACTIVE_USERS", "4"))

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expire_in: int
    expire_at: int

router = APIRouter()

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    recaptcha_token: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str

def verify_recaptcha_v2(token: str) -> bool:
    recaptcha_secret = os.getenv("RECAPTCHA_SECRET")
    url = "https://www.google.com/recaptcha/api/siteverify"
    data = {"secret": recaptcha_secret, "response": token}
    response = requests.post(url, data=data)
    result = response.json()
    return result.get("success", False)
@router.post("/register", response_model=Token)
async def register(user: UserCreate, db: Session = Depends(get_db)):
    
    recaptcha_token = user.dict().pop("recaptcha_token", None)
    if not recaptcha_token or not verify_recaptcha_v2(recaptcha_token):
        raise HTTPException(
            status_code=400,
            detail="reCAPTCHA verification failed. Are you a robot?"
        )
    
    # check if user name is already in use
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(
            status_code=400,
            detail="Username already registered"
        )
    
    # check if the email is already in use
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    # check if the user is already registered
    db_user = db.query(RegisteredUser).filter(RegisteredUser.username == user.username).first()
    # if the user is already registered, use the same verification token to verify the email
    verification_token = uuid.uuid4().hex
    if db_user:
        db_user.verification_token = verification_token
        db_user.email = user.email
        db_user.hashed_password = User.get_password_hash(user.password)
        db_user.created_at = datetime.utcnow()
        db.commit()
    else:
        # otherwise, create a new rigistered user
        db_user = RegisteredUser(
            username=user.username,
            email=user.email,
            hashed_password=User.get_password_hash(user.password),
            verification_token=verification_token,
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)

    verification_link = f"{os.getenv('APP_BASE_URL', 'http://localhost:12393')}/auth/verify?token={verification_token}&user={db_user.username}"
    if not RegisteredUser.send_verification_email(db_user.email, verification_link):
        raise HTTPException(
            status_code=500,
            detail="Failed to send verification email. Please try again later."
        )
    
    # 创建访问令牌
    access_token_expires = timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES))
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/token", response_model=TokenResponse)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
    request: Request = None
):
    form = await request.form()
    recaptcha_token = form.get("g-recaptcha-response")
    if not recaptcha_token or not verify_recaptcha_v2(recaptcha_token):
        raise HTTPException(
            status_code=400,
            detail="reCAPTCHA verification failed. Please try again."
        )
    # support both username and email to login
    user = db.query(User).filter(or_(User.username == form_data.username, User.email == form_data.username)).first()
    registered_user = db.query(RegisteredUser).filter(or_(RegisteredUser.username == form_data.username, RegisteredUser.email == form_data.username)).first()

    # if the user is registered but not verified the email, raise an exception
    if registered_user and not registered_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email not verified. Please verify your email first.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user or not User.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # calculate how many users are currently logged in
    active_count = db.query(ActiveSession).filter(
        ActiveSession.user_id > 0
    ).count()
    if active_count >= MAX_ACTIVE_USERS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Maximum number of active users reached. Please try later."
        )

    max_logins = MAX_LOGIN_PER_DAY
    since_time = datetime.utcnow() - timedelta(days=1)
    login_count = db.query(LoginAttempt).filter(
        LoginAttempt.user_id == user.id,
        LoginAttempt.timestamp >= since_time
    ).count()
    
    if login_count >= max_logins and user.username not in VIP_USERS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many login attempts. You can only login {max_logins} times in 24 hours."
        )
    
    login_attempt = LoginAttempt(user_id=user.id)
    db.add(login_attempt)
    db.commit()
    db.refresh(login_attempt)

    # if successfully logged in
    session_id = uuid.uuid4().hex
    token_payload = {"sub": user.username, "session_id": session_id}
    access_token_expires = timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES))
    access_token = create_access_token(
        data=token_payload, expires_delta=access_token_expires
    )
    now = datetime.utcnow()
    if user.username in VIP_USERS: # vip user's session can be alive for 1 day
        expires_at = int((now + timedelta(days=1)).timestamp())
    else:
        expires_at = int((now + timedelta(minutes=SESSION_EXPIRE_MINUTES)).timestamp())
    expires_in = int(access_token_expires.total_seconds())
    
    active_session = ActiveSession(
        user_id=user.id,
        session_id=session_id,
        login_time=now
    )
    db.add(active_session)
    db.commit()
    token_data = {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": expires_in,
        "expires_at": expires_at
    }
    # 设置cookie
    response = Response(
        content=json.dumps(token_data),
        media_type="application/json"
    )
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        max_age=expires_in,
        expires=expires_in,
    )
    
    return response
@router.api_route("/logout", methods=["GET", "POST"])
async def logout(response: Response, request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")  # Extract token from cookies
    session_id = None

    if token:
        try:
            payload = jwt.decode(token.split(' ')[1] if ' ' in token else token, os.getenv("SECRET_KEY"), algorithms=["HS256"])
            session_id: str = payload.get("session_id")
        except JWTError:
            pass

    if session_id:
        active_session = db.query(ActiveSession).filter(ActiveSession.session_id == session_id).first()
        if active_session:
            db.delete(active_session)
            db.commit()

    response.delete_cookie("access_token")
    response = RedirectResponse(url="/login.html", status_code=302)
    return response

@router.get("/verify")
async def verify_email(token: str, user: str, db: Session = Depends(get_db)):
    # Here, you should retrieve the user by id
    db_user = db.query(RegisteredUser).filter(RegisteredUser.username == user).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    if db_user.verification_token != token:
        raise HTTPException(status_code=400, detail="Invalid verification token")
    if db_user.is_verified:
        raise HTTPException(status_code=400, detail="Email already verified. Please login.")
    db_user.is_verified = True
    db_user.created_at = datetime.utcnow()
    db.commit()
    # after successful verification, create a new User object and save it to the database
    real_user = User(
        username=db_user.username,
        email=db_user.email,
        hashed_password=db_user.hashed_password,
        is_verified=True,
        created_at=datetime.utcnow()
    )
    
      # Make sure your User model includes this field.
    db.add(real_user)
    db.commit()
    db.refresh(real_user)
    # Optionally, redirect to a login page or a success message.
    return RedirectResponse(url="/verification-success.html")
@router.post("/forgot-password")
async def forgot_password(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    email = data.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    
    # Find the user by email. Assuming password resets apply to verified users.
    user = db.query(User).filter(User.email == email).first()
    # For security, do not reveal if the email exists or not.
    if not user:
        return JSONResponse(content={"message": "No user found with that email."})
    
    reset_user = db.query(ResetPasswordUser).filter(ResetPasswordUser.email == email).first()
    reset_token = uuid.uuid4().hex
    if reset_user:
        # if the user exists, which means he trys to reset password again, update the token and reset_finished
        reset_user.reset_token = reset_token
        reset_user.reset_finished = False
        reset_user.created_at = datetime.utcnow()
        db.commit()
    else:
        reset_user = ResetPasswordUser(
            username=user.username,
            email=user.email,
            reset_token=reset_token,
            reset_finished=False,
            created_at=datetime.utcnow()
        )
        db.add(reset_user)
        db.commit()
        db.refresh(reset_user)    
    # Build the reset URL. Adjust APP_BASE_URL as needed.
    reset_link = f"{os.getenv('APP_BASE_URL', 'http://localhost:12393')}/auth/reset-password?token={reset_token}&user={user.username}"
    
    if not ResetPasswordUser.send_reset_email(reset_user.username, reset_user.email, reset_link):
        raise HTTPException(status_code=500, detail="Failed to send reset email. Please try again later.")
    
    return JSONResponse(content={"message": "Check your inbox and follow the link to reset your password."})

@router.get("/reset-password")
async def reset_password_get(token: str, user: str, db: Session = Depends(get_db)):
    reset_user = db.query(ResetPasswordUser).filter(ResetPasswordUser.username == user).first()
    if not reset_user:
        raise HTTPException(status_code=404, detail="User not found")
    # Check the token and expiration
    if reset_user.reset_token != token:
        raise HTTPException(status_code=400, detail="Invalid reset token")
    if reset_user.reset_finished:
        raise HTTPException(status_code=400, detail="Password reset already completed. Please login.")
    # Redirect to a static HTML page with a form for entering a new password.
    # Make sure you create this page under your static folder (e.g., static/reset-password.html)
    return RedirectResponse(url=f"/reset-password.html?token={token}&user={user}")

@router.post("/reset-password")
async def reset_password_post(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    token = data.get("token")
    username = data.get("user")
    new_password = data.get("new_password")
    if not (token and username and new_password):
        raise HTTPException(status_code=400, detail="Missing fields")
    
    reset_user = db.query(ResetPasswordUser).filter(ResetPasswordUser.username == username).first()
    user = db.query(User).filter(User.username == username).first()
    if not reset_user:
        raise HTTPException(status_code=404, detail="User not found")
    if reset_user.reset_token != token:
        raise HTTPException(status_code=400, detail="Invalid reset token")
    
    # Update the user's password and clear the reset token
    user.hashed_password = User.get_password_hash(new_password)
    reset_user.reset_finished = True
    db.commit()
    return JSONResponse(content={"message": "Success"})