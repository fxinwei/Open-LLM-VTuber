from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.responses import RedirectResponse, JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_
from datetime import timedelta, datetime, date
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
    first_name: str
    last_name: str
    date_of_birth: str
    country: str
    address: str
    gender: str
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
            detail="reCAPTCHA認証に失敗しました。あなたはロボットですか？"
        )
    
    # check if user name is already in use
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(
            status_code=400,
            detail="このユーザー名は既に登録されています。"
        )
    
    # check if the email is already in use
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(
            status_code=400,
            detail="このメールアドレスは既に登録されています。"
        )

    # check if the user is already registered
    db_user = db.query(RegisteredUser).filter(RegisteredUser.email == user.email).first()
    # if the user is already registered, use the same verification token to verify the email
    verification_token = uuid.uuid4().hex
    if db_user:
        db_user.verification_token = verification_token
        db_user.username = user.username
        db_user.email = user.email
        db_user.hashed_password = User.get_password_hash(user.password)
        db_user.first_name = user.first_name
        db_user.last_name = user.last_name
        db_user.date_of_birth = datetime.strptime(user.date_of_birth, '%Y-%m-%d').date()  # Expecting a date string, may need conversion
        db_user.country = user.country
        db_user.address = user.address
        db_user.gender = user.gender
        db_user.created_at = datetime.utcnow()
        db_user.is_verified = False
        db.commit()
    else:
        # otherwise, create a new rigistered user
        db_user = RegisteredUser(
            username=user.username,
            email=user.email,
            hashed_password=User.get_password_hash(user.password),
            first_name=user.first_name,
            last_name=user.last_name,
            date_of_birth=datetime.strptime(user.date_of_birth, '%Y-%m-%d').date(),  # conversion may be needed
            country=user.country,
            address=user.address,
            gender=user.gender,
            verification_token=verification_token,
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)

    verification_link = f"{os.getenv('APP_BASE_URL', 'http://localhost:12393')}/auth/verify?token={verification_token}&user={db_user.username}"
    if not RegisteredUser.send_verification_email(db_user.email, verification_link):
        raise HTTPException(
            status_code=500,
            detail="確認メールの送信に失敗しました。後でもう一度お試しください。"
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
            detail="reCAPTCHA認証に失敗しました。もう一度お試しください。"
        )
    # support both username and email to login
    user = db.query(User).filter(or_(User.username == form_data.username, User.email == form_data.username)).first()
    registered_user = db.query(RegisteredUser).filter(or_(RegisteredUser.username == form_data.username, RegisteredUser.email == form_data.username)).first()

    # if the user is registered but not verified the email, raise an exception
    if registered_user and not registered_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="メールが未認証です。先にメールを認証してください。",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user or not User.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ユーザー名またはパスワードが間違っています。",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # when user try to login, remove inactive sessions in the database first
    db.query(ActiveSession).filter(
        datetime.utcnow() > ActiveSession.expire_datetime
    ).delete()
    db.commit()
    # calculate how many users are currently logged in
    active_count = db.query(ActiveSession).filter(
        ActiveSession.user_id > 0
    ).count()
    if active_count >= MAX_ACTIVE_USERS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="アクティブユーザーの上限に達しました。後でもう一度お試しください。"
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
            detail=f"ログイン試行回数が多すぎます。24時間以内に最大 {max_logins} 回までログインできます。"
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
    if user.username in VIP_USERS or user.vip_level > 0: # vip user's session can be alive for 1 day
        expires_at = int((now + timedelta(days=1)).timestamp())
    else:
        expires_at = int((now + timedelta(minutes=SESSION_EXPIRE_MINUTES)).timestamp())
    expires_in = int(access_token_expires.total_seconds())
    
    active_session = ActiveSession(
        user_id=user.id,
        session_id=session_id,
        login_datetime=now,
        expire_datetime=(now + timedelta(days=1)) if user.username in VIP_USERS else now + timedelta(minutes=SESSION_EXPIRE_MINUTES),
    )
    db.add(active_session)
    db.commit()
    token_data = {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": expires_in,
        "expires_at": expires_at + 30
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
        secure=True,
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
            active_session.logout_datetime = datetime.utcnow()
            db.delete(active_session)
            db.commit()

    response = RedirectResponse(url="/login.html", status_code=302)
    response.delete_cookie("access_token")
    return response

@router.get("/verify")
async def verify_email(token: str, user: str, db: Session = Depends(get_db)):
    # Here, you should retrieve the user by id
    db_user = db.query(RegisteredUser).filter(RegisteredUser.username == user).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="ユーザーが見つかりません")
    if db_user.verification_token != token:
        raise HTTPException(status_code=400, detail="無効な確認トークンです")
    if db_user.is_verified:
        raise HTTPException(status_code=400, detail="メールは既に認証されています。ログインしてください。")
    db_user.is_verified = True
    db_user.created_at = datetime.utcnow()
    db.commit()
    # after successful verification, create a new User object and save it to the database
    real_user = User(
        username=db_user.username,
        email=db_user.email,
        hashed_password=db_user.hashed_password,
        first_name=db_user.first_name,
        last_name=db_user.last_name,
        date_of_birth=db_user.date_of_birth,
        country=db_user.country,
        address=db_user.address,
        gender=db_user.gender,
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
        raise HTTPException(status_code=400, detail="メールアドレスは必須です")
    
    # Find the user by email. Assuming password resets apply to verified users.
    user = db.query(User).filter(User.email == email).first()
    # For security, do not reveal if the email exists or not.
    if not user:
        return JSONResponse(content={"message": "そのメールアドレスのユーザーは見つかりませんでした。"})
    
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
        raise HTTPException(status_code=500, detail="パスワードリセット用のメールの送信に失敗しました。後でもう一度お試しください。")
    
    return JSONResponse(content={"message": "受信箱を確認し、リンクをクリックしてパスワードをリセットしてください。"})

@router.get("/reset-password")
async def reset_password_get(token: str, user: str, db: Session = Depends(get_db)):
    reset_user = db.query(ResetPasswordUser).filter(ResetPasswordUser.username == user).first()
    if not reset_user:
        raise HTTPException(status_code=404, detail="ユーザーが見つかりませんでした。")
    # Check the token and expiration
    if reset_user.reset_token != token:
        raise HTTPException(status_code=400, detail="無効なリセットトークンです。")
    if reset_user.reset_finished:
        raise HTTPException(status_code=400, detail="パスワードのリセットは既に完了しています。ログインしてください。")
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
        raise HTTPException(status_code=400, detail="未入力の項目があります。")
    
    reset_user = db.query(ResetPasswordUser).filter(ResetPasswordUser.username == username).first()
    user = db.query(User).filter(User.username == username).first()
    if not reset_user:
        raise HTTPException(status_code=404, detail="ユーザーが見つかりませんでした。")
    if reset_user.reset_token != token:
        raise HTTPException(status_code=400, detail="無効なリセットトークンです。")
    
    # Update the user's password and clear the reset token
    user.hashed_password = User.get_password_hash(new_password)
    reset_user.reset_finished = True
    db.commit()
    return JSONResponse(content={"message": "Success"})

@router.post("/checksession")
async def check_session(request: Request, response: Response, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    session_id = None

    if token:
        try:
            payload = jwt.decode(token.split(' ')[1] if ' ' in token else token, os.getenv("SECRET_KEY"), algorithms=["HS256"])
            session_id: str = payload.get("session_id")
        except JWTError:
            pass

    if session_id:
        active_session = db.query(ActiveSession).filter(ActiveSession.session_id == session_id).first()
        print(f"current session_id: {session_id}\nactive_session: {active_session}")
        if active_session:
            # if the session is expired, delete it and raise an exception
            if datetime.utcnow().timestamp() > active_session.expire_datetime.timestamp():
                db.delete(active_session)
                db.commit()
                # raise HTTPException(status_code=401, detail="Session Expired")
                
                return JSONResponse(content={"message": "session-timeout"})
            else:
                active_session.last_active = datetime.utcnow()
                db.commit()
            return JSONResponse(content={"message": "Session checked"})
    # if the session id is not found in database, raise an exception
    if not token or not active_session:
        return JSONResponse(content={"message": "session-not-found"})