from fastapi import APIRouter, Depends, HTTPException, status, Response
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.responses import RedirectResponse, JSONResponse
from sqlalchemy.orm import Session
from datetime import timedelta, datetime
from typing import Optional
from pydantic import BaseModel
from models import User
from database import get_db, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
import json
from dotenv import load_dotenv
import os

load_dotenv()

SESSION_EXPIRE_MINUTES = int(os.getenv("SESSION_EXPIRE_MINUTES"))

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

class Token(BaseModel):
    access_token: str
    token_type: str

@router.post("/register", response_model=Token)
async def register(user: UserCreate, db: Session = Depends(get_db)):
    # 检查用户名是否已存在
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(
            status_code=400,
            detail="Username already registered"
        )
    
    # 检查邮箱是否已存在
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )
    
    # 创建新用户
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=User.get_password_hash(user.password)
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    # 创建访问令牌
    access_token_expires = timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES))
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/token", response_model=TokenResponse)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not User.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES))
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    now = datetime.utcnow()
    expires_at = int((now + timedelta(minutes=SESSION_EXPIRE_MINUTES)).timestamp())
    expires_in = int(access_token_expires.total_seconds())
    
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
@router.get("/logout")
async def logout(response: Response):
    response = RedirectResponse(url="/login.html", status_code=302)
    response.delete_cookie("access_token")
    return response