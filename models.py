from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from passlib.context import CryptContext
import uuid
import boto3
from botocore.exceptions import ClientError
import os
from dotenv import load_dotenv

load_dotenv()

Base = declarative_base()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    is_verified = Column(Boolean, default=False)

    
    @staticmethod
    def verify_password(plain_password, hashed_password):
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def get_password_hash(password):
        return pwd_context.hash(password)
    
class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

class ActiveSession(Base):
    __tablename__ = "active_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    login_time = Column(DateTime(timezone=True), server_default=func.now())

# the user who is registed but not verified yet
class RegisteredUser(Base):
    __tablename__ = "registered_users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    verification_token = Column(String)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    @staticmethod
    def send_verification_email(recipient_email: str, verification_link: str) -> bool:
        # AWS SES setting
        ses_client = boto3.client(
            'ses',
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            region_name=os.getenv("AWS_SES_REGION")
        )

        SENDER = os.getenv("AWS_SES_SENDER")  # Verified sender email in SES
        SUBJECT = "Verify your email"
        BODY_TEXT = f"""\
        Please verify your email address by clicking the link below:
        {verification_link}
        If you did not request this email, please ignore it.
        """
        BODY_HTML = f"""\
        <html>
        <head></head>
        <body>
            <p>Please verify your email address by clicking the link below:</p>
            <p><a href="{verification_link}">Verify Email</a></p>
            <p>If you did not request this email, please ignore it.</p>
        </body>
        </html>
        """
        CHARSET = "UTF-8"
        
        try:
            response = ses_client.send_email(
                Source=SENDER,
                Destination={
                    'ToAddresses': [
                        recipient_email,
                    ],
                },
                Message={
                    'Subject': {
                        'Data': SUBJECT,
                        'Charset': CHARSET
                    },
                    'Body': {
                        'Text': {
                            'Data': BODY_TEXT,
                            'Charset': CHARSET
                        },
                        'Html': {
                            'Data': BODY_HTML,
                            'Charset': CHARSET
                        }
                    }
                }
            )
        except ClientError as e:
            # Log error with logger.error(e)
            return False
        return True
