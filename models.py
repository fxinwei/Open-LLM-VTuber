from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, Date
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from passlib.context import CryptContext
import uuid
import boto3
from botocore.exceptions import ClientError
import os
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

load_dotenv()

Base = declarative_base()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def send_email(recipient_email, subject, body, attachment_path=None):

    smtp_server = 'sv1113.xserver.jp'
    port = 587
    sender_email = 'info@rinsouken.jp'
    sender_password = 'gyfdez-bysrin-hoMca9'  
    
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    if attachment_path and os.path.exists(attachment_path):
        with open(attachment_path, 'rb') as attachment_file:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment_file.read())
            encoders.encode_base64(part)  
            part.add_header(
                'Content-Disposition',
                f'attachment; filename={os.path.basename(attachment_path)}', 
            )
            msg.attach(part)
    try:
        with smtplib.SMTP(smtp_server, port) as server:
            server.starttls() 
            server.login(sender_email, sender_password)
            server.send_message(msg)
            print("send mail successfully")
    except Exception as e:
        print(f"email return code: {e}")

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    first_name = Column(String)
    last_name = Column(String)
    date_of_birth = Column(Date)
    country = Column(String)
    address = Column(String)
    gender = Column(String)
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
    login_datetime = Column(DateTime(timezone=True), server_default=func.now())
    last_active = Column(DateTime(timezone=True), server_default=func.now())
    logout_datetime = Column(DateTime(timezone=True))
    expire_datetime = Column(DateTime(timezone=True))

# the user who is registed but not verified yet
class RegisteredUser(Base):
    __tablename__ = "registered_users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    first_name = Column(String)
    last_name = Column(String)
    date_of_birth = Column(Date)
    country = Column(String)
    address = Column(String)
    gender = Column(String)
    verification_token = Column(String)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    @staticmethod
    def send_verification_email(recipient_email: str, verification_link: str) -> bool:
        # AWS SES setting
        if os.getenv("MAIL_SERVER") == "AWS":
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
        else:
            subject = "Verify your email"
            body = f"""\
            Please your email address by clicking the link below:

            {verification_link}
            
            You receive this email because you are trying to rigister an account for AI-Assistant application.
            If you did not request this email, please ignore it.
            """
            send_email(recipient_email, subject, body)
            return True

class ResetPasswordUser(Base):
    __tablename__ = "reset_password_users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    reset_token = Column(String)
    reset_finished = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    @staticmethod
    def send_reset_email(username: str, recipient_email: str, reset_link: str) -> bool:
        # AWS SES setting
        if os.getenv("MAIL_SERVER") == "AWS":
            ses_client = boto3.client(
                'ses',
                aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
                aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
                region_name=os.getenv("AWS_SES_REGION")
            )

            SENDER = os.getenv("AWS_SES_SENDER")
            SUBJECT = "Password Reset for LLM-VTuber"
            BODY_TEXT = f"Please click the link below to reset your password:\n{reset_link}"
            BODY_HTML = f"""
            <html>
            <head></head>
            <body>
                <p>Your username is: {username}</p>
                <p>Please click the link below to reset your password:</p>
                <p><a href="{reset_link}">Reset Password</a></p>
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
        else:
            # Send email using SMTP
            subject = f"Password Reset"
            body = f"""
            Your username is: {username}
            Please click the link below to reset your password:
            
            {reset_link}

            You receive this email because you are trying to reset your password for your AI-Assistant application.
            If you did not request this email, please ignore it.
            """
            send_email(recipient_email, subject, body)

            return True
