from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
import os
from dotenv import load_dotenv
from fastapi import Request
from sqlalchemy.orm import Session
from models import Base, ConversationRecord, User
from ollama import generate
from pydantic import BaseModel
import json
from json import JSONDecodeError
import pandas as pd
import shutil
from openpyxl import load_workbook
load_dotenv()

SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")  # 用于JWT加密的密钥
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# 数据库依赖项
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    from models import User
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

class Summary(BaseModel):

    視力: str
    聴力: str
    麻痺: str
    移動: str
    寝返り: str
    起き上がり: str
    座位保持: str
    移乗: str
    立ち上がり :str
    立位保持: str
    転倒リスク: str

def write_excel(template_path, base_dict, username, session_id, start_row, start_col):

    new_excel_path = f"/home/nt/Documents/my_repo/Open-LLM-VTuber/static/dialogues/inteku_{username}_{session_id}.xlsx"
    shutil.copy(template_path, new_excel_path)
    book = load_workbook(new_excel_path)

    sheet_name = "sheet1"
    sheet = book[sheet_name]
    df = pd.DataFrame(list(base_dict.values()), columns=['状態'])    

    with pd.ExcelWriter(new_excel_path, engine="openpyxl", mode="a", if_sheet_exists="overlay") as writer:
        df.to_excel(writer, sheet_name=sheet_name, startrow=start_row-1, startcol=start_col-1, index=False, header=False)

    # df_new = pd.read_excel(new_excel_path, sheet_name=sheet_name)    
def analyze_conversation(session_id: str, db: Session = Depends(get_db)):

    session = db.query(ConversationRecord).filter(ConversationRecord.session_id == session_id).first()
    if session:
        data = session.data
        if len(data) > 0:
            generation_params = {
                #"do_sample": True,
                "temperature": 0.3,
                "top_p": 0.9,
                "top_k": 40,
                "num_predict": 2048,
                "num_ctx": 2048,
                "repeat_penalty": 1.2,
            }

            system_prompt = """
            ユーザーとLLMの間の対話内容を要約するタスクです。対話には以下のプロジェクトと選択肢が含まれています。
            
            １．視力：「普通、眼鏡使用で可、ほとんどみえない」
            ２．聴力：「普通、補聴器使用で可、ほとんど聞こえない
            ３．麻痺：「なし、あり（左上肢、左下肢、右上肢、右下肢 ）」
            ４．移動：「手引き、杖、歩行器、車椅子」
            ５．寝返り：「自立、つかまれば可、全介助」
            ６．起き上がり：「自立、つかまれば可、全介助」
            ７．座位保持：「自立、背もたれ必要、全介助」
            ８．移乗：「自立、つかまれば可、見守り等、一部介助、全介助」
            ９．立ち上がり：「自立、つかまれば可、見守り等、一部介助、全介助」
            １０．立位保持：「自立、つかまれば可、全介助」
            １１．転倒リスク：「なし、あり」

            以上のプロジェクトは、対話内容に基づいてユーザーの状況に最も適した選択肢を選び、JSON形式で出力します。

            出力例：
            
            {
            "視力": "眼鏡使用で可",
            "聴力": "補聴器使用で可",
            "麻痺": "あり（左下肢、右下肢）",
            "移動": "車椅子",
            "寝返り": "自立",
            "起き上がり": "つかまれば可",
            "座位保持": "背もたれ必要",
            "移乗": "一部介助",
            "立ち上がり": "全介助",
            "立位保持": "つかまれば可",
            "転倒リスク": "なし"
            }

            注意点：

            １．不明な項目がある場合は、「不明」とみなし、過度な推測を行いません。
            ２．**出力例のJSON形式に厳密に従って出力してください。**
            """
            session.process_start_datetime = datetime.utcnow()
            print(f"session {session_id} start to process conversation")
            res = generate(
            model="llama3.3_param",
            prompt=data,
            system=system_prompt,
            options=generation_params,
            format=Summary.model_json_schema()
            )

            base_dict = {'視力': '不明',
            '聴力': '不明',
            '麻痺': '不明',
            '移動': '不明',
            '寝返り': '不明',
            '起き上がり': '不明',
            '座位保持': '不明',
            '移乗': '不明',
            '立ち上がり': '不明',
            '立位保持': '不明',
            '転倒リスク': '不明'}   

            try:
                # if the LLM correctly output JSON format response, update the base_dict
                output_dict = json.loads(res['response'])
                base_dict.update({k: v for k, v in output_dict.items() if k in base_dict})
                output_info = ''
            except JSONDecodeError as e:
                output_info = "Error: Output can not be transformed to JSON format\n"
            # transform dict to string
            output = json.dumps(base_dict, ensure_ascii=False, indent=2)
            session.data_analyzed = output_info + output if output_info else output
            session.process_end_datetime = datetime.utcnow()
            # write to excel file
            excel_template_path = "/home/nt/Documents/my_repo/Open-LLM-VTuber/static/dialogues/inteku_template.xlsx"
            current_user = db.query(User).filter(User.username == session.username).first()
            write_excel(
                template_path=excel_template_path,
                base_dict=base_dict,
                username=current_user.last_name +'-'+ current_user.first_name,
                session_id=session_id,
                start_row=16,
                start_col=5
            )

            print(f"session {session_id} finish to process conversation\nresult:\n{output}")
            db.commit()
