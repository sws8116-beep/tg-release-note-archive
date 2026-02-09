import streamlit as st
import pdfplumber
import sqlite3
import pandas as pd
import re
import os

# --- 1. 페이지 스타일 설정 ---
st.set_page_config(page_title="보안팀 릴리즈 아카이브 Pro", layout="wide")

st.markdown("""
    <style>
    .version-title { 
        font-size: 28px !important; font-weight: 800 !important; color: #0D47A1 !important; 
        background-color: #E3F2FD; padding: 12px 20px; border-radius: 8px; 
        margin-top: 40px; border-left: 10px solid #1565C0;
    }
    .report-card { 
        padding: 25px; border: 1px solid #CFD8DC; background-color: white;
        border-radius: 0px 0px 8px 8px; margin-bottom: 30px; line-height: 1.8;
    }
    .highlight { background-color: #FFFF00; color: black; font-weight: bold; }
    </style>
    """, unsafe_allow_html=True)

# --- 2. DB 연결 설정 ---
DB_FILE = 'security_notes_archive.db'

def get_connection():
    return sqlite3.connect(DB_FILE, check_same_thread=False)

conn = get_connection()
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS notes 
                  (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                   version TEXT, improvements TEXT, issues TEXT, raw_text TEXT)''')
conn.commit()

# --- 3. 텍스트 정제 함수 ---
def clean_format(section_text):
    if not section_text: return ""
    text = re.sub(r'\s+', ' ', section_text).strip()
    parts = re.split(r'(\[)', text)
    formatted = []
    if parts[0].strip(): formatted.append(f"• {parts[0].strip()}")
    for i in range(1, len(parts), 2):
        bracket, content = parts[i], parts[i+1] if i+1 < len(parts) else ""
        formatted.append(f"• {bracket}{content.strip()}")
    return "\n".join(formatted)

# --- 4. 메인 화면 ---
st.title("🛡️ TrusGuard 통합 릴리즈 관제센터")

search_col1, search_col2 = st.columns([5, 1])
with search_col1:
    keyword = st.text_input("검색어 입력", placeholder="예: VPN 접속")
with search_col2:
    st.write(" ")
    if st.button("🔄 초기화", use_container_width=True):
        st.rerun()

if keyword:
    kws = keyword.split()
    query = "SELECT version, improvements, issues FROM notes WHERE "
    query += " AND ".join(["raw_text LIKE ?" for _ in kws]) + " ORDER BY version DESC"
    df = pd.read_sql_query(query, conn, params=[f'%{k}%' for k in kws])

    for _, row in df.iterrows():
        st.markdown(f"<div class='version-title'>📦 TrusGuard {row['version']}</div>", unsafe_allow_html=True)
        all_lines = (row['improvements'] + "\n" + row['issues']).split('\n')
        matched_lines = [l for l in all_lines if all(k.lower() in l.lower() for k in kws) and l.strip()]
        display_text = "\n".join(matched_lines) if matched_lines else "*(본문에 키워드 존재)*"
        for k in kws:
            display_text = re.sub(f"({re.escape(k)})", r"<mark class='highlight'>\1</mark>", display_text, flags=re.IGNORECASE)
        st.markdown(f"<div class='report-card'>{display_text.replace('\n', '<br>')}</div>", unsafe_allow_html=True)

# --- 5. 사이드바: DB 관리 도구 ---
with st.sidebar:
    st.header("⚙️ 데이터베이스 관리")
    
    # PDF 업로드 및 DB 반영
    st.subheader("1. PDF 신규 등록")
    files = st.file_uploader("PDF 멀티 업로드", accept_multiple_files=True)
    if st.button("✅ DB 반영"):
        if files:
            for f in files:
                with pdfplumber.open(f) as pdf:
                    raw = "\n".join([p.extract_text() for p in pdf.pages if p.extract_text()])
                v = re.search(r'TrusGuard\s+([\d\.]+)', raw)
                version = v.group(1) if v else "Unknown"
                imp = re.search(r'Improvement(.*?)(Issue|$|5\.)', raw, re.DOTALL)
                iss = re.search(r'Issue(.*?)(5\.|참고|$)', raw, re.DOTALL)
                cursor.execute("INSERT INTO notes (version, improvements, issues, raw_text) VALUES (?, ?, ?, ?)",
                               (version, clean_format(imp.group(1)) if imp else "", clean_format(iss.group(1)) if iss else "", raw))
                conn.commit()
            st.success("데이터가 성공적으로 반영되었습니다.")
            st.rerun()
    
    st.divider()
    
    # DB 파일 업로드/다운로드
    st.subheader("2. DB 백업 및 복구")
    
    # 다운로드: 현재 서버의 DB를 내 PC로
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "rb") as f:
            st.download_button(
                label="📥 현재 DB 다운로드 (.db)",
                data=f,
                file_name="security_notes_backup.db",
                mime="application/octet-stream",
                help="서버에 저장된 최신 데이터를 내 PC로 백업합니다."
            )

    # 업로드: 내 PC의 DB를 서버로 반영
    uploaded_db = st.file_uploader("📤 백업 DB 업로드 (.db)", type=['db'])
    if uploaded_db is not None:
        if st.button("🔥 서버 DB 교체 (주의)"):
            with open(DB_FILE, "wb") as f:
                f.write(uploaded_db.getbuffer())
            st.success("서버 DB가 업로드된 파일로 교체되었습니다!")
            st.rerun()

    st.divider()
    st.subheader("📜 전체 버전")
    history = pd.read_sql_query("SELECT version FROM notes ORDER BY version DESC", conn)
    st.dataframe(history, use_container_width=True, hide_index=True)
