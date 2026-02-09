import streamlit as st
import pdfplumber
import sqlite3
import pandas as pd
import re
import os

# --- 1. 페이지 스타일 및 레이아웃 ---
st.set_page_config(page_title="보안팀 릴리즈 아카이브 Pro", layout="wide")

st.markdown("""
    <style>
    .version-title { 
        font-size: 28px !important; font-weight: 800 !important; color: #0D47A1 !important; 
        background-color: #E3F2FD; padding: 12px 20px; border-radius: 8px; 
        margin-top: 5px; border-left: 10px solid #1565C0;
    }
    .report-card { 
        padding: 25px; border: 1px solid #CFD8DC; background-color: white;
        border-radius: 0px 0px 8px 8px; margin-bottom: 30px; line-height: 1.8;
    }
    .sub-label { font-weight: bold; color: #455A64; margin-top: 10px; display: block; }
    .highlight { background-color: #FFFF00; color: black; font-weight: bold; }
    .small-font { font-size: 12px !important; color: #757575; }
    </style>
    """, unsafe_allow_html=True)

# --- 2. DB 연결 및 테이블 설정 ---
DB_FILE = 'security_notes_archive.db'

def get_connection():
    return sqlite3.connect(DB_FILE, check_same_thread=False)

conn = get_connection()
cursor = conn.cursor()
# 버전(version) 컬럼에 UNIQUE 제약 조건을 걸거나 로직에서 체크합니다.
cursor.execute('''CREATE TABLE IF NOT EXISTS notes 
                  (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                   version TEXT, openssl TEXT, openssh TEXT, 
                   improvements TEXT, issues TEXT, raw_text TEXT)''')
conn.commit()

# --- 3. 정제 함수 및 유틸리티 ---
def clean_format(section_text):
    if not section_text: return ""
    text = re.sub(r'\s+', ' ', section_text).strip()
    parts = re.split(r'(\[)', text)
    formatted_lines = []
    if parts[0].strip(): formatted_lines.append(f"* {parts[0].strip()}")
    for i in range(1, len(parts), 2):
        bracket = parts[i]
        content = parts[i+1] if i+1 < len(parts) else ""
        formatted_lines.append(f"* {bracket}{content.strip()}")
    return "\n".join(formatted_lines)

def reset_search():
    st.session_state.search_input = ""
    st.session_state.search_key = str(os.urandom(5))

if 'search_key' not in st.session_state:
    st.session_state.search_key = "v18"

# --- 4. 사이드바 구성 ---
with st.sidebar:
    st.header("📜 버전 히스토리")
    history_df = pd.read_sql_query("SELECT version FROM notes ORDER BY version DESC", conn)
    
    selected_version = None
    if not history_df.empty:
        selected_version = st.radio("상세 내용을 볼 버전을 선택하세요:", history_df['version'].tolist(), key="sidebar_radio")
    else:
        st.write("등록된 데이터가 없습니다.")

    st.markdown("<br><br>", unsafe_allow_html=True)
    st.divider()
    
    # [기능 1] 중복 방지 PDF 등록
    with st.expander("➕ PDF 신규 등록", expanded=False):
        files = st.file_uploader("파일 선택", accept_multiple_files=True, label_visibility="collapsed")
        if st.button("✅ DB 반영", use_container_width=True):
            if files:
                for f in files:
                    with pdfplumber.open(f) as pdf:
                        raw = "\n".join([p.extract_text() for p in pdf.pages if p.extract_text()])
                    v_match = re.search(r'TrusGuard\s+([\d\.]+)', raw)
                    version = v_match.group(1) if v_match else "Unknown"
                    
                    # 중복 체크 로직 추가
                    cursor.execute("SELECT version FROM notes WHERE version = ?", (version,))
                    if cursor.fetchone():
                        st.warning(f"⚠️ {version} 버전은 이미 존재합니다. 건너뜁니다.")
                        continue

                    openssl = re.search(r'OpenSSL\s+([\d\.]+[\w]*)', raw)
                    openssh = re.search(r'OpenSSH\s+([\d\.]+p\d+)', raw)
                    imp = re.search(r'Improvement(.*?)(Issue|$|5\.)', raw, re.DOTALL)
                    iss = re.search(r'Issue(.*?)(5\.|참고|$)', raw, re.DOTALL)
                    
                    cursor.execute("INSERT INTO notes (version, openssl, openssh, improvements, issues, raw_text) VALUES (?, ?, ?, ?, ?, ?)",
                                   (version, openssl.group(1) if openssl else "-", openssh.group(1) if openssh else "-",
                                    clean_format(imp.group(1)) if imp else "", clean_format(iss.group(1)) if iss else "", raw))
                    conn.commit()
                st.success("반영 완료!")
                st.rerun()

    # [기능 2] 잘못된 데이터 삭제
    with st.expander("🗑️ 데이터 삭제", expanded=False):
        if not history_df.empty:
            del_version = st.selectbox("삭제할 버전 선택", history_df['version'].tolist())
            if st.button("🚨 선택한 버전 삭제", use_container_width=True):
                cursor.execute("DELETE FROM notes WHERE version = ?", (del_version,))
                conn.commit()
                st.error(f"✅ {del_version} 버전이 삭제되었습니다.")
                st.rerun()

    # [기능 3] 시스템 관리
    with st.expander("💾 시스템 관리", expanded=False):
        if os.path.exists(DB_FILE):
            with open(DB_FILE, "rb") as f:
                st.download_button("📥 DB 다운로드", f, file_name="backup.db", mime="application/octet-stream")
        
        uploaded_db = st.file_uploader("📤 DB 업로드", type=['db'], label_visibility="collapsed")
        if uploaded_db and st.button("🔥 서버 DB 교체"):
            with open(DB_FILE, "wb") as f:
                f.write(uploaded_db.getbuffer())
            st.success("교체 완료!")
            st.rerun()

# --- 5. 메인 화면 ---
st.title("🛡️ TrusGuard 통합 릴리즈 관제센터")

col1, col2 = st.columns([5, 1], vertical_alignment="bottom")
with col1:
    keyword = st.text_input("검색어 입력", placeholder="예: VPN 접속", key=st.session_state.search_key)
with col2:
    st.button("🔄 초기화", use_container_width=True, on_click=reset_search)

def highlight_text(text, kws):
    if not kws: return text.replace("\n", "<br>")
    for k in kws:
        text = re.sub(f"({re.escape(k)})", r"<mark class='highlight'>\1</mark>", text, flags=re.IGNORECASE)
    return text.replace("\n", "<br>")

if keyword:
    kws = keyword.split()
    query = "SELECT version, improvements, issues FROM notes WHERE "
    query += " AND ".join(["raw_text LIKE ?" for _ in kws]) + " ORDER BY version DESC"
    search_df = pd.read_sql_query(query, conn, params=[f'%{k}%' for k in kws])

    if not search_df.empty:
        st.subheader(f"🔎 '{keyword}' 통합 검색 결과 ({len(search_df)}건)")
        for _, row in search_df.iterrows():
            st.markdown(f"<div class='version-title'>📦 TrusGuard {row['version']}</div>", unsafe_allow_html=True)
            all_lines = (row['improvements'] + "\n" + row['issues']).split('\n')
            matched_lines = [l for l in all_lines if all(k.lower() in l.lower() for k in kws) and l.strip()]
            display_text = "\n".join(matched_lines) if matched_lines else "*(본문에 키워드 존재)*"
            st.markdown(f"<div class='report-card'>{highlight_text(display_text, kws)}</div>", unsafe_allow_html=True)
    else:
        st.error("검색 결과가 없습니다.")
elif selected_version:
    res = pd.read_sql_query("SELECT * FROM notes WHERE version = ?", conn, params=[selected_version]).iloc[0]
    st.markdown(f"<div class='version-title'>📋 TrusGuard {res['version']} 전체 리포트</div>", unsafe_allow_html=True)
    full_content = f"""
    <div class='report-card'>
        <span class='sub-label'>🔒 보안 컴포넌트</span>
        OpenSSL: {res['openssl']} / OpenSSH: {res['openssh']}<br><br>
        <span class='sub-label'>🔼 주요 개선 사항</span>
        {res['improvements'].replace('\n', '<br>')}<br><br>
        <span class='sub-label'>🔥 이슈 해결 내역</span>
        {res['issues'].replace('\n', '<br>')}
    </div>
    """
    st.markdown(full_content, unsafe_allow_html=True)
