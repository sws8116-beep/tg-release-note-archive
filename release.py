import streamlit as st
import pdfplumber
import sqlite3
import pandas as pd
import re
import os

# --- 1. 페이지 스타일 (디자인 강화) ---
st.set_page_config(page_title="보안팀 릴리즈 아카이브 Pro", layout="wide")

st.markdown("""
    <style>
    .version-title { 
        font-size: 28px !important; font-weight: 800 !important; color: #0D47A1 !important; 
        background-color: #E3F2FD; padding: 12px 20px; border-radius: 8px; 
        margin-top: 40px; border-left: 10px solid #1565C0; box-shadow: 2px 2px 5px rgba(0,0,0,0.1);
    }
    .report-card { 
        padding: 25px; border: 1px solid #CFD8DC; background-color: white;
        border-radius: 0px 0px 8px 8px; margin-bottom: 30px; line-height: 1.8; font-size: 16px;
    }
    .highlight { background-color: #FFFF00; color: black; font-weight: bold; padding: 0 2px; }
    </style>
    """, unsafe_allow_html=True)


# --- 2. 로컬 DB 연결 (영구 저장) ---
def get_connection():
    # 파일 이름을 고정하여 프로그램 재시작 시에도 데이터가 유지되게 함
    return sqlite3.connect('security_notes_archive.db', check_same_thread=False)


conn = get_connection()
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS notes
                  (
                      id
                      INTEGER
                      PRIMARY
                      KEY
                      AUTOINCREMENT,
                      version
                      TEXT,
                      openssl
                      TEXT,
                      openssh
                      TEXT,
                      improvements
                      TEXT,
                      issues
                      TEXT,
                      raw_text
                      TEXT
                  )''')
conn.commit()


# --- 3. [핵심] 대괄호 기준 문단 정제 함수 ---
def clean_format(section_text):
    if not section_text: return ""
    text = re.sub(r'\s+', ' ', section_text).strip()
    parts = re.split(r'(\[)', text)
    formatted = []
    if parts[0].strip(): formatted.append(f"• {parts[0].strip()}")
    for i in range(1, len(parts), 2):
        bracket, content = parts[i], parts[i + 1] if i + 1 < len(parts) else ""
        formatted.append(f"• {bracket}{content.strip()}")
    return "\n".join(formatted)


# --- 4. 메인 화면 구성 ---
st.title("🛡️ TrusGuard 통합 릴리즈 관제센터")
st.write(f"📢 **팀원 접속 주소:** `http://{os.popen('hostname').read().strip()}:8501` (또는 내 IP 주소)")

search_col1, search_col2 = st.columns([5, 1])
with search_col1:
    keyword = st.text_input("검색어 입력 (공백으로 여러 단어 검색 가능)", placeholder="예: VPN 접속 불가")
with search_col2:
    st.write(" ")
    if st.button("🔄 검색 초기화", use_container_width=True):
        st.rerun()

# --- 5. 통합 검색 및 출력 (v15.0 핵심 로직) ---
if keyword:
    kws = keyword.split()
    query = "SELECT version, improvements, issues FROM notes WHERE "
    query += " AND ".join(["raw_text LIKE ?" for _ in kws]) + " ORDER BY version DESC"
    df = pd.read_sql_query(query, conn, params=[f'%{k}%' for k in kws])

    if not df.empty:
        st.subheader(f"🔎 '{' + '.join(kws)}' 통합 검색 결과 ({len(df)}건)")
        for _, row in df.iterrows():
            # 1. 버전 제목 (크고 파란색)
            st.markdown(f"<div class='version-title'>📦 TrusGuard {row['version']}</div>", unsafe_allow_html=True)

            # 2. 문장 필터링 및 리포트 구성
            all_lines = (row['improvements'] + "\n" + row['issues']).split('\n')
            matched_lines = [l for l in all_lines if all(k.lower() in l.lower() for k in kws) and l.strip()]

            display_text = "\n".join(matched_lines) if matched_lines else "*(상세 항목 외 본문에 키워드 존재함)*"
            for k in kws:
                display_text = re.sub(f"({re.escape(k)})", r"<mark class='highlight'>\1</mark>", display_text,
                                      flags=re.IGNORECASE)

            st.markdown(f"<div class='report-card'>{display_text.replace('\n', '<br>')}</div>", unsafe_allow_html=True)
    else:
        st.error(f"🔍 '{keyword}' 검색 결과가 없습니다.")

# --- 6. 사이드바 (등록 및 전체 목록) ---
with st.sidebar:
    st.header("⚙️ 관리 도구")
    files = st.file_uploader("PDF 멀티 등록", accept_multiple_files=True)
    if st.button("DB 영구 저장"):
        if files:
            for f in files:
                with pdfplumber.open(f) as pdf:
                    raw = "\n".join([p.extract_text() for p in pdf.pages if p.extract_text()])
                v = re.search(r'TrusGuard\s+([\d\.]+)', raw)
                version = v.group(1) if v else "Unknown"
                imp = re.search(r'Improvement(.*?)(Issue|$|5\.)', raw, re.DOTALL)
                iss = re.search(r'Issue(.*?)(5\.|참고|$)', raw, re.DOTALL)

                cursor.execute("INSERT INTO notes (version, improvements, issues, raw_text) VALUES (?, ?, ?, ?)",
                               (version, clean_format(imp.group(1)) if imp else "",
                                clean_format(iss.group(1)) if iss else "", raw))
                conn.commit()
            st.success("데이터 저장 완료!")
            st.rerun()

    st.divider()
    st.subheader("📜 전체 히스토리")
    history = pd.read_sql_query("SELECT version FROM notes ORDER BY version DESC", conn)
    st.table(history)