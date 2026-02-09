import streamlit as st
import pdfplumber
import sqlite3
import pandas as pd
import re
import os

# --- 1. 페이지 스타일 및 문단 디자인 ---
st.set_page_config(page_title="보안팀 릴리즈 아카이브 Pro v33.0", layout="wide")
st.markdown("""
    <style>
    .version-title { font-size: 28px; font-weight: 800; color: #0D47A1; background-color: #E3F2FD; padding: 12px 20px; border-radius: 8px; margin-top: 5px; border-left: 10px solid #1565C0; }
    .report-card { padding: 25px; border: 1px solid #CFD8DC; background-color: white; border-radius: 0px 0px 8px 8px; margin-bottom: 30px; line-height: 2.2; font-size: 15px; }
    .sub-label { font-weight: bold; color: #1565C0; margin-top: 25px; margin-bottom: 10px; display: block; font-size: 18px; border-bottom: 2px solid #E3F2FD; padding-bottom: 5px; }
    .highlight { background-color: #FFFF00; color: black; font-weight: bold; }
    /* 문단 간격을 넓게 벌려 가독성 확보 */
    .release-item { margin-bottom: 20px; display: block; padding-left: 10px; border-left: 3px solid #ECEFF1; }
    </style>
    """, unsafe_allow_html=True)

# --- 2. DB 연결 및 초기화 ---
DB_FILE = 'security_notes_archive.db'
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS notes 
                  (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                   version TEXT, openssl TEXT, openssh TEXT, 
                   improvements TEXT, issues TEXT, raw_text TEXT)''')
conn.commit()

# --- 3. [상식적 해결] 문장 단위 문단 재구성 로직 ---

def format_custom_text(text):
    """
    텍스트를 기호(•, -, *)나 대괄호 기준으로 나누어 한 문단씩 정렬
    """
    if not text: return "", ""
    
    # 주요 개선/요청 사항과 버그 수정을 키워드로 분리 시도
    split_keyword = "기타 버그 수정"
    parts = text.split(split_keyword)
    
    imp_raw = parts[0]
    iss_raw = parts[1] if len(parts) > 1 else ""

    def process_block(block):
        # 줄바꿈 정제 및 문장 단위 분리
        lines = block.split('\n')
        final_lines = []
        for l in lines:
            clean_l = l.strip()
            if not clean_l or "AhnLab 파트너지원" in clean_l or "http" in clean_l:
                continue
            # 특수 기호가 없으면 붙여줌
            if not any(clean_l.startswith(s) for s in ['•', '-', '*', '[']):
                clean_l = f"• {clean_l}"
            final_lines.append(clean_l)
        return "\n\n".join(final_lines)

    return process_block(imp_raw), process_block(iss_raw)

# --- 4. 사이드바 메뉴 ---
if 's_key' not in st.session_state: st.session_state.s_key = "v33"

with st.sidebar:
    st.header("📜 버전 히스토리")
    hist = pd.read_sql_query("SELECT version FROM notes ORDER BY version DESC", conn)
    sel_v = st.radio("상세 보기 선택", hist['version'].tolist()) if not hist.empty else None

    st.divider()
    with st.expander("➕ 요약 텍스트 직접 등록", expanded=True):
        input_v = st.text_input("버전 입력", placeholder="예: 3.1.3.11")
        input_text = st.text_area("릴리즈 내용 붙여넣기", height=300)
        if st.button("🚀 데이터 반영", use_container_width=True):
            if input_v and input_text:
                imp, iss = format_custom_text(input_text)
                cursor.execute("INSERT INTO notes (version, improvements, issues, raw_text) VALUES (?,?,?,?)",
                               (input_v, imp, iss, input_text))
                conn.commit()
                st.success(f"{input_v} 반영 완료!")
                st.rerun()

    with st.expander("🗑️ 데이터 삭제"):
        if not hist.empty:
            del_v = st.selectbox("삭제 버전", hist['version'].tolist())
            if st.button("🚨 삭제 실행"):
                cursor.execute("DELETE FROM notes WHERE version = ?", (del_v,))
                conn.commit()
                st.rerun()

# --- 5. 메인 화면 ---
st.title("🛡️ TrusGuard 통합 관제 (v33.0)")

c1, c2 = st.columns([5,1], vertical_alignment="bottom")
keyword = c1.text_input("검색어 입력", key=st.session_state.s_key)
if c2.button("🔄 초기화"):
    st.session_state.s_key = os.urandom(4).hex()
    st.rerun()

def display_item(text):
    if not text: return ""
    items = text.split('\n\n')
    return "".join([f"<div class='release-item'>{item}</div>" for item in items])

if keyword:
    kws = keyword.split()
    query = "SELECT version, improvements, issues FROM notes WHERE " + " AND ".join(["raw_text LIKE ?" for _ in kws]) + " ORDER BY version DESC"
    res = pd.read_sql_query(query, conn, params=[f'%{k}%' for k in kws])
    for _, row in res.iterrows():
        st.markdown(f"<div class='version-title'>📦 TrusGuard {row['version']}</div>", unsafe_allow_html=True)
        # 검색어 강조 로직 생략(가독성 우선)
        st.markdown(f"<div class='report-card'>{display_item(row['improvements'] + row['issues'])}</div>", unsafe_allow_html=True)

elif sel_v:
    r = pd.read_sql_query("SELECT * FROM notes WHERE version = ?", conn, params=[sel_v]).iloc[0]
    st.markdown(f"<div class='version-title'>📋 TrusGuard {r['version']} 상세 리포트</div>", unsafe_allow_html=True)
    st.markdown(f"""<div class='report-card'>
        <span class='sub-label'>🔼 주요 기능 요청 및 개선</span>
        {display_item(r['improvements'])}
        <span class='sub-label'>🐞 기타 버그 수정</span>
        {display_item(r['issues'])}
    </div>""", unsafe_allow_html=True)
