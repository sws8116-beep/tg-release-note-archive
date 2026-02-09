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
        margin-top: 5px; border-left: 10px solid #1565C0;
    }
    .report-card { 
        padding: 25px; border: 1px solid #CFD8DC; background-color: white;
        border-radius: 0px 0px 8px 8px; margin-bottom: 30px; line-height: 1.8;
    }
    .sub-label { font-weight: bold; color: #455A64; margin-top: 10px; display: block; }
    .highlight { background-color: #FFFF00; color: black; font-weight: bold; }
    </style>
    """, unsafe_allow_html=True)

# --- 2. DB 연결 ---
DB_FILE = 'security_notes_archive.db'
def get_connection():
    return sqlite3.connect(DB_FILE, check_same_thread=False)

conn = get_connection()
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS notes 
                  (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                   version TEXT, openssl TEXT, openssh TEXT, 
                   improvements TEXT, issues TEXT, raw_text TEXT)''')
conn.commit()

# --- 3. [강화된 파싱 로직] ---
def clean_format(section_text):
    if not section_text: return ""
    # 불필요한 따옴표, 중복 줄바꿈 제거
    text = section_text.replace('"', '').replace("'", "")
    text = re.sub(r'\s+', ' ', text).strip()
    
    # 대괄호([]) 또는 특정 기호(•, -) 기준으로 문단 나누기
    parts = re.split(r'(\[|•|- )', text)
    
    formatted_lines = []
    current_line = ""
    
    for part in parts:
        if part in ['[', '•', '- ']:
            if current_line.strip():
                formatted_lines.append(f"* {current_line.strip()}")
            current_line = part
        else:
            current_line += part
            
    if current_line.strip():
        formatted_lines.append(f"* {current_line.strip()}")
        
    return "\n".join(formatted_lines)

def extract_release_info(text):
    """다양한 형식의 릴리즈 노트에서 핵심 정보 추출"""
    # 1. 버전 추출 (TrusGuard 뒤에 오는 숫자 조합들)
    v_match = re.search(r'TrusGuard\s+v?([\d\.]+)', text, re.IGNORECASE)
    version = v_match.group(1) if v_match else "Unknown"

    # 2. 보안 컴포넌트 (OpenSSL, OpenSSH)
    openssl = re.search(r'OpenSSL\s+([\d\.]+[\w]*)', text, re.IGNORECASE)
    openssh = re.search(r'OpenSSH\s+([\d\.]+p\d+)', text, re.IGNORECASE)

    # 3. 주요 내용 섹션 (표 형식이나 리스트 형식을 모두 포괄하도록 패턴 확장)
    # 개선사항(Improvement) 섹션 탐색
    imp_patterns = [r'주요\s*개선\s*사항(.*?)(이슈|제약|참고|$)', r'Improvement(.*?)(Issue|$|5\.)']
    improvements = ""
    for p in imp_patterns:
        match = re.search(p, text, re.DOTALL | re.IGNORECASE)
        if match:
            improvements = match.group(1)
            break

    # 이슈(Issue) 섹션 탐색
    iss_patterns = [r'주요\s*이슈\s*해결(.*?)(연관|참고|$)', r'Issue(.*?)(5\.|참고|$)', r'주요\s*수정\s*내용(.*?)연관']
    issues = ""
    for p in iss_patterns:
        match = re.search(p, text, re.DOTALL | re.IGNORECASE)
        if match:
            issues = match.group(1)
            break

    return {
        "version": version,
        "openssl": openssl.group(1) if openssl else "-",
        "openssh": openssh.group(1) if openssh else "-",
        "improvements": clean_format(improvements),
        "issues": clean_format(issues),
        "raw_text": text
    }

# --- 4. 사이드바 (데이터 관리) ---
with st.sidebar:
    st.header("📜 버전 히스토리")
    history_df = pd.read_sql_query("SELECT version FROM notes ORDER BY version DESC", conn)
    
    selected_version = st.radio("상세 보기 선택:", history_df['version'].tolist()) if not history_df.empty else None

    st.markdown("<br><br>", unsafe_allow_html=True)
    st.divider()
    
    with st.expander("➕ PDF 신규 등록", expanded=False):
        files = st.file_uploader("파일 선택", accept_multiple_files=True, label_visibility="collapsed")
        if st.button("✅ DB 반영", use_container_width=True):
            if files:
                for f in files:
                    with pdfplumber.open(f) as pdf:
                        full_text = ""
                        for page in pdf.pages:
                            # 표(Table) 데이터도 텍스트로 변환하여 포함
                            table_text = page.extract_text() or ""
                            full_text += table_text + "\n"
                    
                    info = extract_release_info(full_text)
                    
                    # 중복 체크
                    cursor.execute("SELECT version FROM notes WHERE version = ?", (info['version'],))
                    if cursor.fetchone():
                        st.warning(f"⚠️ {info['version']} 이미 존재")
                        continue

                    cursor.execute("""INSERT INTO notes (version, openssl, openssh, improvements, issues, raw_text) 
                                      VALUES (?, ?, ?, ?, ?, ?)""",
                                   (info['version'], info['openssl'], info['openssh'], 
                                    info['improvements'], info['issues'], info['raw_text']))
                    conn.commit()
                st.success("반영 완료!")
                st.rerun()

    with st.expander("🗑️ 데이터 삭제"):
        if not history_df.empty:
            del_v = st.selectbox("삭제 버전", history_df['version'].tolist())
            if st.button("🚨 삭제 실행"):
                cursor.execute("DELETE FROM notes WHERE version = ?", (del_v,))
                conn.commit()
                st.rerun()

# --- 5. 메인 화면 ---
st.title("🛡️ TrusGuard 통합 릴리즈 관제센터")

# 검색 및 초기화
if 'search_key' not in st.session_state: st.session_state.search_key = "v19"
col1, col2 = st.columns([5, 1], vertical_alignment="bottom")
with col1:
    keyword = st.text_input("검색어", key=st.session_state.search_key)
with col2:
    if st.button("🔄 초기화"):
        st.session_state.search_key = os.urandom(5).hex()
        st.rerun()

def highlight_text(text, kws):
    if not kws: return text.replace("\n", "<br>")
    for k in kws:
        text = re.sub(f"({re.escape(k)})", r"<mark class='highlight'>\1</mark>", text, flags=re.IGNORECASE)
    return text.replace("\n", "<br>")

# 결과 출력
if keyword:
    kws = keyword.split()
    query = "SELECT version, improvements, issues FROM notes WHERE "
    query += " AND ".join(["raw_text LIKE ?" for _ in kws]) + " ORDER BY version DESC"
    search_df = pd.read_sql_query(query, conn, params=[f'%{k}%' for k in kws])

    for _, row in search_df.iterrows():
        st.markdown(f"<div class='version-title'>📦 TrusGuard {row['version']}</div>", unsafe_allow_html=True)
        all_lines = (row['improvements'] + "\n" + row['issues']).split('\n')
        matched_lines = [l for l in all_lines if all(k.lower() in l.lower() for k in kws) and l.strip()]
        st.markdown(f"<div class='report-card'>{highlight_text('\n'.join(matched_lines) if matched_lines else '*(본문 존재)*', kws)}</div>", unsafe_allow_html=True)

elif selected_version:
    res = pd.read_sql_query("SELECT * FROM notes WHERE version = ?", conn, params=[selected_version]).iloc[0]
    st.markdown(f"<div class='version-title'>📋 TrusGuard {res['version']} 리포트</div>", unsafe_allow_html=True)
    st.markdown(f"""<div class='report-card'>
        <span class='sub-label'>🔒 보안 컴포넌트</span> OpenSSL: {res['openssl']} / OpenSSH: {res['openssh']}<br><br>
        <span class='sub-label'>🔼 개선 사항</span> {res['improvements'].replace('\n', '<br>')}<br><br>
        <span class='sub-label'>🔥 이슈 해결</span> {res['issues'].replace('\n', '<br>')}
    </div>""", unsafe_allow_html=True)
