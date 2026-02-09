import streamlit as st
import pdfplumber
import sqlite3
import pandas as pd
import re
import os

# --- 1. 페이지 스타일 ---
st.set_page_config(page_title="보안팀 릴리즈 아카이브 Pro", layout="wide")
st.markdown("""
    <style>
    .version-title { font-size: 28px !important; font-weight: 800; color: #0D47A1; background-color: #E3F2FD; padding: 12px 20px; border-radius: 8px; margin-top: 5px; border-left: 10px solid #1565C0; }
    .report-card { padding: 25px; border: 1px solid #CFD8DC; background-color: white; border-radius: 0px 0px 8px 8px; margin-bottom: 30px; line-height: 1.8; }
    .sub-label { font-weight: bold; color: #455A64; margin-top: 10px; display: block; }
    .highlight { background-color: #FFFF00; color: black; font-weight: bold; }
    </style>
    """, unsafe_allow_html=True)

# --- 2. DB 연결 ---
DB_FILE = 'security_notes_archive.db'
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT, openssl TEXT, openssh TEXT, improvements TEXT, issues TEXT, raw_text TEXT)''')
conn.commit()

# --- 3. [개선된 파싱 함수] ---
def clean_report_text(raw_text):
    if not raw_text: return ""
    # 불필요한 따옴표 및 줄바꿈 정제
    clean = raw_text.replace('"', '').replace("'", "").strip()
    clean = re.sub(r'\n+', ' ', clean) # 줄바꿈을 일단 공백으로 통합
    
    # 주요 구분 기호를 기준으로 문단 나누기
    # [항목], •, -, 번호(1., 2.) 등 대응
    parts = re.split(r'(\[|•|- |\d+\.)', clean)
    
    lines = []
    current = ""
    for p in parts:
        if p in ['[', '•', '- '] or re.match(r'\d+\.', p):
            if current.strip(): lines.append(f"* {current.strip()}")
            current = p
        else:
            current += p
    if current.strip(): lines.append(f"* {current.strip()}")
    return "\n".join(lines)

def parse_enhanced_pdf(file):
    with pdfplumber.open(file) as pdf:
        full_text = ""
        for page in pdf.pages:
            # 1. 표(Table) 추출 시도
            tables = page.extract_tables()
            if tables:
                for table in tables:
                    for row in table:
                        # None 값 제거 및 텍스트 합치기
                        row_text = " ".join([cell for cell in row if cell])
                        full_text += row_text + "\n"
            # 2. 일반 텍스트 추출 병행
            full_text += (page.extract_text() or "") + "\n"

    # 버전 추출 (v3.0.0.14 등 대응)
    v_match = re.search(r'TrusGuard\s+v?([\d\.]+)', full_text, re.I)
    version = v_match.group(1) if v_match else "Unknown"

    # 섹션별 텍스트 범위 탐색 (더 넓은 범위의 키워드 적용)
    # 3.0.0.14 파일은 '주요 개선 사항'과 '주요 이슈 해결' 키워드 사용
    imp_start = re.search(r'(주요\s*개선\s*사항|Improvement)', full_text, re.I)
    iss_start = re.search(r'(주요\s*이슈\s*해결|Issue)', full_text, re.I)
    ref_start = re.search(r'(연관\s*제품|참고\s*사항|5\.)', full_text, re.I)

    imp_text = full_text[imp_start.end():iss_start.start()] if imp_start and iss_start else ""
    iss_text = full_text[iss_start.end():ref_start.start()] if iss_start and ref_start else ""
    
    # 보안 컴포넌트
    ssl = re.search(r'OpenSSL\s+([\d\.]+[\w]*)', full_text, re.I)
    ssh = re.search(r'OpenSSH\s+([\d\.]+p\d+)', full_text, re.I)

    return {
        "version": version,
        "openssl": ssl.group(1) if ssl else "-",
        "openssh": ssh.group(1) if ssh else "-",
        "improvements": clean_report_text(imp_text),
        "issues": clean_report_text(iss_text),
        "raw_text": full_text
    }

# --- 4. 메인 UI ---
with st.sidebar:
    st.header("📜 버전 히스토리")
    history = pd.read_sql_query("SELECT version FROM notes ORDER BY version DESC", conn)
    selected_v = st.radio("버전 선택", history['version'].tolist()) if not history.empty else None
    
    st.divider()
    with st.expander("➕ PDF 등록 (표 형식 대응)"):
        files = st.file_uploader("파일 선택", accept_multiple_files=True, label_visibility="collapsed")
        if st.button("✅ DB 반영", use_container_width=True):
            for f in files:
                info = parse_enhanced_pdf(f)
                cursor.execute("SELECT version FROM notes WHERE version = ?", (info['version'],))
                if cursor.fetchone(): 
                    st.warning(f"{info['version']} 중복")
                    continue
                cursor.execute("INSERT INTO notes (version, openssl, openssh, improvements, issues, raw_text) VALUES (?,?,?,?,?,?)",
                               (info['version'], info['openssl'], info['openssh'], info['improvements'], info['issues'], info['raw_text']))
                conn.commit()
            st.rerun()

st.title("🛡️ TrusGuard 통합 관제 (v19.1)")

# 검색 로직
if 's_key' not in st.session_state: st.session_state.s_key = "v191"
c1, c2 = st.columns([5,1], vertical_alignment="bottom")
keyword = c1.text_input("검색어 입력", key=st.session_state.s_key)
if c2.button("🔄 초기화"):
    st.session_state.s_key = os.urandom(4).hex()
    st.rerun()

if keyword:
    kws = keyword.split()
    q = "SELECT version, improvements, issues FROM notes WHERE " + " AND ".join(["raw_text LIKE ?" for _ in kws]) + " ORDER BY version DESC"
    res = pd.read_sql_query(q, conn, params=[f'%{k}%' for k in kws])
    for _, row in res.iterrows():
        st.markdown(f"<div class='version-title'>📦 TrusGuard {row['version']}</div>", unsafe_allow_html=True)
        content = (row['improvements'] + "\n" + row['issues']).split('\n')
        matched = [l for l in content if all(k.lower() in l.lower() for k in kws) and l.strip()]
        display = "\n".join(matched) if matched else "*(본문 존재)*"
        for k in kws: display = re.sub(f"({re.escape(k)})", r"<mark class='highlight'>\1</mark>", display, flags=re.I)
        st.markdown(f"<div class='report-card'>{display.replace('\n','<br>')}</div>", unsafe_allow_html=True)

elif selected_v:
    r = pd.read_sql_query("SELECT * FROM notes WHERE version = ?", conn, params=[selected_v]).iloc[0]
    st.markdown(f"<div class='version-title'>📋 TrusGuard {r['version']} 상세</div>", unsafe_allow_html=True)
    st.markdown(f"<div class='report-card'><span class='sub-label'>🔒 보안 컴포넌트</span>OpenSSL: {r['openssl']} / OpenSSH: {r['openssh']}<br><br><span class='sub-label'>🔼 개선 사항</span>{r['improvements'].replace('\n','<br>')}<br><br><span class='sub-label'>🔥 이슈 해결</span>{r['issues'].replace('\n','<br>')}</div>", unsafe_allow_html=True)
