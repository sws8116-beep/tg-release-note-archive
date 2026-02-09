import streamlit as st
import pdfplumber
import sqlite3
import pandas as pd
import re
import os

# --- 1. 페이지 스타일 및 레이아웃 설정 ---
st.set_page_config(page_title="보안팀 릴리즈 아카이브 Pro v27.0", layout="wide")

st.markdown("""
    <style>
    .version-title { font-size: 28px; font-weight: 800; color: #0D47A1; background-color: #E3F2FD; padding: 12px 20px; border-radius: 8px; margin-top: 5px; border-left: 10px solid #1565C0; }
    .report-card { padding: 25px; border: 1px solid #CFD8DC; background-color: white; border-radius: 0px 0px 8px 8px; margin-bottom: 30px; line-height: 1.8; }
    .sub-label { font-weight: bold; color: #455A64; margin-top: 15px; display: block; font-size: 16px; }
    .highlight { background-color: #FFFF00; color: black; font-weight: bold; }
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

# --- 3. [핵심] 대괄호([]) 및 글머리 기호(•) 통합 파싱 로직 ---

def clean_and_reassemble(raw_text):
    """
    텍스트를 [ 또는 • 기준으로 나누어 항목별로 재조합 (짤림 방지)
    """
    if not raw_text: return ""
    # 모든 줄바꿈을 공백으로 합쳐서 문장 끊김 방지
    text = re.sub(r'\s+', ' ', raw_text).strip()
    
    # [ 또는 • 를 기준으로 분리 (전방 탐색을 사용하여 구분자 포함)
    parts = re.split(r'(?=\[|•)', text)
    
    final_items = []
    for p in parts:
        item = p.strip()
        if not item: continue
        # 이미 * 로 시작하지 않는다면 붙여줌
        final_items.append(f"* {item}")
        
    return "\n".join(final_items)

def parse_pdf_universal(file):
    with pdfplumber.open(file) as pdf:
        full_raw = ""
        imp_raw = ""
        iss_raw = ""
        current_sec = None

        for page in pdf.pages:
            p_text = page.extract_text() or ""
            full_raw += p_text + "\n"
            
            # 섹션 감지
            if "상세변경사항 (개선/신규)" in p_text or "주요 개선 사항" in p_text:
                current_sec = "IMP"
            elif "상세변경사항 (이슈)" in p_text or "주요 이슈 해결" in p_text:
                current_sec = "ISS"
            elif "5. 연관제품" in p_text or "참고사항" in p_text:
                current_sec = None

            # 표(Table) 데이터도 텍스트로 합쳐서 섹션에 포함 (짤림 방지)
            tables = page.extract_tables()
            for table in tables:
                for row in table:
                    # 행 데이터를 한 줄의 텍스트로 합침
                    row_text = " ".join([str(c).replace('\n', ' ').strip() for c in row if c])
                    if current_sec == "IMP": imp_raw += row_text + " "
                    elif current_sec == "ISS": iss_raw += row_text + " "

            # 일반 텍스트에서도 섹션 내용 수집
            if current_sec == "IMP": imp_raw += p_text + " "
            elif current_sec == "ISS": iss_raw += p_text + " "

        # 버전 및 보안 정보 추출
        v = re.search(r'TrusGuard\s+v?([\d\.]+)', full_raw, re.I)
        version = v.group(1) if v else "Unknown"
        ssl = re.search(r'OpenSSL\s+([\d\.]+[\w]*)', full_raw, re.I)
        ssh = re.search(r'OpenSSH\s+([\d\.]+p\d+)', full_raw, re.I)

    return {
        "version": version,
        "openssl": ssl.group(1) if ssl else "-",
        "openssh": ssh.group(1) if ssh else "-",
        "improvements": clean_and_reassemble(imp_raw),
        "issues": clean_and_reassemble(iss_raw),
        "raw_text": full_raw
    }

# --- 4. 사이드바 (모든 관리 메뉴 복구) ---
if 's_key' not in st.session_state: st.session_state.s_key = "v27"

def reset_search():
    st.session_state.s_key = os.urandom(4).hex()
    st.rerun()

with st.sidebar:
    st.header("📜 전체 히스토리")
    hist_df = pd.read_sql_query("SELECT version FROM notes ORDER BY version DESC", conn)
    sel_v = st.radio("상세 보기 선택", hist_df['version'].tolist()) if not hist_df.empty else None

    st.divider()
    # 1. PDF 등록
    with st.expander("➕ PDF 신규 등록", expanded=False):
        uploaded = st.file_uploader("파일 선택", accept_multiple_files=True, label_visibility="collapsed")
        if st.button("✅ DB 반영", use_container_width=True):
            for f in uploaded:
                info = parse_pdf_universal(f)
                cursor.execute("SELECT version FROM notes WHERE version = ?", (info['version'],))
                if not cursor.fetchone():
                    cursor.execute("INSERT INTO notes (version, openssl, openssh, improvements, issues, raw_text) VALUES (?,?,?,?,?,?)",
                                   (info['version'], info['openssl'], info['openssh'], info['improvements'], info['issues'], info['raw_text']))
                    conn.commit()
            st.success("데이터가 반영되었습니다.")
            st.rerun()

    # 2. 데이터 삭제
    with st.expander("🗑️ 데이터 삭제", expanded=False):
        if not hist_df.empty:
            del_v = st.selectbox("삭제 버전 선택", hist_df['version'].tolist())
            if st.button("🚨 삭제 실행", use_container_width=True):
                cursor.execute("DELETE FROM notes WHERE version = ?", (del_v,))
                conn.commit()
                st.rerun()

    # 3. DB 관리
    with st.expander("💾 시스템 DB 관리", expanded=False):
        if os.path.exists(DB_FILE):
            with open(DB_FILE, "rb") as f: st.download_button("📥 DB 다운로드", f, file_name="notes_archive.db")
        up_db = st.file_uploader("📤 백업 DB 업로드", type=['db'])
        if up_db and st.button("🔥 서버 DB 교체"):
            with open(DB_FILE, "wb") as f: f.write(up_db.getbuffer())
            st.rerun()

# --- 5. 메인 화면 ---
st.title("🛡️ TrusGuard 통합 관제 (v27.0)")

c1, c2 = st.columns([5,1], vertical_alignment="bottom")
keyword = c1.text_input("검색어 입력 (공백 시 다중 검색)", key=st.session_state.s_key)
if c2.button("🔄 초기화", use_container_width=True, on_click=reset_search):
    pass # on_click에서 처리

def highlight(text, kws):
    if not kws: return text.replace("\n", "<br>")
    for k in kws: text = re.sub(f"({re.escape(k)})", r"<mark class='highlight'>\1</mark>", text, flags=re.I)
    return text.replace("\n", "<br>")

if keyword:
    kws = keyword.split()
    query = "SELECT version, improvements, issues FROM notes WHERE " + " AND ".join(["raw_text LIKE ?" for _ in kws]) + " ORDER BY version DESC"
    res = pd.read_sql_query(query, conn, params=[f'%{k}%' for k in kws])
    for _, row in res.iterrows():
        st.markdown(f"<div class='version-title'>📦 TrusGuard {row['version']}</div>", unsafe_allow_html=True)
        # 내용 합치기
        all_c = (row['improvements'] + "\n" + row['issues']).split('\n')
        matched = [l for l in all_c if all(k.lower() in l.lower() for k in kws) and l.strip()]
        st.markdown(f"<div class='report-card'>{highlight('\n'.join(matched) if matched else '*(본문 내 존재)*', kws)}</div>", unsafe_allow_html=True)

elif sel_v:
    r = pd.read_sql_query("SELECT * FROM notes WHERE version = ?", conn, params=[sel_v]).iloc[0]
    st.markdown(f"<div class='version-title'>📋 TrusGuard {r['version']} 상세 리포트</div>", unsafe_allow_html=True)
    st.markdown(f"""<div class='report-card'>
        <span class='sub-label'>🔒 보안 컴포넌트</span>OpenSSL: {r['openssl']} / OpenSSH: {r['openssh']}<br><br>
        <span class='sub-label'>🔼 상세변경사항 (개선/신규)</span>{r['improvements'].replace('\n','<br>')}<br><br>
        <span class='sub-label'>🔥 상세변경사항 (이슈)</span>{r['issues'].replace('\n','<br>')}
    </div>""", unsafe_allow_html=True)
