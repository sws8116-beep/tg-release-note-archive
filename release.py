import streamlit as st
import pdfplumber
import sqlite3
import pandas as pd
import re
import os

# --- 1. 페이지 스타일 및 레이아웃 ---
st.set_page_config(page_title="보안팀 릴리즈 아카이브 Pro v29.0", layout="wide")
st.markdown("""
    <style>
    .version-title { font-size: 28px; font-weight: 800; color: #0D47A1; background-color: #E3F2FD; padding: 12px 20px; border-radius: 8px; margin-top: 5px; border-left: 10px solid #1565C0; }
    .report-card { padding: 25px; border: 1px solid #CFD8DC; background-color: white; border-radius: 0px 0px 8px 8px; margin-bottom: 30px; line-height: 2.0; }
    .sub-label { font-weight: bold; color: #455A64; margin-top: 15px; display: block; font-size: 16px; }
    .highlight { background-color: #FFFF00; color: black; font-weight: bold; }
    </style>
    """, unsafe_allow_html=True)

# --- 2. DB 연결 ---
DB_FILE = 'security_notes_archive.db'
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT, openssl TEXT, openssh TEXT, improvements TEXT, issues TEXT, raw_text TEXT)''')
conn.commit()

# --- 3. [상식적 해결] 점(•) 항목 정밀 추출 로직 ---
def extract_bullet_points(text):
    """
    텍스트 전체에서 점(•) 또는 불렛 기호를 기준으로 시작하는 문장만 추출하여 한 줄씩 정렬
    """
    if not text: return ""
    # 1. 문서 전체의 줄바꿈을 공백으로 합쳐서 문맥 끊김 방지
    flat_text = re.sub(r'\s+', ' ', text).strip()
    
    # 2. 점(•) 또는 특수 불렛 기호(●, - 등)를 기준으로 분할
    # 3.1.3.11에서 주로 사용되는 '•'를 타겟팅
    items = re.split(r'•', flat_text)
    
    final_lines = []
    for item in items:
        clean_item = item.strip()
        if len(clean_item) > 3: # 의미 없는 짧은 텍스트 제외
            # 항목의 끝이 다음 항목의 시작 전까지임을 보장 (짤림 방지)
            final_lines.append(f"• {clean_item}")
            
    return "\n".join(final_lines)

def parse_v29_bullet_only(file):
    with pdfplumber.open(file) as pdf:
        full_text = ""
        for page in pdf.pages:
            # 일반 텍스트와 표 텍스트를 모두 가져옴
            full_text += (page.extract_text() or "") + "\n"
            tables = page.extract_tables()
            for table in tables:
                for row in table:
                    full_text += " ".join([str(c) for c in row if c]) + " "

        # 버전 정보 추출
        v = re.search(r'TrusGuard\s+v?([\d\.]+)', full_text, re.I)
        version = v.group(1) if v else "Unknown"
        
        # 보안 컴포넌트 추출
        ssl = re.search(r'OpenSSL\s+([\d\.]+[\w]*)', full_text, re.I)
        ssh = re.search(r'OpenSSH\s+([\d\.]+p\d+)', full_text, re.I)

        # 핵심 점(•) 항목들만 추출
        bullet_content = extract_bullet_points(full_text)

    return {
        "version": version,
        "openssl": ssl.group(1) if ssl else "-",
        "openssh": ssh.group(1) if ssh else "-",
        "content": bullet_content,
        "raw": full_text
    }

# --- 4. 사이드바 메뉴 (완전 복구) ---
if 's_key' not in st.session_state: st.session_state.s_key = "v29"

with st.sidebar:
    st.header("📜 버전 히스토리")
    hist = pd.read_sql_query("SELECT version FROM notes ORDER BY version DESC", conn)
    sel_v = st.radio("상세 보기 선택", hist['version'].tolist()) if not hist.empty else None

    st.divider()
    with st.expander("➕ PDF 등록 (점 항목 추출)", expanded=True):
        up_files = st.file_uploader("파일 선택", accept_multiple_files=True, label_visibility="collapsed")
        if st.button("✅ DB 반영", use_container_width=True):
            for f in up_files:
                info = parse_v29_bullet_only(f)
                cursor.execute("SELECT version FROM notes WHERE version = ?", (info['version'],))
                if not cursor.fetchone():
                    # improvements 필드에 점(•)으로 정리된 모든 내용을 저장
                    cursor.execute("INSERT INTO notes (version, openssl, openssh, improvements, issues, raw_text) VALUES (?,?,?,?,?,?)",
                                   (info['version'], info['openssl'], info['openssh'], info['content'], "", info['raw']))
                    conn.commit()
            st.rerun()

    with st.expander("🗑️ 데이터 삭제"):
        if not hist.empty:
            del_v = st.selectbox("삭제할 버전", hist['version'].tolist())
            if st.button("🚨 삭제 실행", use_container_width=True):
                cursor.execute("DELETE FROM notes WHERE version = ?", (del_v,))
                conn.commit()
                st.rerun()

    with st.expander("💾 시스템 DB 관리"):
        if os.path.exists(DB_FILE):
            with open(DB_FILE, "rb") as f: st.download_button("📥 DB 다운로드", f, file_name="notes.db")
        up_db = st.file_uploader("📤 DB 업로드", type=['db'])
        if up_db and st.button("🔥 교체"):
            with open(DB_FILE, "wb") as f: f.write(up_db.getbuffer())
            st.rerun()

# --- 5. 메인 화면 ---
st.title("🛡️ TrusGuard 통합 관제 (v29.0)")

c1, c2 = st.columns([5,1], vertical_alignment="bottom")
keyword = c1.text_input("검색어 입력", key=st.session_state.s_key)
if c2.button("🔄 초기화"):
    st.session_state.s_key = os.urandom(4).hex()
    st.rerun()

def highlight(text, kws):
    if not kws: return text.replace("\n", "<br>")
    for k in kws: text = re.sub(f"({re.escape(k)})", r"<mark class='highlight'>\1</mark>", text, flags=re.I)
    return text.replace("\n", "<br>")

if keyword:
    kws = keyword.split()
    query = "SELECT version, improvements FROM notes WHERE " + " AND ".join(["raw_text LIKE ?" for _ in kws]) + " ORDER BY version DESC"
    res = pd.read_sql_query(query, conn, params=[f'%{k}%' for k in kws])
    for _, row in res.iterrows():
        st.markdown(f"<div class='version-title'>📦 TrusGuard {row['version']}</div>", unsafe_allow_html=True)
        all_c = row['improvements'].split('\n')
        matched = [l for l in all_c if all(k.lower() in l.lower() for k in kws) and l.strip()]
        st.markdown(f"<div class='report-card'>{highlight('\n'.join(matched) if matched else '*(본문 검색됨)*', kws)}</div>", unsafe_allow_html=True)

elif sel_v:
    r = pd.read_sql_query("SELECT * FROM notes WHERE version = ?", conn, params=[sel_v]).iloc[0]
    st.markdown(f"<div class='version-title'>📋 TrusGuard {r['version']} 전체 리포트</div>", unsafe_allow_html=True)
    st.markdown(f"""<div class='report-card'>
        <span class='sub-label'>🔒 보안 컴포넌트</span>OpenSSL: {r['openssl']} / OpenSSH: {r['openssh']}<br><br>
        <span class='sub-label'>📋 상세 변경 내역 (점 항목 통합)</span>{r['improvements'].replace('\n','<br>')}
    </div>""", unsafe_allow_html=True)
