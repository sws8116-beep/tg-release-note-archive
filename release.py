import streamlit as st
import pdfplumber
import sqlite3
import pandas as pd
import re
import os

# --- 1. 페이지 스타일 및 문단 디자인 ---
st.set_page_config(page_title="보안팀 릴리즈 아카이브 Pro v32.0", layout="wide")
st.markdown("""
    <style>
    .version-title { font-size: 28px; font-weight: 800; color: #0D47A1; background-color: #E3F2FD; padding: 12px 20px; border-radius: 8px; margin-top: 5px; border-left: 10px solid #1565C0; }
    .report-card { padding: 25px; border: 1px solid #CFD8DC; background-color: white; border-radius: 0px 0px 8px 8px; margin-bottom: 30px; line-height: 2.2; }
    .sub-label { font-weight: bold; color: #455A64; margin-top: 15px; display: block; font-size: 16px; }
    .highlight { background-color: #FFFF00; color: black; font-weight: bold; }
    /* 문단 간격을 넓게 벌려 가독성 확보 */
    .release-item { margin-bottom: 25px; display: block; border-bottom: 1px solid #F0F4F8; padding-bottom: 15px; }
    .release-item:last-child { border-bottom: none; }
    </style>
    """, unsafe_allow_html=True)

# --- 2. DB 연결 ---
DB_FILE = 'security_notes_archive.db'
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT, openssl TEXT, openssh TEXT, improvements TEXT, issues TEXT, raw_text TEXT)''')
conn.commit()

# --- 3. [상식적 해결] 3.1.3.11 표 데이터 정밀 추출 로직 ---
def parse_v32_expert(file):
    with pdfplumber.open(file) as pdf:
        full_raw = ""
        extracted_items = []
        
        for page in pdf.pages:
            p_text = page.extract_text() or ""
            full_raw += p_text + "\n"
            
            # 표(Table) 추출 - 3.1.3.11의 요약 테이블 타겟팅
            tables = page.extract_tables()
            for table in tables:
                if not table: continue
                for row in table:
                    # 셀 내부 줄바꿈 제거 및 데이터 병합
                    cells = [str(c).replace('\n', ' ').strip() if c else "" for c in row]
                    
                    # 3.1.3.11 구조: [유형, 기능 분류, 요약, WORKS]
                    # 유형 컬럼에 개선, 신규, 이슈 등의 키워드가 있는 행만 수집
                    if len(cells) >= 3 and any(kw in cells[0] for kw in ['개선', '신규', '이슈', 'BUG', '수정']):
                        category = cells[1] # 기능 분류
                        summary = cells[2]  # 요약 내용 (이제 안 짤림)
                        works_id = cells[3] if len(cells) > 3 else ""
                        
                        # 항목 생성
                        line = f"• [{category}] {summary}"
                        if works_id and works_id.lower() != "none" and works_id != category:
                            line += f" ({works_id})"
                        extracted_items.append(line)

        # 중복 제거 및 버전 정보
        unique_items = list(dict.fromkeys(extracted_items))
        v_match = re.search(r'TrusGuard\s+v?([\d\.]+)', full_raw, re.I)
        version = v_match.group(1) if v_match else "Unknown"
        ssl = re.search(r'OpenSSL\s+([\d\.]+[\w]*)', full_raw, re.I)
        ssh = re.search(r'OpenSSH\s+([\d\.]+p\d+)', full_raw, re.I)

    return {
        "version": version,
        "openssl": ssl.group(1) if ssl else "-",
        "openssh": ssh.group(1) if ssh else "-",
        "content": "\n\n".join(unique_items), # 문단 사이 간격을 위해 \n\n 적용
        "raw": full_raw
    }

# --- 4. 사이드바 (메뉴 복구) ---
if 's_key' not in st.session_state: st.session_state.s_key = "v32"

with st.sidebar:
    st.header("📜 버전 히스토리")
    hist_df = pd.read_sql_query("SELECT version FROM notes ORDER BY version DESC", conn)
    sel_v = st.radio("상세 보기 선택", hist_df['version'].tolist()) if not hist_df.empty else None

    st.divider()
    with st.expander("➕ PDF 등록 (정밀 추출)", expanded=True):
        up_files = st.file_uploader("파일 선택", accept_multiple_files=True, label_visibility="collapsed")
        if st.button("✅ DB 반영", use_container_width=True):
            for f in up_files:
                info = parse_v32_expert(f)
                cursor.execute("SELECT version FROM notes WHERE version = ?", (info['version'],))
                if not cursor.fetchone():
                    cursor.execute("INSERT INTO notes (version, openssl, openssh, improvements, issues, raw_text) VALUES (?,?,?,?,?,?)",
                                   (info['version'], info['openssl'], info['openssh'], info['content'], "", info['raw']))
                    conn.commit()
            st.rerun()

    with st.expander("🗑️ 데이터 삭제"):
        if not hist_df.empty:
            del_v = st.selectbox("삭제 버전", hist_df['version'].tolist())
            if st.button("🚨 삭제 실행"):
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
st.title("🛡️ TrusGuard 통합 관제 (v32.0)")

c1, c2 = st.columns([5,1], vertical_alignment="bottom")
keyword = c1.text_input("검색어 입력", key=st.session_state.s_key)
if c2.button("🔄 초기화"):
    st.session_state.s_key = os.urandom(4).hex()
    st.rerun()

def highlight_html(text, kws):
    if not text: return ""
    paras = text.split('\n\n')
    html_items = [f"<div class='release-item'>{p.strip()}</div>" for p in paras if p.strip()]
    combined = "".join(html_items)
    if kws:
        for k in kws: combined = re.sub(f"({re.escape(k)})", r"<mark class='highlight'>\1</mark>", combined, flags=re.I)
    return combined

if keyword:
    kws = keyword.split()
    query = "SELECT version, improvements FROM notes WHERE " + " AND ".join(["raw_text LIKE ?" for _ in kws]) + " ORDER BY version DESC"
    res = pd.read_sql_query(query, conn, params=[f'%{k}%' for k in kws])
    for _, row in res.iterrows():
        st.markdown(f"<div class='version-title'>📦 TrusGuard {row['version']}</div>", unsafe_allow_html=True)
        all_paras = row['improvements'].split('\n\n')
        matched = [p for p in all_paras if all(k.lower() in p.lower() for k in kws)]
        st.markdown(f"<div class='report-card'>{highlight_html('\n\n'.join(matched), kws)}</div>", unsafe_allow_html=True)

elif sel_v:
    r = pd.read_sql_query("SELECT * FROM notes WHERE version = ?", conn, params=[sel_v]).iloc[0]
    st.markdown(f"<div class='version-title'>📋 TrusGuard {r['version']} 리포트</div>", unsafe_allow_html=True)
    st.markdown(f"""<div class='report-card'>
        <span class='sub-label'>🔒 보안 컴포넌트</span>OpenSSL: {r['openssl']} / OpenSSH: {r['openssh']}<br><br>
        <span class='sub-label'>📋 주요 내역 요약</span>{highlight_html(r['improvements'], [])}
    </div>""", unsafe_allow_html=True)
