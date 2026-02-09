import streamlit as st
import pdfplumber
import sqlite3
import pandas as pd
import re
import os

# --- 1. 페이지 스타일 및 문단 디자인 ---
st.set_page_config(page_title="보안팀 릴리즈 아카이브 Pro v35.0", layout="wide")
st.markdown("""
    <style>
    .version-title { font-size: 28px; font-weight: 800; color: #0D47A1; background-color: #E3F2FD; padding: 12px 20px; border-radius: 8px; margin-top: 5px; border-left: 10px solid #1565C0; }
    .report-card { padding: 25px; border: 1px solid #CFD8DC; background-color: white; border-radius: 0px 0px 8px 8px; margin-bottom: 30px; line-height: 2.2; font-size: 15px; }
    .sub-label { font-weight: bold; color: #1565C0; margin-top: 25px; margin-bottom: 10px; display: block; font-size: 18px; border-bottom: 2px solid #E3F2FD; padding-bottom: 5px; }
    .highlight { background-color: #FFFF00; color: black; font-weight: bold; }
    .release-item { margin-bottom: 22px; display: block; padding-left: 10px; border-left: 3px solid #ECEFF1; }
    </style>
    """, unsafe_allow_html=True)

# --- 2. DB 연결 ---
DB_FILE = 'security_notes_archive.db'
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT, openssl TEXT, openssh TEXT, improvements TEXT, issues TEXT, raw_text TEXT)''')
conn.commit()

# --- 3. [통합 엔진] 표 데이터 문장화 및 텍스트 하이브리드 파싱 ---

def parse_pdf_v35(file):
    with pdfplumber.open(file) as pdf:
        full_raw = ""
        combined_list = []
        
        for page in pdf.pages:
            p_text = page.extract_text() or ""
            full_raw += p_text + "\n"
            
            # [A] 표(Table) 데이터 정밀 추출 (3.1.3 이하 버전 핵심)
            tables = page.extract_tables()
            for table in tables:
                if not table: continue
                for row in table:
                    # 셀 내부 줄바꿈 제거 및 데이터 병합
                    cells = [str(c).replace('\n', ' ').strip() if c else "" for c in row]
                    
                    # 유형(개선/신규/이슈)이 포함된 행을 찾아 한 문장으로 조립
                    if len(cells) >= 3 and any(kw in cells[0] for kw in ['개선', '신규', '이슈', '수정', 'BUG', 'TASK']):
                        v_type = cells[0]   # 개선/신규/이슈
                        v_cat = cells[1]    # 기능 분류
                        v_desc = cells[2]   # 요약 내용
                        v_id = cells[3] if len(cells) > 3 else "" # WORKS ID
                        
                        # 사용자 요청 포맷: [유형/기능분류] 요약 (ID)
                        assembled_line = f"• [{v_type}/{v_cat}] {v_desc}"
                        if v_id and v_id.lower() != "none" and v_id != v_cat:
                            assembled_line += f" ({v_id})"
                        
                        combined_list.append(assembled_line)

            # [B] 일반 텍스트 및 불렛 기호 추출 (3.1.4 버전 호환)
            lines = p_text.split('\n')
            for l in lines:
                clean_l = l.strip()
                # • 로 시작하거나 [내용] 으로 시작하는 행 수집
                if clean_l.startswith('•') or (clean_l.startswith('[') and ']' in clean_l):
                    if len(clean_l) > 10 and not any(clean_l in item for item in combined_list):
                        combined_list.append(clean_l)

        # 버전 및 보안 정보
        v = re.search(r'TrusGuard\s+v?([\d\.]+)', full_raw, re.I)
        version = v.group(1) if v else "Unknown"
        ssl = re.search(r'OpenSSL\s+([\d\.]+[\w]*)', full_raw, re.I)
        ssh = re.search(r'OpenSSH\s+([\d\.]+p\d+)', full_raw, re.I)

    return {
        "version": version,
        "openssl": ssl.group(1) if ssl else "-",
        "openssh": ssh.group(1) if ssh else "-",
        "content": "\n\n".join(dict.fromkeys(combined_list)), # 중복 제거 및 문단 간격
        "raw": full_raw
    }

# --- 4. 사이드바 메뉴 ---
if 's_key' not in st.session_state: st.session_state.s_key = "v35"

with st.sidebar:
    st.header("📜 버전 히스토리")
    hist_df = pd.read_sql_query("SELECT version FROM notes ORDER BY version DESC", conn)
    sel_v = st.radio("버전 선택", hist_df['version'].tolist()) if not hist_df.empty else None

    st.divider()
    with st.expander("➕ PDF 등록 (표 문장화 지원)", expanded=True):
        uploaded = st.file_uploader("파일 선택", accept_multiple_files=True, label_visibility="collapsed")
        if st.button("✅ DB 반영", use_container_width=True):
            for f in uploaded:
                info = parse_pdf_v35(f)
                cursor.execute("SELECT version FROM notes WHERE version = ?", (info['version'],))
                if not cursor.fetchone():
                    cursor.execute("INSERT INTO notes (version, openssl, openssh, improvements, issues, raw_text) VALUES (?,?,?,?,?,?)",
                                   (info['version'], info['openssl'], info['openssh'], info['content'], "", info['raw']))
                    conn.commit()
            st.rerun()

    with st.expander("🗑️ 데이터 삭제"):
        if not hist_df.empty:
            del_v = st.selectbox("삭제 버전 선택", hist_df['version'].tolist())
            if st.button("🚨 삭제 실행"):
                cursor.execute("DELETE FROM notes WHERE version = ?", (del_v,))
                conn.commit()
                st.rerun()

    with st.expander("💾 시스템 DB 관리"):
        if os.path.exists(DB_FILE):
            with open(DB_FILE, "rb") as f: st.download_button("📥 DB 다운로드", f, file_name="notes.db")

# --- 5. 메인 화면 ---
st.title("🛡️ TrusGuard 통합 관제 (v35.0)")

c1, c2 = st.columns([5,1], vertical_alignment="bottom")
keyword = c1.text_input("검색어 입력", key=st.session_state.s_key)
if c2.button("🔄 초기화"):
    st.session_state.s_key = os.urandom(4).hex()
    st.rerun()

def display_content(text, kws):
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
        all_p = row['improvements'].split('\n\n')
        matched = [p for p in all_p if all(k.lower() in p.lower() for k in kws)]
        st.markdown(f"<div class='report-card'>{display_content('\n\n'.join(matched), kws)}</div>", unsafe_allow_html=True)

elif sel_v:
    r = pd.read_sql_query("SELECT * FROM notes WHERE version = ?", conn, params=[sel_v]).iloc[0]
    st.markdown(f"<div class='version-title'>📋 TrusGuard {r['version']} 상세 리포트</div>", unsafe_allow_html=True)
    st.markdown(f"""<div class='report-card'>
        <span class='sub-label'>🔒 보안 컴포넌트</span>OpenSSL: {r['openssl']} / OpenSSH: {r['openssh']}<br><br>
        <span class='sub-label'>📋 상세 변경 내역 (통합 추출)</span>
        {display_content(r['improvements'], [])}
    </div>""", unsafe_allow_html=True)
