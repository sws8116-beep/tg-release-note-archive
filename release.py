import streamlit as st
import pdfplumber
import sqlite3
import pandas as pd
import re
import os

# --- 1. 페이지 스타일 ---
st.set_page_config(page_title="보안팀 릴리즈 아카이브 Pro v26.0", layout="wide")
st.markdown("""
    <style>
    .version-title { font-size: 28px; font-weight: 800; color: #0D47A1; background-color: #E3F2FD; padding: 12px 20px; border-radius: 8px; margin-top: 5px; border-left: 10px solid #1565C0; }
    .report-card { padding: 25px; border: 1px solid #CFD8DC; background-color: white; border-radius: 0px 0px 8px 8px; margin-bottom: 30px; line-height: 1.8; }
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

# --- 3. [상식적 보정] 텍스트 한 줄 통합 로직 ---
def reassemble_text(text_list):
    """분절된 텍스트 조각들을 문맥에 맞게 한 줄씩 재조합"""
    combined = " ".join(text_list)
    # 1. 불필요한 연속 공백 제거 및 줄바꿈 삭제
    clean_text = re.sub(r'\s+', ' ', combined).strip()
    # 2. 대괄호([])를 기준으로 문장 나누기
    # 예: "[SSL VPN] 어쩌구 저쩌구 [IPS] 하하하" -> ["", "[SSL VPN] 어쩌구 저쩌구 ", "[IPS] 하하하"]
    items = re.split(r'(\[[^\]]+\])', clean_text)
    
    final_lines = []
    current_item = ""
    for i in range(1, len(items), 2):
        header = items[i] # [모듈명]
        content = items[i+1] if i+1 < len(items) else ""
        final_lines.append(f"* {header}{content.strip()}")
        
    return "\n".join(final_lines)

def parse_pdf_v26(file):
    with pdfplumber.open(file) as pdf:
        full_raw = ""
        imp_raw_parts = []
        iss_raw_parts = []
        current_sec = None

        for page in pdf.pages:
            p_text = page.extract_text() or ""
            full_raw += p_text + "\n"
            
            # 섹션 감지
            if "개선/신규" in p_text or "개선 사항" in p_text: current_sec = "IMP"
            elif "이슈" in p_text and "상세변경" in p_text: current_sec = "ISS"
            elif "5. 연관제품" in p_text: current_sec = None

            # 표(Table)에서 데이터 조각 수집
            tables = page.extract_tables()
            for table in tables:
                for row in table:
                    # 행의 모든 셀을 합치되, None은 무시
                    row_cells = [str(c).strip() for c in row if c]
                    if not row_cells: continue
                    
                    # 3.1.3.11 구조 대응: [구분, 모듈, 상세, 이슈번호]
                    if len(row_cells) >= 3 and any(k in row_cells[0] for k in ['개선', '신규', '이슈']):
                        line_fragment = f"[{row_cells[1]}] {row_cells[2]}"
                        if len(row_cells) > 3 and row_cells[3] and row_cells[3] != row_cells[1]:
                            line_fragment += f" ({row_cells[3]})"
                        
                        if current_sec == "IMP": imp_raw_parts.append(line_fragment)
                        elif current_sec == "ISS": iss_raw_parts.append(line_fragment)

        # 정보 추출
        v = re.search(r'TrusGuard\s+v?([\d\.]+)', full_raw, re.I)
        version = v.group(1) if v else "Unknown"
        ssl = re.search(r'OpenSSL\s+([\d\.]+[\w]*)', full_raw, re.I)
        ssh = re.search(r'OpenSSH\s+([\d\.]+p\d+)', full_raw, re.I)

    return {
        "version": version,
        "openssl": ssl.group(1) if ssl else "-",
        "openssh": ssh.group(1) if ssh else "-",
        "improvements": reassemble_text(imp_raw_parts),
        "issues": reassemble_text(iss_raw_parts),
        "raw_text": full_raw
    }

# --- 4. 사이드바 (메뉴 고정) ---
if 's_key' not in st.session_state: st.session_state.s_key = "v26"

with st.sidebar:
    st.header("📜 버전 히스토리")
    hist = pd.read_sql_query("SELECT version FROM notes ORDER BY version DESC", conn)
    sel_v = st.radio("버전 선택", hist['version'].tolist()) if not hist.empty else None

    st.divider()
    with st.expander("➕ PDF 신규 등록", expanded=True): # 등록 메뉴는 열어둠
        up_files = st.file_uploader("파일 선택", accept_multiple_files=True, label_visibility="collapsed")
        if st.button("✅ DB 반영", use_container_width=True):
            for f in up_files:
                info = parse_pdf_v26(f)
                cursor.execute("SELECT version FROM notes WHERE version = ?", (info['version'],))
                if not cursor.fetchone():
                    cursor.execute("INSERT INTO notes (version, openssl, openssh, improvements, issues, raw_text) VALUES (?,?,?,?,?,?)",
                                   (info['version'], info['openssl'], info['openssh'], info['improvements'], info['issues'], info['raw_text']))
                    conn.commit()
            st.success("데이터가 정상 반영되었습니다.")
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
st.title("🛡️ TrusGuard 통합 관제 (v26.0)")

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
    query = "SELECT version, improvements, issues FROM notes WHERE " + " AND ".join(["raw_text LIKE ?" for _ in kws]) + " ORDER BY version DESC"
    res = pd.read_sql_query(query, conn, params=[f'%{k}%' for k in kws])
    for _, row in res.iterrows():
        st.markdown(f"<div class='version-title'>📦 TrusGuard {row['version']}</div>", unsafe_allow_html=True)
        all_c = (row['improvements'] + "\n" + row['issues']).split('\n')
        matched = [l for l in all_c if all(k.lower() in l.lower() for k in kws) and l.strip()]
        st.markdown(f"<div class='report-card'>{highlight('\n'.join(matched) if matched else '*(본문 검색됨)*', kws)}</div>", unsafe_allow_html=True)

elif sel_v:
    r = pd.read_sql_query("SELECT * FROM notes WHERE version = ?", conn, params=[sel_v]).iloc[0]
    st.markdown(f"<div class='version-title'>📋 TrusGuard {r['version']} 상세 리포트</div>", unsafe_allow_html=True)
    st.markdown(f"""<div class='report-card'>
        <span class='sub-label'>🔒 보안 컴포넌트</span>OpenSSL: {r['openssl']} / OpenSSH: {r['openssh']}<br><br>
        <span class='sub-label'>🔼 상세변경사항 (개선/신규)</span>{r['improvements'].replace('\n','<br>')}<br><br>
        <span class='sub-label'>🔥 상세변경사항 (이슈)</span>{r['issues'].replace('\n','<br>')}
    </div>""", unsafe_allow_html=True)
