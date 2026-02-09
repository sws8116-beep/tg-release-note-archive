import streamlit as st
import pdfplumber
import sqlite3
import pandas as pd
import re
import os

# --- 1. 페이지 스타일 ---
st.set_page_config(page_title="보안팀 릴리즈 아카이브 Pro v22.0", layout="wide")
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

# --- 3. [핵심] 정밀 표 추출 로직 ---
def extract_table_data(page):
    """표 데이터를 '상세내용' 위주로 한 줄로 합쳐서 추출"""
    lines = []
    tables = page.extract_tables()
    for table in tables:
        if not table or len(table) < 1: continue
        # 헤더 검색 (구분, 모듈, 상세 내용 등)
        for row in table:
            # None 제거 및 텍스트 정제
            cells = [str(c).replace('\n', ' ').strip() for c in row if c is not None]
            if len(cells) >= 3 and ('개선' in cells[0] or '이슈' in cells[0] or '신규' in cells[0]):
                # 0:구분, 1:모듈/기능, 2:상세내용, 3:이슈번호
                mod = cells[1]
                desc = cells[2]
                issue = cells[3] if len(cells) > 3 else ""
                line = f"* [{mod}] {desc}"
                if issue and issue != mod: line += f" ({issue})"
                lines.append(line)
    return lines

def parse_full_pdf(file):
    with pdfplumber.open(file) as pdf:
        full_raw = ""
        improvement_all = []
        issue_all = []
        
        # 섹션 감지 플래그
        current_sec = None
        
        for page in pdf.pages:
            p_text = page.extract_text() or ""
            full_raw += p_text + "\n"
            
            # 섹션 전환 체크
            if "상세변경사항 (개선/신규)" in p_text or "주요 개선 사항" in p_text:
                current_sec = "IMP"
            elif "상세변경사항 (이슈)" in p_text or "주요 이슈 해결" in p_text:
                current_sec = "ISS"
            elif "5. 연관제품" in p_text or "참고사항" in p_text:
                current_sec = None
            
            # 표 데이터 추출
            table_lines = extract_table_data(page)
            if table_lines:
                if current_sec == "IMP": improvement_all.extend(table_lines)
                elif current_sec == "ISS": issue_all.extend(table_lines)
            else:
                # 표가 없는 경우 일반 텍스트에서 글머리 기호 기준 추출
                clean_p = re.sub(r'\s+', ' ', p_text)
                if current_sec:
                    # [모듈] 패턴 찾기
                    found = re.findall(r'(\[[^\]]+\][^\[]+)', clean_p)
                    if current_sec == "IMP": improvement_all.extend([f"* {f.strip()}" for f in found])
                    elif current_sec == "ISS": issue_all.extend([f"* {f.strip()}" for f in found])

        # 정보 정리
        v = re.search(r'TrusGuard\s+v?([\d\.]+)', full_raw, re.I)
        version = v.group(1) if v else "Unknown"
        ssl = re.search(r'OpenSSL\s+([\d\.]+[\w]*)', full_raw, re.I)
        ssh = re.search(r'OpenSSH\s+([\d\.]+p\d+)', full_raw, re.I)

    return {
        "version": version,
        "openssl": ssl.group(1) if ssl else "-",
        "openssh": ssh.group(1) if ssh else "-",
        "improvements": "\n".join(list(dict.fromkeys(improvement_all))), # 중복 제거
        "issues": "\n".join(list(dict.fromkeys(issue_all))),
        "raw_text": full_raw
    }

# --- 4. 사이드바 메뉴 ---
if 's_key' not in st.session_state: st.session_state.s_key = "v22"

with st.sidebar:
    st.header("📜 전체 히스토리")
    hist_df = pd.read_sql_query("SELECT version FROM notes ORDER BY version DESC", conn)
    sel_v = st.radio("상세 보기 선택", hist_df['version'].tolist()) if not hist_df.empty else None

    st.divider()
    with st.expander("➕ PDF 신규 등록", expanded=False):
        uploaded = st.file_uploader("파일 선택", accept_multiple_files=True, label_visibility="collapsed")
        if st.button("✅ DB 반영", use_container_width=True):
            for f in uploaded:
                info = parse_full_pdf(f)
                cursor.execute("SELECT version FROM notes WHERE version = ?", (info['version'],))
                if not cursor.fetchone():
                    cursor.execute("INSERT INTO notes (version, openssl, openssh, improvements, issues, raw_text) VALUES (?,?,?,?,?,?)",
                                   (info['version'], info['openssl'], info['openssh'], info['improvements'], info['issues'], info['raw_text']))
                    conn.commit()
            st.rerun()

    with st.expander("🗑️ 데이터 삭제", expanded=False):
        if not hist_df.empty:
            del_v = st.selectbox("삭제 버전", hist_df['version'].tolist())
            if st.button("🚨 삭제 실행"):
                cursor.execute("DELETE FROM notes WHERE version = ?", (del_v,))
                conn.commit()
                st.rerun()

    with st.expander("💾 시스템 DB 관리", expanded=False):
        if os.path.exists(DB_FILE):
            with open(DB_FILE, "rb") as f: st.download_button("📥 DB 다운로드", f, file_name="notes.db")
        up_db = st.file_uploader("📤 DB 업로드", type=['db'])
        if up_db and st.button("🔥 교체"):
            with open(DB_FILE, "wb") as f: f.write(up_db.getbuffer())
            st.rerun()

# --- 5. 메인 화면 ---
st.title("🛡️ TrusGuard 통합 관제 (v22.0)")
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
        st.markdown(f"<div class='report-card'>{highlight('\n'.join(matched) if matched else '*(본문 존재)*', kws)}</div>", unsafe_allow_html=True)

elif sel_v:
    r = pd.read_sql_query("SELECT * FROM notes WHERE version = ?", conn, params=[sel_v]).iloc[0]
    st.markdown(f"<div class='version-title'>📋 TrusGuard {r['version']} 상세</div>", unsafe_allow_html=True)
    st.markdown(f"<div class='report-card'><span class='sub-label'>🔒 보안 컴포넌트</span>OpenSSL: {r['openssl']} / OpenSSH: {r['openssh']}<br><br><span class='sub-label'>🔼 개선 사항</span>{r['improvements'].replace('\n','<br>')}<br><br><span class='sub-label'>🔥 이슈 해결</span>{r['issues'].replace('\n','<br>')}</div>", unsafe_allow_html=True)
