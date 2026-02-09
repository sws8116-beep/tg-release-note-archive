import streamlit as st
import pdfplumber
import sqlite3
import pandas as pd
import re
import os

# --- 1. 페이지 스타일 및 문단 디자인 ---
st.set_page_config(page_title="보안팀 릴리즈 아카이브 Pro v34.0", layout="wide")
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

# --- 3. [통합 엔진] 3.1.3(표) & 3.1.4(텍스트) 하이브리드 파싱 ---

def parse_hybrid_v34(file):
    with pdfplumber.open(file) as pdf:
        full_raw = ""
        combined_list = []
        current_sec = None

        for page in pdf.pages:
            p_text = page.extract_text() or ""
            full_raw += p_text + "\n"
            
            # 섹션 감지 (3.1.4 버전 호환)
            if "개선사항" in p_text or "Improvement" in p_text: current_sec = "IMP"
            elif "이슈" in p_text or "Issue" in p_text: current_sec = "ISS"

            # [A] 표(Table) 추출 로직 (3.1.3 이하 버전용)
            tables = page.extract_tables()
            for table in tables:
                for row in table:
                    cells = [str(c).replace('\n', ' ').strip() if c else "" for c in row]
                    # 표의 1줄을 [유형] 내용 (ID) 한 문장으로 만들기
                    if len(cells) >= 3 and any(kw in cells[0] for kw in ['개선', '신규', '이슈', '수정', 'BUG']):
                        type_tag = cells[0]  # 개선/신규/이슈
                        mod_func = cells[1]  # 기능 분류
                        desc = cells[2]      # 상세 내용
                        works_id = cells[3] if len(cells) > 3 else ""
                        
                        line = f"• [{type_tag}/{mod_func}] {desc}"
                        if works_id and works_id.lower() != "none": line += f" ({works_id})"
                        combined_list.append(line)

            # [B] 일반 텍스트 추출 로직 (3.1.4 버전 및 불렛 기호 대응)
            lines = p_text.split('\n')
            for l in lines:
                clean_l = l.strip()
                if clean_l.startswith('•') or (clean_l.startswith('[') and ']' in clean_l):
                    if len(clean_l) > 10: # 의미 있는 길이만
                        combined_list.append(clean_l)

        # 정보 정리
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
if 's_key' not in st.session_state: st.session_state.s_key = "v34"

with st.sidebar:
    st.header("📜 버전 히스토리")
    hist_df = pd.read_sql_query("SELECT version FROM notes ORDER BY version DESC", conn)
    sel_v = st.radio("버전 선택", hist_df['version'].tolist()) if not hist_df.empty else None

    st.divider()
    with st.expander("➕ PDF 신규 등록 (3.1.3 & 3.1.4 통합)", expanded=True):
        uploaded = st.file_uploader("파일 선택", accept_multiple_files=True, label_visibility="collapsed")
        if st.button("✅ DB 반영", use_container_width=True):
            for f in uploaded:
                info = parse_hybrid_v34(f)
                cursor.execute("SELECT version FROM notes WHERE version = ?", (info['version'],))
                if not cursor.fetchone():
                    cursor.execute("INSERT INTO notes (version, openssl, openssh, improvements, issues, raw_text) VALUES (?,?,?,?,?,?)",
                                   (info['version'], info['openssl'], info['openssh'], info['content'], "", info['raw']))
                    conn.commit()
            st.success("데이터가 통합 반영되었습니다.")
            st.rerun()

    with st.expander("🗑️ 데이터 삭제"):
        if not hist_df.empty:
            del_v = st.selectbox("삭제 버전", hist_df['version'].tolist())
            if st.button("🚨 삭제 실행", use_container_width=True):
                cursor.execute("DELETE FROM notes WHERE version = ?", (del_v,))
                conn.commit()
                st.rerun()

# --- 5. 메인 화면 ---
st.title("🛡️ TrusGuard 통합 관제 (v34.0)")

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
