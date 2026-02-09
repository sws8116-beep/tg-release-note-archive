import streamlit as st
import pdfplumber
import sqlite3
import pandas as pd
import re
import os

# --- 1. 페이지 스타일 및 문단 간격 설정 ---
st.set_page_config(page_title="보안팀 릴리즈 아카이브 Pro v31.0", layout="wide")
st.markdown("""
    <style>
    .version-title { font-size: 28px; font-weight: 800; color: #0D47A1; background-color: #E3F2FD; padding: 12px 20px; border-radius: 8px; margin-top: 5px; border-left: 10px solid #1565C0; }
    .report-card { padding: 25px; border: 1px solid #CFD8DC; background-color: white; border-radius: 0px 0px 8px 8px; margin-bottom: 30px; line-height: 2.2; font-size: 15px; }
    .sub-label { font-weight: bold; color: #455A64; margin-top: 15px; display: block; font-size: 16px; }
    .highlight { background-color: #FFFF00; color: black; font-weight: bold; }
    /* 각 항목(문단) 사이의 간격을 확실하게 부여 */
    .release-item { margin-bottom: 25px; display: block; border-bottom: 1px dashed #ECEFF1; padding-bottom: 10px; } 
    .release-item:last-child { border-bottom: none; }
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

# --- 3. [핵심] 3.1.3.11 전용 주요내역 카테고리 추출 로직 ---

def parse_v31_smart(file):
    with pdfplumber.open(file) as pdf:
        full_raw_text = ""
        items = []
        
        for page in pdf.pages:
            p_text = page.extract_text() or ""
            full_raw_text += p_text + "\n"
            
            # 1. 표(Table) 데이터 처리 (3.1.3.11 '요약' 테이블 타겟팅)
            tables = page.extract_tables()
            for table in tables:
                if not table: continue
                for row in table:
                    # 셀 내부 줄바꿈 제거 및 정리
                    cells = [str(c).replace('\n', ' ').strip() if c else "" for c in row]
                    
                    # 3.1.3.11 요약 표 구조 대응: [유형(개선/신규), 기능분류(카테고리), 요약, Works]
                    if len(cells) >= 3 and any(kw in cells[0] for kw in ['개선', '신규', '이슈', 'BUG']):
                        category = cells[1] # 기능 분류 (예: NAT, SSL VPN)
                        summary = cells[2]  # 요약 내용
                        works_id = cells[3] if len(cells) > 3 else ""
                        
                        # 항목 생성: • [카테고리] 요약 내용 (ID)
                        formatted = f"• [{category}] {summary}"
                        if works_id and works_id.lower() != "none" and works_id != category:
                            formatted += f" ({works_id})"
                        items.append(formatted)

            # 2. 일반 텍스트에서 불렛(•) 또는 대괄호 항목 추출
            # 표로 잡히지 않는 나머지 항목들 보충
            lines = p_text.split('\n')
            for line in lines:
                l = line.strip()
                if l.startswith('•') or (l.startswith('[') and ']' in l):
                    if len(l) > 10: # 너무 짧은 제목성 텍스트 제외
                        items.append(l)

        # 중복 제거 및 문단 간격 적용 (줄바꿈 두 번)
        unique_items = list(dict.fromkeys(items))
        formatted_content = "\n\n".join(unique_items)

        # 버전 및 보안 정보 추출
        v_match = re.search(r'TrusGuard\s+v?([\d\.]+)', full_raw_text, re.I)
        version = v_match.group(1) if v_match else "Unknown"
        ssl = re.search(r'OpenSSL\s+([\d\.]+[\w]*)', full_raw_text, re.I)
        ssh = re.search(r'OpenSSH\s+([\d\.]+p\d+)', full_raw_text, re.I)

    return {
        "version": version,
        "openssl": ssl.group(1) if ssl else "-",
        "openssh": ssh.group(1) if ssh else "-",
        "content": formatted_content,
        "raw": full_raw_text
    }

# --- 4. 사이드바 (사용자 인터페이스) ---
if 's_key' not in st.session_state: st.session_state.s_key = "v31"

with st.sidebar:
    st.header("📜 버전 히스토리")
    hist = pd.read_sql_query("SELECT version FROM notes ORDER BY version DESC", conn)
    sel_v = st.radio("상세 보기 선택", hist['version'].tolist()) if not hist.empty else None

    st.divider()
    with st.expander("➕ PDF 등록 (3.1.3.11 최적화)", expanded=True):
        up_files = st.file_uploader("파일 선택", accept_multiple_files=True, label_visibility="collapsed")
        if st.button("✅ DB 반영", use_container_width=True):
            for f in up_files:
                info = parse_v31_smart(f)
                cursor.execute("SELECT version FROM notes WHERE version = ?", (info['version'],))
                if not cursor.fetchone():
                    cursor.execute("INSERT INTO notes (version, openssl, openssh, improvements, issues, raw_text) VALUES (?,?,?,?,?,?)",
                                   (info['version'], info['openssl'], info['openssh'], info['content'], "", info['raw']))
                    conn.commit()
            st.rerun()

    with st.expander("🗑️ 데이터 삭제"):
        if not hist.empty:
            del_v = st.selectbox("삭제 버전", hist['version'].tolist())
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
st.title("🛡️ TrusGuard 통합 관제 (v31.0)")

c1, c2 = st.columns([5,1], vertical_alignment="bottom")
keyword = c1.text_input("검색어 입력", placeholder="예: VPN", key=st.session_state.s_key)
if c2.button("🔄 초기화"):
    st.session_state.s_key = os.urandom(4).hex()
    st.rerun()

def highlight_html(text, kws):
    if not text: return ""
    # 항목 구분자(\n\n)를 기반으로 HTML 문단으로 변환
    paras = text.split('\n\n')
    html_items = []
    for p in paras:
        if p.strip():
            html_items.append(f"<div class='release-item'>{p.strip()}</div>")
    
    combined_html = "".join(html_items)
    if kws:
        for k in kws:
            combined_html = re.sub(f"({re.escape(k)})", r"<mark class='highlight'>\1</mark>", combined_html, flags=re.I)
    return combined_html

# 출력 로직
if keyword:
    kws = keyword.split()
    query = "SELECT version, improvements FROM notes WHERE " + " AND ".join(["raw_text LIKE ?" for _ in kws]) + " ORDER BY version DESC"
    res = pd.read_sql_query(query, conn, params=[f'%{k}%' for k in kws])
    for _, row in res.iterrows():
        st.markdown(f"<div class='version-title'>📦 TrusGuard {row['version']}</div>", unsafe_allow_html=True)
        all_paras = row['improvements'].split('\n\n')
        matched = [p for p in all_paras if all(k.lower() in p.lower() for k in kws)]
        display_html = highlight_html("\n\n".join(matched) if matched else "*(본문 내 존재)*", kws)
        st.markdown(f"<div class='report-card'>{display_html}</div>", unsafe_allow_html=True)

elif sel_v:
    r = pd.read_sql_query("SELECT * FROM notes WHERE version = ?", conn, params=[sel_v]).iloc[0]
    st.markdown(f"<div class='version-title'>📋 TrusGuard {r['version']} 상세 리포트</div>", unsafe_allow_html=True)
    display_html = highlight_html(r['improvements'], [])
    st.markdown(f"""<div class='report-card'>
        <span class='sub-label'>🔒 보안 컴포넌트</span>OpenSSL: {r['openssl']} / OpenSSH: {r['openssh']}<br><br>
        <span class='sub-label'>📋 주요 내역 요약</span>
        {display_html}
    </div>""", unsafe_allow_html=True)
