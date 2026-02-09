import streamlit as st
import pdfplumber
import sqlite3
import pandas as pd
import re
import os

# --- 1. 페이지 스타일 및 문단 간격 설정 ---
st.set_page_config(page_title="보안팀 릴리즈 아카이브 Pro v30.0", layout="wide")
st.markdown("""
    <style>
    .version-title { font-size: 28px; font-weight: 800; color: #0D47A1; background-color: #E3F2FD; padding: 12px 20px; border-radius: 8px; margin-top: 5px; border-left: 10px solid #1565C0; }
    .report-card { padding: 25px; border: 1px solid #CFD8DC; background-color: white; border-radius: 0px 0px 8px 8px; margin-bottom: 30px; line-height: 2.2; font-size: 15px; }
    .sub-label { font-weight: bold; color: #455A64; margin-top: 15px; display: block; font-size: 16px; }
    .highlight { background-color: #FFFF00; color: black; font-weight: bold; }
    /* 문단 간격을 넓게 조정 */
    .release-item { margin-bottom: 15px; display: block; } 
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

# --- 3. [핵심] 점(•) 및 대괄호([]) 기반 문단 재구성 로직 ---

def format_as_paragraphs(text):
    """
    텍스트를 점(•) 또는 대괄호([]) 기준으로 나누어 
    각 항목을 독립적인 한 문단으로 재조합합니다.
    """
    if not text: return ""
    
    # 1. 문서 전체의 강제 줄바꿈을 제거하여 문장을 하나로 합침
    flat = re.sub(r'\s+', ' ', text).strip()
    
    # 2. 항목 구분자(• 또는 [모듈명])를 기준으로 분리
    # ?= 를 사용하여 구분자를 유지하며 나눕니다.
    pattern = r'(?=•|\[[^\]]+\])'
    parts = re.split(pattern, flat)
    
    final_paragraphs = []
    for p in parts:
        item = p.strip()
        if len(item) > 2:
            # 항목 앞에 글머리 기호가 없다면 추가 (대괄호인 경우 제외)
            if not (item.startswith('•') or item.startswith('[')):
                item = f"• {item}"
            final_paragraphs.append(item)
            
    # 3. 항목 사이에 두 번의 줄바꿈(\n\n)을 넣어 문단 구분
    return "\n\n".join(final_paragraphs)

def parse_v30_smart(file):
    with pdfplumber.open(file) as pdf:
        full_text = ""
        for page in pdf.pages:
            # 텍스트와 표 데이터를 모두 평면화하여 추출
            full_text += (page.extract_text() or "") + "\n"
            tables = page.extract_tables()
            for table in tables:
                for row in table:
                    full_text += " ".join([str(c) for c in row if c]) + " "

        # 버전/보안 정보 추출
        v = re.search(r'TrusGuard\s+v?([\d\.]+)', full_text, re.I)
        version = v.group(1) if v else "Unknown"
        ssl = re.search(r'OpenSSL\s+([\d\.]+[\w]*)', full_text, re.I)
        ssh = re.search(r'OpenSSH\s+([\d\.]+p\d+)', full_text, re.I)

        # 문단 단위로 정리
        formatted_content = format_as_paragraphs(full_text)

    return {
        "version": version,
        "openssl": ssl.group(1) if ssl else "-",
        "openssh": ssh.group(1) if ssh else "-",
        "content": formatted_content,
        "raw": full_text
    }

# --- 4. 사이드바 (메뉴 풀세트) ---
if 's_key' not in st.session_state: st.session_state.s_key = "v30"

with st.sidebar:
    st.header("📜 버전 히스토리")
    hist = pd.read_sql_query("SELECT version FROM notes ORDER BY version DESC", conn)
    sel_v = st.radio("상세 보기 선택", hist['version'].tolist()) if not hist.empty else None

    st.divider()
    with st.expander("➕ PDF 등록 (문단 최적화)", expanded=True):
        up_files = st.file_uploader("파일 선택", accept_multiple_files=True, label_visibility="collapsed")
        if st.button("✅ DB 반영", use_container_width=True):
            for f in up_files:
                info = parse_v30_smart(f)
                cursor.execute("SELECT version FROM notes WHERE version = ?", (info['version'],))
                if not cursor.fetchone():
                    # 모든 정리된 문단을 improvements 필드에 저장
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
            with open(DB_FILE, "rb") as f: st.download_button("📥 DB 다운로드", f, file_name="notes_archive.db")
        up_db = st.file_uploader("📤 백업 DB 업로드", type=['db'])
        if up_db and st.button("🔥 교체"):
            with open(DB_FILE, "wb") as f: f.write(up_db.getbuffer())
            st.rerun()

# --- 5. 메인 화면 ---
st.title("🛡️ TrusGuard 통합 관제 (v30.0)")

c1, c2 = st.columns([5,1], vertical_alignment="bottom")
keyword = c1.text_input("검색어 입력", placeholder="예: VPN", key=st.session_state.s_key)
if c2.button("🔄 초기화"):
    st.session_state.s_key = os.urandom(4).hex()
    st.rerun()

def highlight_html(text, kws):
    if not kws: return text.replace("\n", "<br>")
    # 문단 간격을 위해 \n\n을 <br><br>로 변환
    html = text.replace("\n\n", "</div><div class='release-item'>")
    html = f"<div class='release-item'>{html}</div>"
    for k in kws:
        html = re.sub(f"({re.escape(k)})", r"<mark class='highlight'>\1</mark>", html, flags=re.I)
    return html

# 출력 로직
if keyword:
    kws = keyword.split()
    query = "SELECT version, improvements FROM notes WHERE " + " AND ".join(["raw_text LIKE ?" for _ in kws]) + " ORDER BY version DESC"
    res = pd.read_sql_query(query, conn, params=[f'%{k}%' for k in kws])
    for _, row in res.iterrows():
        st.markdown(f"<div class='version-title'>📦 TrusGuard {row['version']}</div>", unsafe_allow_html=True)
        # 검색된 단어가 포함된 문단만 필터링하여 출력
        all_paras = row['improvements'].split('\n\n')
        matched = [p for p in all_paras if all(k.lower() in p.lower() for k in kws)]
        display_html = highlight_html("\n\n".join(matched) if matched else "*(본문 내 존재)*", kws)
        st.markdown(f"<div class='report-card'>{display_html}</div>", unsafe_allow_html=True)

elif sel_v:
    r = pd.read_sql_query("SELECT * FROM notes WHERE version = ?", conn, params=[sel_v]).iloc[0]
    st.markdown(f"<div class='version-title'>📋 TrusGuard {r['version']} 상세 리포트</div>", unsafe_allow_html=True)
    # 전체 리포트 줄바꿈 처리
    display_html = highlight_html(r['improvements'], [])
    st.markdown(f"""<div class='report-card'>
        <span class='sub-label'>🔒 보안 컴포넌트</span>OpenSSL: {r['openssl']} / OpenSSH: {r['openssh']}<br><br>
        <span class='sub-label'>📋 상세 변경 내역</span>
        {display_html}
    </div>""", unsafe_allow_html=True)
