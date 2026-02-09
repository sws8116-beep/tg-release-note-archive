import streamlit as st
import pdfplumber
import sqlite3
import pandas as pd
import re
import os

# --- 1. 페이지 스타일 및 레이아웃 ---
st.set_page_config(page_title="보안팀 릴리즈 아카이브 Pro v21.0", layout="wide")

st.markdown("""
    <style>
    .version-title { 
        font-size: 28px !important; font-weight: 800; color: #0D47A1; 
        background-color: #E3F2FD; padding: 12px 20px; border-radius: 8px; 
        margin-top: 5px; border-left: 10px solid #1565C0;
    }
    .report-card { 
        padding: 25px; border: 1px solid #CFD8DC; background-color: white;
        border-radius: 0px 0px 8px 8px; margin-bottom: 30px; line-height: 1.8;
    }
    .sub-label { font-weight: bold; color: #455A64; margin-top: 10px; display: block; }
    .highlight { background-color: #FFFF00; color: black; font-weight: bold; }
    </style>
    """, unsafe_allow_html=True)

# --- 2. DB 연결 및 초기화 ---
DB_FILE = 'security_notes_archive.db'
def get_connection():
    return sqlite3.connect(DB_FILE, check_same_thread=False)

conn = get_connection()
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS notes 
                  (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                   version TEXT, openssl TEXT, openssh TEXT, 
                   improvements TEXT, issues TEXT, raw_text TEXT)''')
conn.commit()

# --- 3. [개선] 텍스트 및 표 파싱 로직 ---

def clean_report_text(raw_text):
    if not raw_text: return ""
    # 1. 텍스트 내 줄바꿈과 불필요한 공백을 하나로 합침
    text = re.sub(r'\s+', ' ', raw_text).strip()
    # 2. 대괄호 [] 또는 특정 기호를 기준으로 분리
    parts = re.split(r'(\[|•|－|- )', text)
    formatted_lines = []
    current_chunk = ""
    for part in parts:
        if part in ['[', '•', '－', '- ']:
            if current_chunk.strip():
                formatted_lines.append(f"* {current_chunk.strip()}")
            current_chunk = part
        else:
            current_chunk += part
    if current_chunk.strip():
        formatted_lines.append(f"* {current_chunk.strip()}")
    return "\n".join(formatted_lines)

def process_custom_tables(page):
    """
    3.1.3.11 버전 등 상세변경사항 표를 감지하여 한 줄 포맷으로 변환
    포맷: * [모듈/기능] 상세 내용 (이슈번호)
    """
    extracted_lines = []
    tables = page.extract_tables()
    for table in tables:
        if not table or len(table) < 1: continue
        
        # 헤더 확인 (개선/신규/이슈 등)
        header = [str(c).replace('\n', '') for c in table[0] if c]
        
        # 상세변경사항 표 특징: '구분', '모듈/기능', '상세 내용' 등의 컬럼 존재
        if any('상세' in h or '내용' in h for h in header):
            for row in table[1:]:
                # 빈 셀 제거 및 텍스트 정제
                cells = [str(c).strip().replace('\n', ' ') for c in row if c is not None]
                if len(cells) >= 3:
                    # 보통 0:구분, 1:모듈, 2:내용, 3:이슈번호
                    cat = cells[1] # 모듈/기능
                    desc = cells[2] # 상세 내용
                    issue_no = cells[3] if len(cells) > 3 else ""
                    
                    line = f"* [{cat}] {desc}"
                    if issue_no and issue_no != cat:
                        line += f" ({issue_no})"
                    extracted_lines.append(line)
    return extracted_lines

def parse_pdf_v21(file):
    with pdfplumber.open(file) as pdf:
        full_text_for_raw = ""
        improvement_list = []
        issue_list = []
        
        # 1. 전체 텍스트 추출 (버전 및 보안 정보용)
        for page in pdf.pages:
            full_text_for_raw += (page.extract_text() or "") + "\n"
        
        # 2. 섹션별 정밀 파싱
        # 상세변경사항(개선/신규) 및 상세변경사항(이슈) 텍스트를 찾기 위한 플래그
        current_section = None
        
        for page in pdf.pages:
            p_text = page.extract_text() or ""
            
            # 페이지 내 테이블 먼저 처리
            table_lines = process_custom_tables(page)
            
            # 섹션 전환 감지
            if re.search(r'상세변경사항\s*\(개선/신규\)', p_text):
                current_section = "IMP"
            elif re.search(r'상세변경사항\s*\(이슈\)', p_text):
                current_section = "ISS"
            elif re.search(r'5\.\s*연관제품|참고\s*사항', p_text):
                current_section = None
                
            if table_lines:
                if current_section == "IMP":
                    improvement_list.extend(table_lines)
                elif current_section == "ISS":
                    issue_list.extend(table_lines)
            else:
                # 테이블이 없는 경우 일반 텍스트에서 섹션 추출 (기존 3.1.4 등 호환용)
                pass

        # 기존 3.1.4 호환용 섹션 추출 (테이블 결과가 없을 때)
        if not improvement_list or not issue_list:
            imp_raw = re.search(r'(주요\s*개선\s*사항|Improvement|상세변경사항\s*\(개선/신규\))(.*?)(주요\s*이슈\s*해결|Issue|상세변경사항\s*\(이슈\)|5\.)', full_text_for_raw, re.I | re.S)
            iss_raw = re.search(r'(주요\s*이슈\s*해결|Issue|상세변경사항\s*\(이슈\))(.*?)(연관\s*제품|참고사항|5\.)', full_text_for_raw, re.I | re.S)
            
            if not improvement_list and imp_raw:
                improvement_list = [clean_report_text(imp_raw.group(2))]
            if not issue_list and iss_raw:
                issue_list = [clean_report_text(iss_raw.group(2))]

        # 버전 및 보안 정보
        v_match = re.search(r'TrusGuard\s+v?([\d\.]+)', full_text_for_raw, re.I)
        version = v_match.group(1) if v_match else "Unknown"
        ssl = re.search(r'OpenSSL\s+([\d\.]+[\w]*)', full_text_for_raw, re.I)
        ssh = re.search(r'OpenSSH\s+([\d\.]+p\d+)', full_text_for_raw, re.I)

    return {
        "version": version,
        "openssl": ssl.group(1) if ssl else "-",
        "openssh": ssh.group(1) if ssh else "-",
        "improvements": "\n".join(improvement_list).strip(),
        "issues": "\n".join(issue_list).strip(),
        "raw_text": full_text_for_raw
    }

# --- 4. 사이드바 (모든 메뉴 복구) ---
if 'search_key' not in st.session_state: st.session_state.search_key = "v21"

def trigger_reset():
    st.session_state.search_key = os.urandom(4).hex()
    st.rerun()

with st.sidebar:
    st.header("📜 전체 버전 히스토리")
    history_df = pd.read_sql_query("SELECT version FROM notes ORDER BY version DESC", conn)
    
    selected_version = None
    if not history_df.empty:
        selected_version = st.radio("상세 내용을 볼 버전을 선택하세요:", history_df['version'].tolist())
    else:
        st.write("등록된 데이터가 없습니다.")

    st.markdown("<br><br>", unsafe_allow_html=True)
    st.divider()

    # [중요] DB 관리 메뉴들
    with st.expander("➕ PDF 신규 등록 (3.1.3.11 지원)", expanded=False):
        files = st.file_uploader("PDF 선택", accept_multiple_files=True, label_visibility="collapsed")
        if st.button("✅ DB 반영", use_container_width=True):
            for f in files:
                info = parse_pdf_v21(f)
                cursor.execute("SELECT version FROM notes WHERE version = ?", (info['version'],))
                if cursor.fetchone():
                    st.warning(f"⚠️ {info['version']} 이미 존재합니다.")
                    continue
                cursor.execute("INSERT INTO notes (version, openssl, openssh, improvements, issues, raw_text) VALUES (?,?,?,?,?,?)",
                               (info['version'], info['openssl'], info['openssh'], info['improvements'], info['issues'], info['raw_text']))
                conn.commit()
            st.success("데이터 반영 성공!")
            st.rerun()

    with st.expander("🗑️ 데이터 삭제", expanded=False):
        if not history_df.empty:
            del_target = st.selectbox("삭제할 버전 선택", history_df['version'].tolist())
            if st.button("🚨 선택 버전 삭제", use_container_width=True):
                cursor.execute("DELETE FROM notes WHERE version = ?", (del_target,))
                conn.commit()
                st.rerun()

    with st.expander("💾 시스템 DB 관리 (백업/업로드)", expanded=False):
        if os.path.exists(DB_FILE):
            with open(DB_FILE, "rb") as f:
                st.download_button("📥 현재 DB 다운로드", f, file_name="security_notes.db", mime="application/octet-stream")
        
        uploaded_db = st.file_uploader("📤 백업 DB 업로드", type=['db'], label_visibility="collapsed")
        if uploaded_db and st.button("🔥 서버 DB 교체"):
            with open(DB_FILE, "wb") as f:
                f.write(uploaded_db.getbuffer())
            st.success("교체 완료!")
            st.rerun()

# --- 5. 메인 화면 ---
st.title("🛡️ TrusGuard 통합 릴리즈 관제 (v21.0)")

col_search, col_btn = st.columns([5, 1], vertical_alignment="bottom")
with col_search:
    keyword = st.text_input("검색어 입력", placeholder="예: VPN 접속", key=st.session_state.search_key)
with col_btn:
    st.button("🔄 초기화", use_container_width=True, on_click=trigger_reset)

# 강조 및 출력 함수
def highlight(text, kws):
    if not kws: return text.replace("\n", "<br>")
    for k in kws:
        text = re.sub(f"({re.escape(k)})", r"<mark class='highlight'>\1</mark>", text, flags=re.I)
    return text.replace("\n", "<br>")

if keyword:
    kws = keyword.split()
    query = "SELECT version, improvements, issues FROM notes WHERE " + " AND ".join(["raw_text LIKE ?" for _ in kws]) + " ORDER BY version DESC"
    search_res = pd.read_sql_query(query, conn, params=[f'%{k}%' for k in kws])

    if not search_res.empty:
        st.subheader(f"🔎 '{keyword}' 검색 결과 ({len(search_res)}건)")
        for _, row in search_res.iterrows():
            st.markdown(f"<div class='version-title'>📦 TrusGuard {row['version']}</div>", unsafe_allow_html=True)
            # 개선/이슈 텍스트 합치기
            all_content = (row['improvements'] + "\n" + row['issues']).split('\n')
            matched = [l for l in all_content if all(k.lower() in l.lower() for k in kws) and l.strip()]
            st.markdown(f"<div class='report-card'>{highlight('\n'.join(matched) if matched else '*(본문 내 존재)*', kws)}</div>", unsafe_allow_html=True)
    else:
        st.error("결과가 없습니다.")

elif selected_version:
    res = pd.read_sql_query("SELECT * FROM notes WHERE version = ?", conn, params=[selected_version]).iloc[0]
    st.markdown(f"<div class='version-title'>📋 TrusGuard {res['version']} 상세 리포트</div>", unsafe_allow_html=True)
    st.markdown(f"""
    <div class='report-card'>
        <span class='sub-label'>🔒 보안 컴포넌트</span> OpenSSL: {res['openssl']} / OpenSSH: {res['openssh']}<br><br>
        <span class='sub-label'>🔼 상세변경사항 (개선/신규)</span> {res['improvements'].replace('\n', '<br>')}<br><br>
        <span class='sub-label'>🔥 상세변경사항 (이슈)</span> {res['issues'].replace('\n', '<br>')}
    </div>
    """, unsafe_allow_html=True)
