import streamlit as st
import pdfplumber
import sqlite3
import pandas as pd
import re
import os

# --- 1. 페이지 설정 ---
st.set_page_config(page_title="보안팀 릴리즈 아카이브 Pro v35.14", layout="wide")

st.markdown("""
    <style>
    .version-header { font-size: 24px; font-weight: 800; color: #0D47A1; background-color: #E3F2FD; padding: 15px; border-radius: 8px; border-left: 8px solid #1565C0; margin-bottom: 15px; }
    .report-box { padding: 20px; border: 1px solid #ddd; background-color: #ffffff; border-radius: 8px; margin-bottom: 25px; }
    .item-box { padding: 10px 14px; margin-bottom: 8px; border-left: 4px solid #90CAF9; background-color: #F5F5F5; font-size: 15px; line-height: 1.6; }
    .highlight { background-color: #FFF59D; color: black; font-weight: bold; padding: 2px 4px; border-radius: 4px; }
    .meta-label { color: #1565C0; font-weight: bold; font-size: 16px; border-bottom: 2px solid #BBDEFB; margin-bottom: 10px; display: inline-block; }
    </style>
    """, unsafe_allow_html=True)

# --- 2. DB 연결 및 초기화 ---
DB_FILE = 'security_notes_archive.db'

def get_connection():
    return sqlite3.connect(DB_FILE, check_same_thread=False)

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT, openssl TEXT, openssh TEXT, improvements TEXT, issues TEXT, raw_text TEXT)''')
    conn.commit()
    conn.close()

init_db()

# --- 3. [통합 엔진] v35.14 (Raw Text Parsing) ---

def clean_text(text):
    if not text: return ""
    return re.sub(r'\s+', ' ', str(text).replace('\n', ' ')).strip()

def repair_content(text):
    if not text: return ""
    # Apa * che 복구
    text = re.sub(r'([a-zA-Z])\s*[\*\-]\s*([a-zA-Z])', r'\1\2', text)
    text = re.sub(r'([가-힣])\s*[\*\-]\s*([가-힣])', r'\1\2', text)
    # 괄호 보정
    text = re.sub(r'\(\s+', '(', text)
    text = re.sub(r'\s+\)', ')', text)
    return text

def parse_pdf_v35(file):
    with pdfplumber.open(file) as pdf:
        full_raw = ""
        extracted_data = [] 
        
        # 전체 텍스트 수집 (페이지 구분 없이 통으로 처리)
        for page in pdf.pages:
            p_text = page.extract_text()
            if p_text:
                full_raw += p_text + "\n"
        
        # --- [전략] 라인 기반 스캐닝 (Table 포기) ---
        lines = full_raw.split('\n')
        
        current_type = ""
        current_cat = ""
        current_desc = []
        
        # 처리할 키워드 (시작점 식별자)
        type_keywords = ['개선', '신규', '이슈', '수정', 'BUG', 'Feature', '기능', '↑', '+']
        cat_keywords = ['System', 'SSL', 'VPN', 'Network', 'Dashboard', 'Log', 'IPSec', 'Policy']
        
        for line in lines:
            line = line.strip()
            if not line: continue
            
            # 1. 새 항목의 시작인지 검사
            #    패턴: [유형] 혹은 아이콘(↑, +)으로 시작하거나, 카테고리(System)가 맨 앞에 오는 경우
            
            # (1) 명시적 태그 [개선] ...
            tag_match = re.match(r'^[•\-]?\s*\[([^\]]+)\]\s*(.*)', line)
            
            # (2) 아이콘이나 단순 텍스트로 시작하는 경우 (테이블이 깨져서 줄바꿈 된 경우)
            is_new_start = False
            found_type = ""
            
            if tag_match:
                is_new_start = True
                found_type = tag_match.group(1)
                rest_line = tag_match.group(2)
            else:
                # 줄의 시작이 키워드 중 하나인지 확인
                first_word = line.split()[0] if line.split() else ""
                if any(k in first_word for k in type_keywords) or any(k in first_word for k in cat_keywords):
                     is_new_start = True
                     # 타입 추정 (키워드 매칭)
                     if any(k in first_word for k in type_keywords):
                         found_type = first_word
                     else:
                         found_type = "기타" # 카테고리로 시작하면 타입은 모름
                     rest_line = line[len(first_word):].strip()
                elif len(current_desc) > 0:
                     # 시작이 아니면 이전 항목의 내용(Description)으로 이어 붙임
                     current_desc.append(line)
                     continue
            
            if is_new_start:
                # 이전 항목 저장
                if current_desc:
                    full_desc = " ".join(current_desc)
                    full_desc = repair_content(full_desc) # 내용 복구
                    
                    # 카테고리 추출 시도 (내용 앞부분에 영어가 있으면 카테고리로 간주)
                    # 예: "System Apache..." -> Cat: System, Desc: Apache...
                    detected_cat = ""
                    
                    # 이전 루프에서 유지된 카테고리 사용 or 새로 추출
                    split_desc = full_desc.split(' ', 1)
                    if len(split_desc) > 1 and any(c in split_desc[0] for c in cat_keywords):
                        detected_cat = split_desc[0]
                        final_desc = split_desc[1]
                    else:
                        detected_cat = current_cat # 앞선 항목의 카테고리 상속
                        final_desc = full_desc

                    # 필터링
                    if len(final_desc) > 5 and not any(x in final_desc for x in ["Last Updated", "릴리즈노트", "페이지"]):
                        # 아이콘 치환
                        final_type = current_type.replace('↑', '개선').replace('+', '신규')
                        
                        cat_str = f" {detected_cat}" if detected_cat else ""
                        formatted = f"[{final_type}]{cat_str} * {final_desc}"
                        
                        if formatted not in extracted_data:
                            extracted_data.append(formatted)

                # 상태 초기화 및 새 항목 시작
                current_type = found_type
                # 카테고리는 현재 줄에 있을 수도, 다음 줄에 있을 수도 있음. 일단 초기화 안하고 유지(Forward Fill)하거나 현재 줄에서 찾음
                current_desc = [rest_line] if rest_line else []
        
        # 마지막 항목 저장
        if current_desc:
            full_desc = " ".join(current_desc)
            full_desc = repair_content(full_desc)
            final_type = current_type.replace('↑', '개선').replace('+', '신규')
            formatted = f"[{final_type}] * {full_desc}"
            extracted_data.append(formatted)

        # 메타데이터
        v = re.search(r'TrusGuard\s+v?([0-9\.]+)', full_raw, re.I)
        version = v.group(1) if v else "Unknown"
        
        ssl_match = re.search(r'OpenSSL.*?(?:->\s*|\s)([\d\.]+[a-z]?)', full_raw, re.I)
        openssl = ssl_match.group(1) if ssl_match else "-"
        
        ssh_match = re.search(r'OpenSSH.*?([\d\.]+p\d+)', full_raw, re.I)
        openssh = ssh_match.group(1) if ssh_match else "-"

    return {
        "version": version,
        "openssl": openssl,
        "openssh": openssh,
        "content": "\n\n".join(extracted_data),
        "raw": full_raw
    }

# --- 4. 사이드바 ---
if 's_key' not in st.session_state: st.session_state.s_key = "v35"

conn = get_connection()
cursor = conn.cursor()

with st.sidebar:
    st.header("📜 버전 히스토리")
    try:
        hist_df = pd.read_sql_query("SELECT version FROM notes ORDER BY version DESC", conn)
    except:
        hist_df = pd.DataFrame()

    sel_v = st.radio("버전 선택", hist_df['version'].tolist()) if not hist_df.empty else None

    st.divider()
    with st.expander("➕ PDF 등록", expanded=True):
        uploaded = st.file_uploader("파일 선택", accept_multiple_files=True, label_visibility="collapsed")
        if st.button("✅ DB 반영", use_container_width=True):
            if uploaded:
                for f in uploaded:
                    try:
                        info = parse_pdf_v35(f)
                        cursor.execute("SELECT version FROM notes WHERE version = ?", (info['version'],))
                        if not cursor.fetchone():
                            cursor.execute("INSERT INTO notes (version, openssl, openssh, improvements, issues, raw_text) VALUES (?,?,?,?,?,?)",
                                        (info['version'], info['openssl'], info['openssh'], info['content'], "", info['raw']))
                            conn.commit()
                            st.success(f"v{info['version']} 저장됨")
                        else:
                            st.warning(f"v{info['version']} 이미 존재")
                    except Exception as e:
                        st.error(f"오류: {e}")
                st.rerun()

    # DB 초기화 메뉴
    st.divider()
    with st.expander("💀 관리자 메뉴"):
        if st.button("💣 DB 초기화", type="primary"):
            cursor.execute("DROP TABLE IF EXISTS notes")
            conn.commit()
            init_db()
            st.rerun()
        if not hist_df.empty:
            del_v = st.selectbox("삭제 버전", hist_df['version'].tolist())
            if st.button("🚨 삭제"):
                cursor.execute("DELETE FROM notes WHERE version = ?", (del_v,))
                conn.commit()
                st.rerun()

# --- 5. 메인 렌더링 ---
st.title("🛡️ TrusGuard 통합 관제 (v35.14)")

c1, c2 = st.columns([5,1], vertical_alignment="bottom")
keyword = c1.text_input("검색어 입력", key=st.session_state.s_key)
if c2.button("🔄 초기화"):
    st.session_state.s_key = os.urandom(4).hex()
    st.rerun()

def render_report_card(version, openssl, openssh, content, search_kws=None):
    st.markdown(f"<div class='version-header'>📦 TrusGuard {version}</div>", unsafe_allow_html=True)
    with st.container():
        st.markdown("<div class='report-box'>", unsafe_allow_html=True)
        st.markdown(f"<div class='meta-label'>🔒 보안 컴포넌트</div>", unsafe_allow_html=True)
        st.text(f"OpenSSL: {openssl} / OpenSSH: {openssh}")
        st.markdown("<br>", unsafe_allow_html=True)

        st.markdown(f"<div class='meta-label'>📋 상세 변경 내역</div>", unsafe_allow_html=True)
        if content:
            paras = content.split('\n\n')
            has_content = False
            for p in paras:
                if not p.strip(): continue
                display_text = p.strip()
                if search_kws:
                    if not all(k.lower() in display_text.lower() for k in search_kws): continue
                    for k in search_kws:
                        display_text = re.sub(f"({re.escape(k)})", r"<span class='highlight'>\1</span>", display_text, flags=re.I)
                st.markdown(f"<div class='item-box'>{display_text}</div>", unsafe_allow_html=True)
                has_content = True
            
            if not has_content and search_kws:
                st.info("검색 결과가 없습니다.")
        else:
            st.warning("데이터 추출 실패")
        st.markdown("</div>", unsafe_allow_html=True)

if keyword:
    kws = keyword.split()
    query = "SELECT * FROM notes WHERE " + " AND ".join(["raw_text LIKE ?" for _ in kws]) + " ORDER BY version DESC"
    res = pd.read_sql_query(query, conn, params=[f'%{k}%' for k in kws])
    if res.empty: st.info("검색 결과 없음")
    else:
        for _, row in res.iterrows(): render_report_card(row['version'], row['openssl'], row['openssh'], row['improvements'], kws)
elif sel_v:
    r = pd.read_sql_query("SELECT * FROM notes WHERE version = ?", conn, params=[sel_v]).iloc[0]
    render_report_card(r['version'], r['openssl'], r['openssh'], r['improvements'])
else:
    st.info("좌측 사이드바에서 PDF 파일을 등록하거나 버전을 선택해주세요.")
